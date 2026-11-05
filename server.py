# server.py — harness MCP server (Python, FastMCP from mcp v1)
import json, sqlite3, subprocess, ipaddress, os, time, hashlib, tempfile, re
from mcp.server.fastmcp import FastMCP

DB = os.environ.get("HARNESS_DB", "/data/harness.db")
mcp = FastMCP("harness", host="0.0.0.0", port=8000)

def db():
    c = sqlite3.connect(DB); c.execute("PRAGMA journal_mode=WAL"); return c

def init():
    db().executescript("""
    CREATE TABLE IF NOT EXISTS scope(program TEXT, kind TEXT, value TEXT);
    CREATE TABLE IF NOT EXISTS assets(program TEXT, host TEXT, ip TEXT, status INT,
        first_seen REAL, last_seen REAL, triaged INT DEFAULT 0, UNIQUE(program, host));
    CREATE TABLE IF NOT EXISTS findings(program TEXT, host TEXT, type TEXT, severity TEXT,
        notes TEXT, created REAL);
    CREATE TABLE IF NOT EXISTS tool_log(ts REAL, program TEXT, tool TEXT, target TEXT,
        argv TEXT, exit INT, out_hash TEXT, allowed INT);
    """)

def in_scope(program, host):
    c = db()
    roots = [r for (r,) in c.execute("SELECT value FROM scope WHERE program=? AND kind='root'", (program,))]
    cidrs = [r for (r,) in c.execute("SELECT value FROM scope WHERE program=? AND kind='cidr'", (program,))]
    c.close()
    h = (host or "").strip().lower().rstrip(".")
    if any(h == r or h.endswith("." + r) for r in roots):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in ipaddress.ip_network(n) for n in cidrs)
    except ValueError:
        return False

def log(program, tool, target, argv, code, out, allowed):
    c = db()
    c.execute("INSERT INTO tool_log VALUES (?,?,?,?,?,?,?,?)",
              (time.time(), program, tool, target, json.dumps(argv), code,
               hashlib.sha256(out.encode()).hexdigest(), int(allowed)))
    c.commit(); c.close()

def armed(confirm_code):
    expected = os.environ.get("ACTIVE_ARM_CODE", "__unset__")
    return expected != "__unset__" and confirm_code == expected

BLOCK_MSG = ("BLOCKED: this is an ACTIVE tool. Ask the operator for the arming code and call again "
             "with confirm_code set. Do not guess the code.")

def run(program, tool, target, argv):
    # SCOPE HOOK: enforced in code, cannot be prompt-injected away
    if not in_scope(program, target):
        log(program, tool, target, argv, -1, "", allowed=False)
        raise ValueError(f"REFUSED: {target} not in scope for {program}")
    p = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    log(program, tool, target, argv, p.returncode, p.stdout, allowed=True)
    return p.stdout

def scoped_hosts(program, limit=None):
    c = db(); rows = [h for (h,) in c.execute("SELECT host FROM assets WHERE program=?", (program,))]; c.close()
    hosts = [h for h in rows if in_scope(program, h)]
    return hosts[:limit] if limit else hosts

def run_list(program, tool, hosts, build_cmd, timeout=3600):
    if not hosts:
        return "no in-scope hosts to scan"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); path = f.name
    argv = build_cmd(path)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        log(program, tool, f"{len(hosts)} hosts", argv, p.returncode, p.stdout, allowed=True)
        return p.stdout
    finally:
        try: os.unlink(path)
        except OSError: pass

def record_hosts(program, hosts):
    now = time.time(); c = db(); n = 0
    for h in hosts:
        h = (h or "").strip().lower().rstrip(".")
        if h and in_scope(program, h):
            c.execute("""INSERT INTO assets(program,host,first_seen,last_seen) VALUES(?,?,?,?)
                         ON CONFLICT(program,host) DO UPDATE SET last_seen=?""", (program, h, now, now, now))
            n += 1
    c.commit(); c.close(); return n

def passive(program, name, root, argv):
    """Passive source keyed to a root (root is scope-checked + logged); records in-scope hosts."""
    out = run(program, name, root, argv)
    return f"{name}: {record_hosts(program, out.splitlines())} in-scope hosts recorded"

def info(program, name, target, argv, timeout=300, record=False, cap=4000):
    """Passive info/index lookup (no target traffic). Logs; optionally records in-scope hosts."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    log(program, name, target, argv, p.returncode, p.stdout, allowed=True)
    extra = ""
    if record:
        hosts = [l.split(":")[0].strip() for l in p.stdout.splitlines()]
        extra = f" ({record_hosts(program, hosts)} in-scope hosts recorded)"
    return ((p.stdout or p.stderr or "no data")[:cap]) + extra

# ================= passive / safe =================
@mcp.tool()
def add_scope(program: str, roots: list[str] = [], cidrs: list[str] = []) -> str:
    """Define the authorized scope for a program. Do this before anything else."""
    c = db()
    for r in roots: c.execute("INSERT INTO scope VALUES (?,?,?)", (program, "root", r.lower()))
    for n in cidrs: c.execute("INSERT INTO scope VALUES (?,?,?)", (program, "cidr", n))
    c.commit(); c.close()
    return f"scope[{program}]: {len(roots)} roots, {len(cidrs)} cidrs"

@mcp.tool()
def passive_enum(program: str, root: str) -> str:
    """Passive subdomain enumeration via subfinder (no traffic to target)."""
    out = run(program, "passive_enum", root, ["subfinder", "-d", root, "-all", "-silent"])
    return f"passive_enum: {record_hosts(program, out.splitlines())} in-scope hosts recorded"

@mcp.tool()
def assetfinder_enum(program: str, root: str) -> str:
    """Passive: related subdomains via assetfinder."""
    return passive(program, "assetfinder", root, ["assetfinder", "--subs-only", root])

@mcp.tool()
def findomain_enum(program: str, root: str) -> str:
    """Passive: subdomains via findomain (certificate + external sources)."""
    return passive(program, "findomain", root, ["findomain", "-t", root, "-q"])

@mcp.tool()
def chaos_enum(program: str, root: str) -> str:
    """Passive: subdomains from ProjectDiscovery Chaos dataset. Needs PDCP_API_KEY in the container env."""
    return passive(program, "chaos", root, ["chaos", "-d", root, "-silent"])

@mcp.tool()
def github_subdomains(program: str, root: str) -> str:
    """Passive: subdomain references on GitHub. Needs GITHUB_TOKEN in the container env."""
    return passive(program, "github_subdomains", root,
                   ["github-subdomains", "-d", root, "-t", os.environ.get("GITHUB_TOKEN", "")])

@mcp.tool()
def gitlab_subdomains(program: str, root: str) -> str:
    """Passive: subdomain references on GitLab. Needs GITLAB_TOKEN in the container env."""
    return passive(program, "gitlab_subdomains", root,
                   ["gitlab-subdomains", "-d", root, "-t", os.environ.get("GITLAB_TOKEN", "")])

@mcp.tool()
def archive_domains(program: str, root: str) -> str:
    """Passive: historical URLs (gau + waybackurls) reduced to in-scope hostnames."""
    out = run(program, "gau", root, ["gau", "--subs", root]) + "\n" + \
          run(program, "waybackurls", root, ["waybackurls", root])
    return f"archives: {record_hosts(program, re.findall(r'https?://([^/:\\s]+)', out))} in-scope hosts recorded"

@mcp.tool()
def theharvester_enum(program: str, root: str) -> str:
    """Passive OSINT via theHarvester (public sources). Records in-scope hosts."""
    p = subprocess.run(["theHarvester", "-d", root, "-b", "crtsh,otx,duckduckgo,bing"],
                       capture_output=True, text=True, timeout=600)
    log(program, "theHarvester", root, ["theHarvester", "-d", root], p.returncode, p.stdout, allowed=True)
    hosts = re.findall(r"([a-z0-9][a-z0-9._-]*\." + re.escape(root.lower()) + r")", p.stdout.lower())
    return f"theHarvester: {record_hosts(program, hosts)} in-scope hosts recorded"

@mcp.tool()
def uncover_search(program: str, query: str) -> str:
    """Passive: search Shodan/Censys/FOFA indexes via uncover (needs provider API keys). Records in-scope hosts."""
    return info(program, "uncover", query, ["uncover", "-q", query, "-silent"], record=True)

@mcp.tool()
def shodan_query(program: str, query: str) -> str:
    """Passive: Shodan search (needs SHODAN_API_KEY / 'shodan init'). Returns indexed info."""
    return info(program, "shodan", query, ["shodan", "search", "--fields", "ip_str,hostnames", query])

@mcp.tool()
def asn_info(program: str, query: str) -> str:
    """Passive: ASN / CIDR ranges for a domain or org (asnmap). Use to help discover scope."""
    return info(program, "asnmap", query, ["asnmap", "-d", query, "-silent"])

@mcp.tool()
def whois_lookup(program: str, target: str) -> str:
    """Passive: whois registration info for a domain or IP."""
    return info(program, "whois", target, ["whois", target], timeout=60)

@mcp.tool()
def get_new_assets(program: str, since_hours: float = 24) -> str:
    """Read-only: hosts first seen within the window (the 'new since last run' diff)."""
    c = db(); cutoff = time.time() - since_hours * 3600
    rows = c.execute("SELECT host FROM assets WHERE program=? AND first_seen>=?", (program, cutoff)).fetchall()
    c.close()
    return "\n".join(h for (h,) in rows) or "none"

@mcp.tool()
def record_finding(program: str, host: str, type: str, severity: str, notes: str) -> str:
    """Write a VERIFIED finding to state (verify scanner candidates by hand first)."""
    c = db(); c.execute("INSERT INTO findings VALUES (?,?,?,?,?,?)",
                         (program, host, type, severity, notes, time.time())); c.commit(); c.close()
    return "recorded"

@mcp.tool()
def summarize(program: str) -> str:
    """Read-only run report: asset/finding counts + recent tool activity."""
    c = db()
    assets = c.execute("SELECT count(*) FROM assets WHERE program=?", (program,)).fetchone()[0]
    findings = c.execute("SELECT count(*) FROM findings WHERE program=?", (program,)).fetchone()[0]
    recent = c.execute("SELECT tool, allowed, exit, datetime(ts,'unixepoch') FROM tool_log "
                       "WHERE program=? ORDER BY ts DESC LIMIT 10", (program,)).fetchall()
    c.close()
    out = [f"Program: {program}", f"Assets: {assets}", f"Findings: {findings}", "Recent tool calls:"]
    for t, al, ex, when in recent:
        out.append(f"  {when}  {t}  allowed={al} exit={ex}")
    return "\n".join(out)

# ================= active / gated =================
@mcp.tool()
def resolve_probe(program: str, confirm_code: str = "") -> str:
    """ACTIVE: resolve known hosts and HTTP-probe them to find live ones. Requires the operator's arming code."""
    if not armed(confirm_code): return BLOCK_MSG
    live = []
    for h in scoped_hosts(program):
        try:
            out = run(program, "resolve_probe", h, ["httpx", "-u", h, "-silent", "-sc"])
            if out.strip(): live.append(out.strip())
        except ValueError:
            continue
    return "\n".join(live) or "no live hosts"

@mcp.tool()
def takeover_check(program: str, confirm_code: str = "") -> str:
    """ACTIVE: check in-scope hosts for subdomain takeover (subzy). Requires the operator's arming code.
    Returns CANDIDATES to verify by hand; does not auto-record findings."""
    if not armed(confirm_code): return BLOCK_MSG
    out = run_list(program, "takeover_check", scoped_hosts(program),
                   lambda path: ["subzy", "run", "--targets", path, "--hide_fails"])
    return out or "no takeover candidates"

@mcp.tool()
def nuclei_scan(program: str, confirm_code: str = "", tags: str = "", max_hosts: int = 500) -> str:
    """ACTIVE: run nuclei detection templates against in-scope hosts. Requires the operator's arming code.
    'tags' focuses templates (e.g. 'takeover,exposure,cve'). Capped at max_hosts. Output = CANDIDATES to verify."""
    if not armed(confirm_code): return BLOCK_MSG
    def cmd(path):
        a = ["nuclei", "-l", path, "-silent"]
        if tags: a += ["-tags", tags]
        return a
    out = run_list(program, "nuclei_scan", scoped_hosts(program, limit=max_hosts), cmd)
    return out or "no nuclei hits"

if __name__ == "__main__":
    init()
    mcp.run(transport="streamable-http")
