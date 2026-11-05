# server.py — harness MCP server (Python, FastMCP from mcp v1)
import json, sqlite3, subprocess, ipaddress, os, time, hashlib, tempfile
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
    h = host.strip().lower().rstrip(".")
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

# ---------------- passive / safe ----------------
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
    """Passive subdomain enumeration (no traffic to the target). Runs automatically."""
    out = run(program, "passive_enum", root, ["subfinder", "-d", root, "-all", "-silent"])
    now = time.time(); c = db(); n = 0
    for host in filter(None, (l.strip().lower() for l in out.splitlines())):
        c.execute("""INSERT INTO assets(program,host,first_seen,last_seen) VALUES(?,?,?,?)
                     ON CONFLICT(program,host) DO UPDATE SET last_seen=?""", (program, host, now, now, now))
        n += 1
    c.commit(); c.close()
    return f"{n} hosts recorded from passive enum of {root}"

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
    """Read-only run report: asset/finding counts + recent tool activity from state and the audit log."""
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

# ---------------- active / gated (need the operator's arming code) ----------------
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
