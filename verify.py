#!/usr/bin/env python3
"""verify.py — independent re-checker for the harness.

Run by the OPERATOR (not the agent), inside the container where the tools live:

    docker compose exec harness-mcp python verify.py <program>

  1. Audit-log invariants (deterministic, no network): prove ACTIVE tools stayed
     in scope and surface anything odd in the tool_log ground truth.
  2. Finding reproduction: re-run detection on every recorded finding's host and
     confirm it still reproduces. Only CONFIRMED findings should become claims.

Deliberately NOT an MCP tool — the agent must not grade its own work.
"""
import os, sys, sqlite3, subprocess, ipaddress

DB = os.environ.get("HARNESS_DB", "/data/harness.db")
# Only tools that send traffic to the target are scope-invariant-checked.
# Passive discovery tools (whois/asnmap/uncover/shodan) legitimately run on
# not-yet-in-scope things, so they are excluded.
ACTIVE_TOOLS = {"resolve_probe", "takeover_check", "nuclei_scan"}


def db():
    return sqlite3.connect(DB)


def in_scope(c, program, host):
    roots = [r for (r,) in c.execute(
        "SELECT value FROM scope WHERE program=? AND kind='root'", (program,))]
    cidrs = [r for (r,) in c.execute(
        "SELECT value FROM scope WHERE program=? AND kind='cidr'", (program,))]
    h = (host or "").strip().lower().rstrip(".")
    if any(h == r or h.endswith("." + r) for r in roots):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return any(ip in ipaddress.ip_network(n) for n in cidrs)
    except ValueError:
        return False


def run(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


def looks_like_host(t):
    return bool(t) and " " not in t and "." in t


def check_invariants(c, program):
    print("== Audit-log invariants ==")
    problems = 0
    for tool, target in c.execute(
            "SELECT tool, target FROM tool_log WHERE program=? AND allowed=1", (program,)):
        if tool in ACTIVE_TOOLS and looks_like_host(target) and not in_scope(c, program, target):
            print(f"  [VIOLATION] allowed '{tool}' run targeted out-of-scope {target}")
            problems += 1
    oos = [h for (h,) in c.execute("SELECT host FROM assets WHERE program=?", (program,))
           if not in_scope(c, program, h)]
    if oos:
        print(f"  [VIOLATION] {len(oos)} stored assets out of scope (e.g. {oos[:3]})")
        problems += len(oos)
    refused = c.execute(
        "SELECT count(*) FROM tool_log WHERE program=? AND allowed=0", (program,)).fetchone()[0]
    print(f"  blocked (out-of-scope) attempts logged: {refused}")
    print(f"  invariant problems: {problems}")
    return problems


def reproduce(c, program):
    print("\n== Finding reproduction ==")
    rows = c.execute(
        "SELECT host, type, severity FROM findings WHERE program=?", (program,)).fetchall()
    if not rows:
        print("  no recorded findings to verify")
        return 0
    confirmed = 0
    for host, ftype, sev in rows:
        if not in_scope(c, program, host):
            print(f"  [SCOPE]          {host}  ({ftype}) — out of scope, not re-checked")
            continue
        if "takeover" in (ftype or "").lower():
            out = run(["subzy", "run", "--target", host, "--hide_fails"])
        else:
            out = run(["nuclei", "-u", host, "-silent"])
        if out.strip():
            print(f"  [CONFIRMED]      {host}  ({ftype}, {sev})"); confirmed += 1
        else:
            print(f"  [NOT-REPRODUCED] {host}  ({ftype}, {sev}) — drop or investigate")
    print(f"  confirmed: {confirmed}/{len(rows)}")
    return confirmed


def main():
    if len(sys.argv) < 2:
        print("usage: python verify.py <program>"); sys.exit(2)
    program = sys.argv[1]
    c = db()
    problems = check_invariants(c, program)
    reproduce(c, program)
    c.close()
    print("\nPromote only CONFIRMED findings to claims. Investigate any VIOLATION immediately.")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
