# Recon methodology (for the harness agent)

Authorized bug-bounty recon. Build the fullest picture of a program's attack
surface, reduce it to live/interesting hosts, flag likely bugs — using only the
harness tools, only within scope.

## Phase flow (maps to the tools)
1. **Scope** — `add_scope` with the program's authorized roots/CIDRs. Only these.
2. **Passive** — `passive_enum` each root (OSINT; no target traffic).
3. **Review** — `get_new_assets` to see what surfaced; focus on what's new.
4. **Live hosts (active, gated)** — `resolve_probe` to find which hosts respond.
5. **Detection (active, gated)** — `takeover_check` first (low noise), then a
   focused `nuclei_scan` (tags like "takeover,exposure,cve,misconfiguration").
6. **Report** — `summarize`; record only VERIFIED findings with `record_finding`.

## What to prioritize (triage)
Interesting hosts, roughly in order:
- dev / staging / test / uat / qa / beta
- admin / internal / intranet / corp / vpn / sso / auth portals
- api / graphql / swagger endpoints
- git / gitlab / jenkins / jira / confluence / grafana / kibana
- old / legacy / backup hosts, and anything on a non-standard port
- hosts NOT behind the main CDN/WAF (possible origin servers)
- names found only by brute force / permutations / scraping — fewer eyes on them

## Subdomain takeover (highest signal for this harness)
Dangling CNAMEs pointing at unclaimed third-party services (S3, Azure, Heroku,
GitHub Pages, Shopify, Fastly, Zendesk, etc.). `takeover_check` flags candidates;
verify by hand before claiming, and keep any PoC benign.

## Rules
- In scope only. The harness enforces it; still plan within scope.
- Active tools need the operator's arming code — ask, never guess.
- Scanner output = candidates. Reproduce before `record_finding`.
- Keep PoCs benign. Follow the program's rules of engagement.
