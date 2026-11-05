# 🛡️ Autonomous Bug-Bounty Recon Harness

An **agent harness** that lets an LLM coding agent (OpenAI Codex) run authorized
bug-bounty reconnaissance and vulnerability *detection* — safely.

The scanning is the easy part. The real work here is the **control layer**: the
scaffolding that keeps an autonomous agent inside scope, logs everything it does,
and never lets it take an active action without a human in the loop. This repo is
a study in **harness engineering** — building the enforcement, state, and audit
*around* an agent that make it genuinely useful instead of a liability.

## The problem

Give an autonomous agent a scanner and a target and the failure modes are
predictable and serious:

- it scans **out of scope** (unauthorized testing),
- it **hammers** hosts,
- it **hallucinates** findings and reports bugs that don't exist,
- it gets **hijacked by prompt injection** in the very pages it reads.

A prompt that says *"please stay in scope"* fixes none of these — the model can
ignore it, forget it after a long run, or be argued out of it by injected text.
So in this project the guardrails live in **code**, outside the model's control.

## Architecture

```
      you ──► Codex (agent: decides what to do)
                   │  MCP over HTTP (localhost)
                   ▼
            harness server (Docker)   ◄── the only door to the network
              • scope check    (enforcement)
              • call log       (ground truth)
              • SQLite state
              • recon / detection tools
```

The agent *plans*; the containerized server *acts* — and every action passes
through a scope check and an audit log before it runs. The agent's own shell has
no network, so recon can **only** happen through the scoped tools.

## The safety design (the point of the project)

| Principle | How it's implemented |
|---|---|
| **Enforce in code, not the prompt** | A scope allowlist is checked in Python on every tool call; out-of-scope targets are refused and logged. |
| **Prevent > detect** | The agent's shell has no network access; there is no path to recon that bypasses the scoped tools. |
| **Human in the loop** | Active scans require an operator "arming code" the agent never sees — it has to ask. |
| **Trust ground truth, not narration** | Every run is logged with target, args, exit code, and output hash — independent of what the agent *says* it did. |
| **Verify before you claim** | Scanner output is treated as *candidates*; nothing becomes a finding until a human reproduces it. |

Each row is a harness-engineering principle, not a slogan — the repo is organized
so you can see exactly where each one lives in the code.

## Capabilities

- Passive subdomain discovery (`subfinder`) and live-host probing (`httpx`, `dnsx`)
- Subdomain-takeover detection (`subzy`) and template-based detection (`nuclei`)
- Persistent, resumable per-program state and run reports (SQLite)
- Driven entirely in natural language through the agent, via 8 scoped MCP tools

See [`AGENTS.md`](./AGENTS.md) for the tool catalog the agent works from, and
[`references/recon-methodology.md`](./references/recon-methodology.md) for the
recon methodology.

## Tech

Python · Model Context Protocol (MCP) · Docker · OpenAI Codex ·
ProjectDiscovery (`subfinder`, `httpx`, `dnsx`, `nuclei`) · `subzy` · SQLite

## Running it

```bash
# build + start the harness (set an arming code to enable active scans)
ACTIVE_ARM_CODE='your-code' docker compose up -d --build

# point your Codex desktop app at this folder and add the MCP server:
#   Settings → MCP servers → Add Server → Streamable HTTP → http://localhost:8000/mcp
```

Then, in the agent: set a program's authorized scope, run passive enum, review,
and — with your arming code — run active detection. Full walkthrough in the
project docs.

## Build notes / lessons learned

- **MCP tools over a raw shell.** Handing an agent a shell *and* a scanner is the
  unsafe default. Every capability here is instead a narrow, scope-checked tool.
- **Scope in code, restated in the prompt.** The prompt restates scope for
  *cooperation*; the code enforces it for *safety*. The guarantee never depends on
  the prompt.
- **Pinned tool versions** in the Docker image, for reproducible, auditable runs.
- **Gotchas solved along the way:** bumping the Go base image for the
  ProjectDiscovery toolchain; pinning the MCP SDK to v1 after a breaking 2.x
  rename (`FastMCP` → `MCPServer`).

## ⚠️ Responsible use

For **authorized** security testing only — bug-bounty programs and systems you
have explicit written permission to test. Respect every program's scope and rules
of engagement, keep proof-of-concepts benign, and verify before you report. The
author is not responsible for misuse.

## License

MIT — see [LICENSE](./LICENSE).
