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

## Model-agnostic by design

The harness is the layer *around* the model — the MCP server (tools, scope hook,
state, gate, audit log) knows nothing about which model is driving it. The agent
sits in a swappable seat.

Any MCP-capable client can connect to the same server unchanged: OpenAI Codex,
Claude (Desktop / Code), Cursor, or a custom agent wrapping GPT, DeepSeek, Llama,
or a local model via Ollama. Only two thin pieces are runtime-specific — the
client you point at the server, and the instruction file (`AGENTS.md`,
`CLAUDE.md`, or a system prompt).

Because every guarantee lives in **code**, it holds regardless of the model — a
weaker or less-aligned model is boxed by the same scope hook and the same human
gate. The safety doesn't depend on the model being smart or well-behaved.

## Getting started

### Prerequisites
- **Docker** (Docker Desktop on macOS/Windows, or Docker Engine on Linux)
- **An MCP-capable agent/client** — anything that can talk to a Streamable HTTP MCP server (examples below)

### 1. Get the harness
```bash
git clone https://github.com/CyberfunkChill12/bug-bounty-recon-harness
cd bug-bounty-recon-harness
```

### 2. Build and start it
```bash
# Set ACTIVE_ARM_CODE to a secret of your choice to enable active scans.
# Omit it and active scanning stays disabled (passive recon still works).
ACTIVE_ARM_CODE='pick-a-secret' docker compose up -d --build
```
The first build takes a few minutes (it compiles the recon tools). Then verify:
```bash
docker compose ps                  # STATUS should be "Up"
curl -i http://localhost:8000/mcp  # a 406 "must accept text/event-stream" = healthy
```
The harness is now serving MCP at **`http://localhost:8000/mcp`**.

### 3. Connect your agent (any model)
It's a standard **Streamable HTTP MCP server** — point any MCP-capable client at the URL above:

| Client (model) | How to connect |
|---|---|
| **OpenAI Codex** (GPT) | Settings → MCP servers → Add Server → type `Streamable HTTP`, URL `http://localhost:8000/mcp` |
| **Claude Desktop / Claude Code** (Claude) | Add as a custom/remote MCP server with the same URL |
| **Cursor** (any) | `.cursor/mcp.json`: `{ "mcpServers": { "harness": { "url": "http://localhost:8000/mcp" } } }` |
| **Custom agent** (GPT, DeepSeek, Llama, Ollama…) | Use any MCP client library, connect to the URL, and call the tools from your agent loop |

Restart the client if the tools don't show up right away.

### 4. Give the agent its playbook
Point your runtime at the included instruction file so it knows the tools and the flow:
- **Codex:** keep `AGENTS.md` in the working folder (already here).
- **Claude:** copy it to `CLAUDE.md`.
- **Custom agent:** load `AGENTS.md` as the system prompt.

### 5. First run
Tell the agent in plain language:
> Set scope for program **test** to root **example.com**, run passive enum, and show me what you found.

Passive discovery runs freely. When you move to active scanning (`resolve_probe`, `takeover_check`, `nuclei_scan`), the agent will ask for your **arming code** — the value you set in `ACTIVE_ARM_CODE`. Provide it only for programs you're authorized to test.

### 6. Verify before you report
Scanner output and the agent's claims are **candidates, not findings**. Re-check them independently before you submit anything:
```bash
docker compose exec harness-mcp python verify.py <program>
```
`verify.py` re-runs detection on each recorded finding (reproduce-or-reject) and asserts scope invariants against the audit log — so only findings that hold up on an independent pass become claims. It's a standalone script, not an agent tool: the agent never grades its own work.

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
