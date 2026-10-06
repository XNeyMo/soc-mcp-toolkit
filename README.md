# SOC MCP Toolkit

**A suite of Model Context Protocol (MCP) servers that turn an AI assistant into a force
multiplier for a Security Operations Center.** It connects a single conversational agent to the
tools a blue team actually uses — Microsoft Defender XDR, Entra ID, Exchange Online, Microsoft
Intune, Microsoft Purview/Audit, Palo Alto Cortex XDR, an Ellucian Banner (ETHOS Integration)
identity source, an offensive-testing lab, and a shared, audited team knowledge vault — so an
analyst can triage, correlate, and respond to an incident **in plain language** instead of
juggling a dozen consoles.

> ⚠️ **Disclaimer.** This is a reference implementation / template. It ships with **generic,
> placeholder values** (hosts, domains, tenant IDs, group IDs). You must supply your own
> credentials and endpoints via environment variables, and you are responsible for using it only
> against systems you own or are explicitly authorized to operate. See [SECURITY.md](SECURITY.md).

---

## Why this exists — the result

A security incident almost never lives in one tool. A single phishing-driven account compromise
leaves traces in email (Exchange), identity (Entra ID sign-ins and risk), the endpoint (Defender /
Cortex), and sometimes the enrollment layer (Intune). The classic workflow is an analyst pivoting
by hand across five portals, copy-pasting an address here, a device ID there, a hash somewhere
else — slow, error-prone, and hard to reproduce.

By exposing each of these platforms as an MCP server and letting one AI agent drive them, the
**initial investigation of an incident dropped from roughly 20 minutes of manual pivoting to under
1 minute** — the agent correlates the same entity (a user, a host, an IOC, a mail subject) across
every connected tool in a single pass, and hands the analyst a consolidated picture to make the
decision.

The human stays in control: every destructive action is gated behind an explicit two-step
confirmation, and every action is audited (see **Safety model** below).

---

## The servers

| MCP server       | Domain                        | What it covers |
|------------------|-------------------------------|----------------|
| `mcp-defender`   | Microsoft Defender XDR / MDE  | Incidents, alerts, advanced hunting (KQL), device/file/IP/URL/user investigation, IOC indicators, isolation, AV scans. |
| `mcp-identity`   | Microsoft Entra ID (Graph)    | User investigation, sign-in & audit history, MFA methods, risky users (Identity Protection), Conditional Access, groups, roles/PIM, OAuth consents, Secure Score, containment (block, revoke sessions, reset, enforce MFA). |
| `mcp-exchange`   | Exchange Online (Graph + EXO) | Mailbox rules/delegates/forwarding, transport rules, quarantine, message search & correlation, auto-reply cleanup, bulk mail remediation. |
| `mcp-intune`     | Microsoft Intune              | Managed-device inventory and posture lookups. |
| `mcp-audit`      | Microsoft Purview / Audit     | Unified audit log, eDiscovery cases, Information Protection labels. **Read-only.** |
| `mcp-cortex`     | Palo Alto Cortex XDR          | Incidents, alerts, endpoints, isolation, file quarantine, hash block/allow, IOC indicators. |
| `mcp-banner`     | Ellucian Banner (ETHOS)       | Example integration with a Student/HR Information System to cross-reference an identity against Entra ID. **Read-only, example endpoints.** |
| `mcp-pentesting` | Offensive testing lab (SSH)   | Authorized security testing: nmap, nikto, nuclei, wpscan, sqlmap, hydra, Metasploit, etc., launched as background jobs on a dedicated Kali host. |
| `mcp-vault`      | Team knowledge vault (SSH)    | Shared, server-side-audited Obsidian-style vault for incidents, entities, playbooks and a daily log — non-forgeable per-analyst attribution. |

All servers share a small `shared/` library: authentication clients (MSAL / OAuth2
client-credentials), HTTP clients per API surface, a local JSONL audit decorator, and an optional
`require_vault` gate.

### Bulk helper scripts

`mcp-identity` and `mcp-exchange` also ship a `scripts/` folder of standalone PowerShell helpers
for bulk / tenant-wide / CSV operations (e.g. scan every user's MFA state, revoke sessions for a
list, purge a phishing campaign). These are **not MCP tools** — the agent runs them out-of-band in
the background, and each has its own preview / `-WhatIf` confirmation flow and uses the same
credentials as its server. Full catalog: **[docs/SCRIPTS.md](docs/SCRIPTS.md)**.

---

## Architecture at a glance

- **One local MCP process per domain**, launched over stdio by the host (e.g. Claude Code /
  Claude Desktop). Each authenticates to its own API with its own app registration / credentials
  supplied through environment variables.
- **Cross-tool correlation happens in the conversation**, not inside any single server: the agent
  calls `mcp-identity`, `mcp-defender`, `mcp-exchange`, … in the same session and joins the results
  on the shared entity (UPN, device, hash, subject).
- **`mcp-vault` and `mcp-pentesting` are SSH-fronted**: the local MCP process opens SSH to a remote
  host for each call. The vault uses an SSH *forced command* so the analyst's identity is decided
  **server-side by which key authenticated**, not by anything the client can claim — making the
  audit trail non-forgeable even when several analysts share one backend account.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

---

## Safety model

1. **Two-step confirmation for every state-changing action.** Write tools default to
   `confirmed=False` and return a *preview* of exactly what they would do, touching nothing. Only a
   second, explicit `confirmed=True` call executes. This is enforced in server code, not just by
   convention.
2. **Audited by default.** Every tool call is recorded by an `@audited(...)` decorator to a local
   append-only JSONL log; vault writes are additionally audited server-side (append-only log + a
   git commit attributed to the requesting analyst).
3. **Audit gate (`require_vault`) — enabled by default.** *No* tool on any operational server runs
   unless the shared audit vault (`claudian`) is reachable and writable first. If the vault is
   down, every tool fails closed. See [Audit gate](#audit-gate-require_vault) below.
4. **Read-only servers stay read-only** (`mcp-audit`, `mcp-banner`).

---

## Audit gate (`require_vault`)

**Every operational server in this toolkit refuses to run any tool unless it can first confirm
that the team audit vault (`claudian`) is reachable and able to write.** This is deliberate and
enabled by default: in a SOC, an action with no audit trail is worse than an action not taken.

### Why it works this way

The local per-analyst audit log (`@audited`) trusts whatever identity the client asserts. The
shared vault (`mcp-vault`) is the **authoritative** record, because the analyst's identity there is
decided server-side by which SSH key authenticated (a forced command on the `claudian` account),
not by anything the client can claim. The gate ties the two together: if the authoritative audit
destination is unreachable, the toolkit must not perform investigative or response actions whose
record would otherwise be lost or unattributable. So the gate covers **reads too, not just
writes** — even "just looking" at a user, a mailbox or an incident is activity a SOC must be able
to attribute after the fact.

### How it works

- Each operational server (`mcp-defender`, `mcp-identity`, `mcp-exchange`, `mcp-intune`,
  `mcp-audit`, `mcp-cortex`, `mcp-banner`, and `mcp-pentesting`) wraps its `call_tool` handler with
  the `@require_vault` decorator (`shared/mcp_common.py`).
- Before any tool runs, the decorator performs a cheap `ping` to the vault over SSH
  (`shared/vault_client.py`) that only writes and re-reads a timestamp — it does **not** touch
  vault content or create a git commit, so the check is fast and leaves no noise in the history.
- The result is cached for `VAULT_GATE_CACHE_SECONDS` (default 30s) so you don't pay an SSH
  round-trip on every call; while the vault is down, the cache also avoids retrying on every call
  until the window expires.
- If the vault cannot be verified, the tool returns an explicit error (`blocked: could not verify
  the audit vault …`) and does nothing else — it **fails closed**.
- `mcp-vault` itself is intentionally **not** gated: it is the vault, so it cannot gate on its own
  availability. That is the only exception.

### What this requires of your deployment

Because the gate reads the vault over SSH, every gated server needs `VAULT_HOST`, `VAULT_USER`
and `VAULT_SSH_KEY` in its environment (the installer sets these for all of them). If you want to
run a server **without** the gate — for example in a lab with no vault — comment out its
`@require_vault` line; the toolkit works, but without the enforced audit guarantee.

---

## Installation

Requirements: Python 3.11+, an MCP-capable host (Claude Code, Claude Desktop, …), and credentials
for whichever platforms you want to connect.

```bash
git clone https://github.com/<your-org>/soc-mcp-toolkit.git
cd soc-mcp-toolkit
# install each server's dependencies
for d in mcp-*; do pip install -r "$d/requirements.txt"; done
```

On Windows, `install-mcp-cyber-toolkit.ps1` is an interactive installer that prompts for the
environment variables, installs dependencies, and merges the server entries into your host's
MCP config. Every value it suggests is a **placeholder** — replace it with your own.

Each server documents its required environment variables (tenant IDs, client IDs/secrets, API
keys, SSH hosts/keys) at the top of its `server.py`. No real secret ships in this repository. The
exact API permissions each app registration / credential needs are listed in
[docs/PERMISSIONS.md](docs/PERMISSIONS.md).

---

## Roadmap

The goal is to reach **every tool a SOC uses**. Committed next steps:

- **Check Point Harmony Endpoint** — EDR correlation alongside Defender and Cortex.
- **Check Point Harmony Email & Collaboration** — email-security correlation alongside Exchange.

…and a long wishlist of connectors (CrowdStrike, Sentinel, Splunk, Okta, AWS, VirusTotal, Jira,
Slack, and more). See **[docs/ROADMAP.md](docs/ROADMAP.md)** — and help build them.

## Contributing & forks

This project is built to be forked and extended by the community. Adding a connector to a platform
you use is the highest-impact contribution, and each one is a small, self-contained MCP server.

- **How to add a connector:** [docs/ADDING-A-CONNECTOR.md](docs/ADDING-A-CONNECTOR.md)
- **What to build:** [docs/ROADMAP.md](docs/ROADMAP.md)
- **Permissions reference:** [docs/PERMISSIONS.md](docs/PERMISSIONS.md)
- **General guide:** [CONTRIBUTING.md](CONTRIBUTING.md)

Fork it, build a connector, open a PR. Issues and discussions welcome.

## License

[MIT](LICENSE).
