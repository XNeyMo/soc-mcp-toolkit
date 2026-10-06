# Architecture

## Goal

Let a single AI agent investigate and respond to security incidents by driving the SOC's real
tools through a uniform interface (the Model Context Protocol), so that **cross-tool correlation
happens automatically in one conversation** instead of by manual pivoting across consoles.

## Topology

```
                         ┌─────────────────────────────┐
                         │   AI host (MCP client)       │
                         │  e.g. Claude Code / Desktop  │
                         └──────────────┬──────────────┘
                                        │ stdio (one process per server)
   ┌───────────┬───────────┬───────────┼───────────┬───────────┬───────────┐
   ▼           ▼           ▼           ▼           ▼           ▼           ▼
mcp-defender mcp-identity mcp-exchange mcp-intune mcp-audit  mcp-cortex  mcp-banner
   │  Graph /    │ Graph      │ Graph /     │ Graph    │ Graph /   │ Cortex    │ ETHOS
   │  Security   │            │ EXO         │          │ Purview   │ XDR API   │ gateway
   ▼  APIs       ▼            ▼             ▼          ▼           ▼           ▼
            Microsoft 365 / Entra / Defender tenant           Palo Alto    SIS/HR

   mcp-pentesting ──SSH──► Kali lab host        mcp-vault ──SSH(forced cmd)──► vault VM
```

Each server is an independent local process. It is launched by the host over stdio, authenticates
to exactly one upstream with its own credentials, and exposes a focused set of tools.

## Shared library (`shared/`)

| Module                         | Responsibility |
|--------------------------------|----------------|
| `auth.py`                      | MSAL app-only token acquisition for Microsoft APIs. |
| `oauth2_client_credentials.py` | Generic OAuth2 client-credentials (non-Microsoft APIs, e.g. Oracle ORDS behind an ETHOS gateway). |
| `graph_client.py`              | Microsoft Graph HTTP client. |
| `mtp_client.py`                | Microsoft Threat Protection / Security API client. |
| `exo_client.py`                | Exchange Online REST client. |
| `cortex_client.py`             | Cortex XDR client with the nonce + timestamp + SHA-256 auth scheme. |
| `vault_client.py`              | SSH transport to the remote vault agent. |
| `pentest_client.py`            | SSH command builder/runner for the testing lab (background jobs). |
| `audit_log.py`                 | `@audited(...)` decorator → local append-only JSONL audit log. |
| `mcp_common.py`                | Common helpers and the `require_vault` audit gate (enabled by default). |

## Safety model

### Two-step confirmation
Every state-changing tool accepts `confirmed: bool = False`. With `confirmed=False` it returns a
**preview** describing exactly what it would change and touches nothing. Only an explicit second
call with `confirmed=True` performs the action. This is enforced in server code via a
`_preview(...)` / `_executed(...)` convention, so it cannot be bypassed by prompt wording alone.

### Auditing
`@audited("<domain>")` records every tool invocation to a local append-only JSONL log. This is the
baseline, client-side trail.

### Non-forgeable identity in the vault
Local audit logs trust whatever identity the client asserts. For a shared team record that must
answer *"who did what"* even when several analysts use one backend account, `mcp-vault` moves the
trust boundary **server-side**:

- Every analyst connects to the **same** shared Unix account (`claudian`) on the vault VM, but with
  their **own** SSH key.
- Each key is pinned in `authorized_keys` to a distinct **forced command**:
  ```
  command="/data/claudian/bin/vault-agent.py --analyst=<upn>",no-pty,... ssh-ed25519 AAAA... <upn>
  ```
- Because `command=` is fixed, the SSH daemon ignores whatever the client asks to run and always
  invokes the agent with the server-chosen `--analyst`. The analyst cannot forge their identity;
  the server decides it from *which key authenticated*.
- The agent writes to an append-only audit log **and** creates a git commit authored as the
  requesting analyst (committer fixed as the agent), separating "who requested" from "what applied".
  A file lock serializes concurrent writes.

### Audit gate (`require_vault`) — enabled by default
Every operational server (`mcp-defender`, `mcp-identity`, `mcp-exchange`, `mcp-intune`,
`mcp-audit`, `mcp-cortex`, `mcp-banner`, `mcp-pentesting`) wraps its `call_tool` with
`@require_vault`, so **no tool — read or write — runs unless the audit vault (`claudian`) is first
confirmed reachable and writable**. The check is a cheap SSH `ping` that writes and re-reads a
timestamp (it does not touch vault content or commit git), cached for `VAULT_GATE_CACHE_SECONDS`
(default 30s). If the vault cannot be verified, the tool fails closed with an explicit error.

The rationale is auditability: the authoritative "who did what" record lives in the vault with
non-forgeable server-side identity (below). An action whose record could not be written there — a
read included — is activity a SOC could not attribute afterward, so the toolkit refuses it. Only
`mcp-vault` is exempt (it cannot gate on its own availability). To run a server without the gate
(e.g. a vault-less lab), comment out its `@require_vault` line.

## Cross-tool correlation

The toolkit deliberately does **not** build correlation into any single server. Instead, the agent
calls several servers in one session and joins on the shared entity:

- a **UPN** links Entra sign-in/risk (`mcp-identity`), mailbox rules & mail (`mcp-exchange`), and
  user alerts (`mcp-defender`);
- a **device** links Defender and Cortex endpoint state;
- a **file hash / URL / IP** links Defender hunting, Cortex IOCs, and indicator blocklists;
- a **mail subject / sender** links Exchange message correlation and Defender email hunting.

This keeps each server simple and makes the correlation logic transparent and auditable in the
conversation transcript.

## Bulk helpers (`scripts/`)

Some tenant-wide or large-list operations (scan every user, remediate a long list of accounts,
purge a campaign of emails) are impractical as synchronous MCP calls. `mcp-identity/scripts/` and
`mcp-exchange/scripts/` provide PowerShell helpers that authenticate with the **same** app
registration and environment variables as their server, implement their own preview/`-WhatIf`
mode, and are meant to be launched as background jobs. They are **not MCP tools**. See
[SCRIPTS.md](SCRIPTS.md) for the full catalog of what each one does.
