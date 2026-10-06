# Adding a connector (a new MCP server)

This toolkit is built to grow. Each security platform is one small, self-contained MCP server that
follows the same handful of conventions, so adding a new connector — Check Point Harmony, a SIEM, a
threat-intel feed, a ticketing system — is mostly filling in a well-worn template.

This guide walks through it end to end. If anything here is unclear, open a discussion or a draft
PR — improving this guide counts as a contribution too.

> **The golden rules.** A connector that doesn't follow these will not be merged:
> 1. **Own credential, least privilege.** Each server authenticates with its own key/app and asks
>    for the minimum scopes. Document them in [PERMISSIONS.md](PERMISSIONS.md).
> 2. **No secrets in code.** Everything sensitive is read from environment variables. Ship
>    placeholders only.
> 3. **Two-step confirmation for every state-changing tool** (`confirmed` → preview → execute).
> 4. **Audited.** Wrap the handler with `@audited("<domain>")`, and with `@require_vault` unless
>    there's a clear reason not to (see below).
> 5. **English**, typed input schemas, and it must `python -m py_compile` cleanly.

---

## 1. Anatomy of a server

A server lives in `mcp-<domain>/` and has two files: `server.py` and `requirements.txt`. It reuses
the shared library in [`shared/`](../shared) for auth, HTTP, auditing and the vault gate:

| Need | Use |
|---|---|
| Microsoft Entra app-only token | `shared.auth.get_token` / `load_domain_credentials` |
| Generic OAuth2 client_credentials (non-Microsoft) | `shared.oauth2_client_credentials` |
| Microsoft Graph calls | `shared.graph_client.GraphClient` |
| Defender/MDE security APIs | `shared.mtp_client.MtpClient` |
| Exchange Online admin API | `shared.exo_client.ExoClient` |
| Cortex-style signed API | `shared.cortex_client.CortexClient` (pattern reference) |
| A brand-new HTTP API | add a small client in `shared/` or use `httpx` directly |
| MCP responses + decorators | `shared.mcp_common` (`ok`, `err`, `audited`, `require_vault`) |
| Local per-analyst audit log | automatic via `@audited` |

## 2. Pick your auth pattern

- **Microsoft 365 / Entra product?** Create a dedicated app registration, give it a
  `<DOMAIN>_CLIENT_ID` / `<DOMAIN>_CLIENT_SECRET` pair and reuse `AZURE_TENANT_ID`. Use
  `load_domain_credentials("<DOMAIN>")`.
- **Third-party with OAuth2 client_credentials?** (e.g. Banner.) Use
  `shared.oauth2_client_credentials` with `<PRODUCT>_TOKEN_URL` / `_CLIENT_ID` / `_CLIENT_SECRET`.
- **Vendor API key with a signing scheme?** (e.g. Cortex XDR.) Mirror `shared/cortex_client.py`.
- **Something over SSH or a local agent?** (e.g. vault, pentesting.) Mirror `shared/vault_client.py`
  or `shared/pentest_client.py`.

Pick env-var names that match the pattern and never embed a default secret.

## 3. The skeleton

```python
"""
MCP Server - <Product> (<one line of scope>)

Auth: <how it authenticates>.
Environment variables:
  <PRODUCT>_...   <description>
  MCP_ANALYST_NAME (optional; analyst name for the local audit log)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.mcp_common import ok, err, audited, require_vault
# ... import the auth/HTTP client you chose ...

server = Server("mcp-<domain>")

# ---- two-step confirmation helpers (copy the pattern from any existing server) ----
def _preview(action, target, detail):
    return ok({"mode": "PREVIEW - action NOT executed", "action": action,
               "target": target, "detail": detail,
               "next_step": "Call again with confirmed=True to execute."})

def _executed(action, result):
    return ok({"mode": "EXECUTED", "action": action, "result": result})


@server.list_tools()
async def list_tools():
    return [
        types.Tool(
            name="get_something",
            description="Read-only lookup. Plain English, say exactly what it returns.",
            inputSchema={"type": "object", "required": ["id"],
                         "properties": {"id": {"type": "string"}}},
        ),
        types.Tool(
            name="do_something",
            description=("Changes state on <product>. confirmed=False (default) returns a preview; "
                         "confirmed=True executes."),
            inputSchema={"type": "object", "required": ["id"],
                         "properties": {"id": {"type": "string"},
                                        "confirmed": {"type": "boolean", "default": False}}},
        ),
    ]


@server.call_tool()
@audited("<domain>")
@require_vault          # AUDIT GATE: no tool runs unless the vault (claudian) is reachable
async def call_tool(name: str, arguments: dict):
    if name == "get_something":
        return ok(...)                       # read-only: just do it

    if name == "do_something":
        target = arguments["id"]
        if not arguments.get("confirmed", False):
            return _preview("do_something", target, "what would change")
        return _executed("do_something", ...)  # only runs on confirmed=True

    raise ValueError(f"unknown tool: {name}")


async def _main():
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())

if __name__ == "__main__":
    import asyncio
    asyncio.run(_main())
```

Add the decorator order exactly as shown: `@server.call_tool()`, then `@audited(...)`, then
`@require_vault`, then the function.

## 4. The audit gate (`require_vault`)

By default every operational server is gated so **no tool runs unless the team audit vault is
reachable and writable** (see [ARCHITECTURE.md](ARCHITECTURE.md) and the README). Keep it on for
any connector that reads or changes real security data. A connector may omit it only if it never
touches a real tenant/target (pure-local utility) — justify that in your PR. Gated servers need
`VAULT_HOST` / `VAULT_USER` / `VAULT_SSH_KEY` in their environment; add them to the server's entry
in the installer.

## 5. Tool design checklist

- **Reads are free; writes are gated.** Every tool that changes state on the remote system takes
  `confirmed: bool = False` and returns a preview first.
- **Typed input schemas** with `required` and clear English `description`s — these are what the AI
  agent reads to decide how to call you.
- **Don't invent fields.** Keep the vendor's real API field names in requests/responses.
- **Return the raw useful data**; don't over-summarize server-side — correlation happens in the
  conversation.
- **Fail loudly, not silently.** Raise with a clear message; `@audited` turns it into an `[ERROR]`.

## 6. Wire it up

1. `mcp-<domain>/requirements.txt` — pin `mcp` plus whatever you import (`httpx`, `msal`, ...).
2. Add the server to the **README** server table and to **[PERMISSIONS.md](PERMISSIONS.md)** with
   the exact scopes/roles it needs.
3. Register it in **`install-mcp-cyber-toolkit.ps1`**: add an env-var prompt block and an entry in
   the `.claude.json` `mcpServers` section (copy an existing block; include the `VAULT_*` vars if
   gated).
4. If it's a whole new auth style, add a small reusable client to `shared/` rather than inlining
   it, so the next connector can reuse it.

## 7. Test before you PR

```bash
pip install -r mcp-<domain>/requirements.txt
python -m py_compile mcp-<domain>/server.py
```

Run the server against a **non-production** tenant or a target you are authorized to test. In your
PR, say what you verified against (without pasting real data), and confirm a repo-wide search for
internal identifiers/secrets comes back empty.

## 8. Open the PR

See [CONTRIBUTING.md](../CONTRIBUTING.md). Keep it scoped to one connector. Welcome aboard — and
thank you for making the toolkit reach further.
