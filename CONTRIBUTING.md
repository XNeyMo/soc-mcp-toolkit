# Contributing

Thanks for your interest in improving the SOC MCP Toolkit. The goal is **one AI agent that can
reach every tool a SOC uses** — so the most valuable thing you can build is a connector to a
platform we don't cover yet. Forks and PRs are very welcome.

## Ways to contribute

- **Build a new connector** (a new MCP server) — the highest-impact contribution. Step-by-step
  guide: **[docs/ADDING-A-CONNECTOR.md](docs/ADDING-A-CONNECTOR.md)**. Wishlist of platforms:
  **[docs/ROADMAP.md](docs/ROADMAP.md)**.
- **Extend an existing server** — add a tool for an endpoint it doesn't cover yet.
- **Harden** — tests, error handling, input validation.
- **Correlation playbooks** — document how to chain servers for a given incident type.
- **Docs** — setup, permissions, onboarding, this guide.

New here? Look for **good first issues** in [docs/ROADMAP.md](docs/ROADMAP.md).

## Fork & PR workflow

1. **Fork** the repo and clone your fork.
2. Create a branch: `git checkout -b connector/<platform>` (or `fix/<thing>`).
3. Make your change (see the guides above). Keep it scoped to one connector/concern.
4. `python -m py_compile` your server; run it against a **non-production** / authorized environment.
5. Run a repo-wide search for secrets and internal identifiers — it must come back empty.
6. Commit, push to your fork, and open a PR against `main` with a clear description of what you
   built and what you tested it against (no real data).

## Ground rules

- **No secrets, ever.** Do not commit real tenant IDs, client secrets, API keys, SSH keys, hosts,
  internal IPs, or real account names. Use placeholders (`example.com`, `10.0.0.x`,
  `00000000-...`, `analyst@example.com`).
- **English only** for code comments, docstrings, tool descriptions, and documentation.
- **Keep the safety model intact.** State-changing tools must keep the two-step
  `confirmed` / `_preview` / `_executed` pattern and the `@audited(...)` decorator. Read-only
  servers (`mcp-audit`, `mcp-banner`) must stay read-only unless there is an explicit design reason.

## Project layout

```
shared/            Shared auth/HTTP/audit/vault clients used by every server
mcp-<domain>/      One MCP server per security domain (server.py + requirements.txt)
  scripts/         Optional bulk/CSV PowerShell helpers that run outside the MCP protocol
install-mcp-cyber-toolkit.ps1   Interactive Windows installer
merge_claude_config.py          Merges server entries into the host MCP config
docs/              Architecture and design notes
```

## Adding a new MCP server

Full walkthrough with a copy-paste skeleton: **[docs/ADDING-A-CONNECTOR.md](docs/ADDING-A-CONNECTOR.md)**.
In short:

1. Create `mcp-<domain>/server.py` and `requirements.txt`.
2. Reuse the clients in `shared/` for authentication and HTTP.
3. Document required environment variables and the exact permissions in
   [docs/PERMISSIONS.md](docs/PERMISSIONS.md) and a `REQUIRED PERMISSIONS` block in `server.py`.
4. Wrap the handler with `@audited("<domain>")` and `@require_vault`.
5. For any state-changing tool, implement the `confirmed=False` preview path first.
6. Add the server to the README table, PERMISSIONS.md, and the installer.

## Development

```bash
pip install -r mcp-<domain>/requirements.txt
python -m py_compile mcp-<domain>/server.py   # quick sanity check
```

Run your server against a **non-production** tenant or an authorized test environment first.

## Pull requests

- Keep changes scoped to one server/concern where possible.
- Describe what platform/API behavior you verified against (without pasting real data).
- Make sure a repository-wide search for internal identifiers comes back empty.
