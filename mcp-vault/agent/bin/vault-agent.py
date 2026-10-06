#!/usr/bin/env python3
"""
vault-agent - server side of the remote SOC team vault, invoked as a
"forced command" from the authorized_keys of the shared Unix account on the
VM, one line per analyst:

    command="/data/claudian/bin/vault-agent.py --analyst=<upn>",no-port-forwarding,no-X11-forwarding,no-pty,no-agent-forwarding ssh-ed25519 AAAA... <upn>@laptop

With `command=` set, sshd IGNORES any command requested by the client and
always runs this script with the `--analyst` from that line. This is what
makes the identity in the audit trail non-forgeable from the analyst's laptop
(the server decides it when it accepts the key, not the client). This script
NEVER reads the analyst from anywhere other than argv.

Protocol: the client (mcp-vault/server.py, running locally on each laptop)
writes a JSON `{"tool": ..., "arguments": {...}}` to stdin and reads a JSON
`{"ok": true, "data": ...}` or `{"ok": false, "error": ...}` from stdout.
Besides the note tools (create_note/append_note/...), it accepts `ping`
(no arguments) - it does not touch vault content or make a commit, it only
checks that the SSH+filesystem+lock pipeline works. It is used by
require_vault in shared/mcp_common.py and shared/vault_client.py so the other
mcp-* servers can verify the vault before running any of their tools.

Expected layout (deployment root, e.g. /data/claudian):
  bin/vault-agent.py (this file) · lib/{notes,audit}.py · data/vault/
  (the actual Obsidian vault) · audit/vault.log.jsonl · config/analysts.yaml ·
  locks/vault.lock · logs/agent.log · backups/
"""

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import notes, audit


def _analyst_from_argv() -> str:
    for a in sys.argv[1:]:
        if a.startswith("--analyst="):
            return a.split("=", 1)[1]
    return None


def _commit_message(tool: str, arguments: dict) -> str:
    hint = arguments.get("path") or arguments.get("name") or ""
    return f"{tool} {hint}".strip()


def _ping() -> dict:
    """Checks the SSH+filesystem+lock pipeline without touching vault content
    or making a git commit. Used by the other mcp-* servers (require_vault in
    shared/mcp_common.py) to verify the vault is available before running
    any of their own tools."""
    check_path = notes.BASE_DIR / "locks" / ".ping"
    check_path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    check_path.write_text(stamp, encoding="utf-8")
    return {"pong": True, "checked": check_path.read_text(encoding="utf-8") == stamp}


def main():
    analyst = _analyst_from_argv()
    if not analyst:
        print(json.dumps({"ok": False, "error": "vault-agent: --analyst was not provided by the forced command (check authorized_keys)"}))
        sys.exit(1)

    logger = audit.get_logger()

    try:
        payload = json.loads(sys.stdin.read())
        tool = payload["tool"]
        arguments = payload.get("arguments") or {}
    except Exception as e:
        logger.exception("invalid payload from %s", analyst)
        print(json.dumps({"ok": False, "error": f"invalid payload: {e}"}))
        sys.exit(1)

    notes.VAULT_ROOT.mkdir(parents=True, exist_ok=True)

    try:
        with audit.lock():
            if tool == "ping":
                data = _ping()
            else:
                data = notes.dispatch(analyst, tool, arguments)
                if tool in audit.WRITE_TOOLS:
                    audit.git_commit(analyst, _commit_message(tool, arguments))
        audit.log_action(analyst, tool, arguments, outcome="ok")
        print(json.dumps({"ok": True, "data": data}, ensure_ascii=False))
    except Exception as e:
        logger.exception("tool=%s analyst=%s failed", tool, analyst)
        audit.log_action(analyst, tool, arguments, outcome="error", error=str(e))
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
