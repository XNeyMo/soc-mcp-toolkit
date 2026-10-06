"""
SSH client for the remote team audit vault (mcp-vault) — shared by mcp-vault
itself and by the other servers (via require_vault in mcp_common.py) to verify
that the audit vault is reachable before taking any action.

Environment variables (required, no embedded default — set by
install-mcp-cyber-toolkit.ps1): VAULT_HOST, VAULT_USER, VAULT_SSH_KEY.
"""

import json
import os
import subprocess


def _ssh_cmd() -> list[str]:
    return [
        "ssh",
        "-i", os.environ["VAULT_SSH_KEY"],
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=accept-new",
        f"{os.environ['VAULT_USER']}@{os.environ['VAULT_HOST']}",
    ]


def call_vault(tool: str, arguments: dict, timeout: int = 30):
    payload = json.dumps({"tool": tool, "arguments": arguments}, ensure_ascii=False)
    try:
        proc = subprocess.run(
            _ssh_cmd(), input=payload, capture_output=True, text=True, timeout=timeout, encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"SSH to the vault timed out ({timeout}s)")

    stdout = (proc.stdout or "").strip()
    if not stdout:
        raise RuntimeError(f"No response from the vault over SSH (exit {proc.returncode}). stderr: {(proc.stderr or '').strip()}")
    try:
        result = json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError:
        raise RuntimeError(f"Non-JSON response from the vault: {stdout!r} (stderr: {(proc.stderr or '').strip()})")

    if not result.get("ok"):
        raise RuntimeError(result.get("error", "unknown vault error"))
    return result.get("data")


def ping_vault(timeout: int = 15):
    """Verify the vault is reachable AND can write — does not touch vault content
    or make a git commit, just exercises the SSH + filesystem pipeline."""
    return call_vault("ping", {}, timeout=timeout)
