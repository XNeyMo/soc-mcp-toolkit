"""
Per-analyst local audit log.

With application permissions (client credentials), Graph only sees the app
identity, never the person who performed the action. Since each analyst uses
their own client secret (named after them in the identity provider),
MCP_ANALYST_NAME must be set locally to that same name so there is a record of
"who did what" -- especially for destructive tools.
"""

import json
import os
import time
from pathlib import Path

LOG_DIR = Path(os.environ.get("MCP_AUDIT_LOG_DIR", Path.home() / ".mct_logs" / "audit"))


def get_analyst_upn() -> str:
    """Locally configured analyst UPN (falls back to the OS user).
    Besides the audit log, the mcp-* servers use it to automatically assign
    themselves the incidents/tasks they are remediating."""
    return os.environ.get("MCP_ANALYST_NAME") or os.environ.get("USERNAME") or "unknown"


def log_action(domain: str, tool: str, arguments: dict, outcome: str, error: str = None) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "analyst": get_analyst_upn(),
        "domain": domain,
        "tool": tool,
        "arguments": arguments,
        "outcome": outcome,
    }
    if error:
        entry["error"] = error
    log_file = LOG_DIR / f"{domain}.log.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
