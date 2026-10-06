"""
Authoritative audit trail for the SOC vault - runs server-side (on the VM) and
never trusts anything sent by the client except the `analyst` that
bin/vault-agent.py receives from sshd (forced command), not from the JSON
payload.

Two layers, both here:
  - audit/vault.log.jsonl  - plain-text, append-only log (`chattr +a` on the
    file is recommended so that even the system user cannot rewrite past
    lines, only append new ones).
  - git commit --author "<analyst> <email>" on the vault itself - the
    committer is fixed as "vault-agent" (see ensure_git_repo), distinct from
    the author, to tell apart "who requested the change" from "which process
    applied it".

logs/agent.log is a DIFFERENT log (errors/tracebacks of the agent itself, not
analyst actions) - keeping it separate from the audit log prevents an
internal parsing bug from polluting the record of "who did what".
"""

import fcntl
import json
import logging
import os
import subprocess
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import yaml

from . import notes

BASE_DIR = Path(__file__).resolve().parent.parent
AUDIT_PATH = Path(os.environ.get("VAULT_AUDIT") or (BASE_DIR / "audit" / "vault.log.jsonl"))
LOCK_PATH = Path(os.environ.get("VAULT_LOCK") or (BASE_DIR / "locks" / "vault.lock"))
CONFIG_PATH = Path(os.environ.get("VAULT_CONFIG") or (BASE_DIR / "config" / "analysts.yaml"))
LOG_PATH = Path(os.environ.get("VAULT_LOG") or (BASE_DIR / "logs" / "agent.log"))
AUTHOR_DOMAIN = os.environ.get("VAULT_AUTHOR_DOMAIN", "example.com")

WRITE_TOOLS = {"create_note", "append_note", "upsert_entity", "daily_log"}

_logger = None


def get_logger() -> logging.Logger:
    global _logger
    if _logger is not None:
        return _logger
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _logger = logging.getLogger("vault-agent")
    _logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    _logger.addHandler(handler)
    return _logger


@contextmanager
def lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOCK_PATH, "w") as lock_f:
        fcntl.flock(lock_f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_f, fcntl.LOCK_UN)


def _analysts_map() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return {}


def _git_author(analyst: str) -> str:
    email = _analysts_map().get(analyst) or (analyst if "@" in analyst else f"{analyst}@{AUTHOR_DOMAIN}")
    return f"{analyst} <{email}>"


def ensure_git_repo():
    if not (notes.VAULT_ROOT / ".git").exists():
        subprocess.run(["git", "init", "--quiet", str(notes.VAULT_ROOT)], check=True)
        subprocess.run(["git", "-C", str(notes.VAULT_ROOT), "config", "user.name", "vault-agent"], check=True)
        subprocess.run(["git", "-C", str(notes.VAULT_ROOT), "config", "user.email", "vault-agent@claudian.local"], check=True)


def git_commit(analyst: str, message: str):
    ensure_git_repo()
    subprocess.run(["git", "-C", str(notes.VAULT_ROOT), "add", "-A"], check=True)
    result = subprocess.run(
        ["git", "-C", str(notes.VAULT_ROOT), "commit", "--quiet", "--author", _git_author(analyst), "-m", message],
        capture_output=True,
    )
    # exit code 1 with nothing staged (nothing to commit) is not a real error
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git commit failed: {result.stderr.decode(errors='replace')}")


def log_action(analyst: str, tool: str, arguments: dict, outcome: str, error: str = None):
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "analyst": analyst,
        "tool": tool,
        "arguments": notes.json_safe(arguments),
        "outcome": outcome,
    }
    if error:
        entry["error"] = error
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
