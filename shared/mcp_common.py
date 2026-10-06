"""Common MCP response helpers + audit/gate decorators for call_tool."""

import functools
import json
import os
import time

from mcp import types

from . import audit_log, vault_client


def ok(data) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=json.dumps(data, ensure_ascii=False, indent=2))]


def err(e: Exception) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=f"[ERROR] {type(e).__name__}: {e}")]


def audited(domain: str):
    """Wraps call_tool: records every invocation (success or error) in the
    domain's local audit log and turns unhandled exceptions into an [ERROR]
    response instead of crashing the server."""
    def decorator(fn):
        @functools.wraps(fn)
        async def wrapper(name: str, arguments: dict):
            try:
                result = await fn(name, arguments)
                audit_log.log_action(domain, name, arguments, outcome="ok")
                return result
            except Exception as e:
                audit_log.log_action(domain, name, arguments, outcome="error", error=str(e))
                return err(e)
        return wrapper
    return decorator


_VAULT_GATE_TTL = float(os.environ.get("VAULT_GATE_CACHE_SECONDS", "30"))
_vault_check = {"ts": 0.0, "ok": False, "error": None}


def require_vault(fn):
    """Wraps call_tool: blocks EVERY tool (read or write) of this server until it
    can verify that mcp-vault (the remote audit vault) is reachable and able to
    write. The check (an SSH ping that does not touch vault content, see
    shared/vault_client.py) is cached for VAULT_GATE_CACHE_SECONDS (default 30s)
    to avoid an SSH round-trip on every call — while the vault is down, the cache
    also prevents retrying on every call until that window expires.

    Applied to every operational server (defender/identity/exchange/intune/audit/
    cortex/banner and pentesting), NEVER to mcp-vault itself (the vault cannot gate
    on its own availability). In this project it is ENABLED by default: each of those
    servers carries an active @require_vault decorator, so if the audit vault is
    unreachable, every tool fails closed with an explanatory error instead of acting
    without an audit trail."""
    @functools.wraps(fn)
    async def wrapper(name: str, arguments: dict):
        now = time.monotonic()
        if now - _vault_check["ts"] > _VAULT_GATE_TTL:
            try:
                vault_client.ping_vault()
                _vault_check["ok"] = True
                _vault_check["error"] = None
            except Exception as e:
                _vault_check["ok"] = False
                _vault_check["error"] = str(e)
            _vault_check["ts"] = now
        if not _vault_check["ok"]:
            return err(RuntimeError(
                f"blocked: could not verify the audit vault before running "
                f"'{name}' ({_vault_check['error']})"
            ))
        return await fn(name, arguments)
    return wrapper
