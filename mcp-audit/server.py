"""
MCP Server - Audit (Microsoft Purview)

Scope: eDiscovery, unified audit logs and Information Protection sensitivity
labels. This is the natural domain for a Governance role: read-only
compliance/audit access, with no operational access to Defender/Intune.
The server name reflects its function (audit queries), not the underlying
Microsoft product.

Mode: READ ONLY - on purpose. This is the only one of the security domains
with no write tools; do not add one without an explicit decision.

Requires: pip install -r requirements.txt
Environment variables:
  AZURE_TENANT_ID     (shared across all mcp-* servers)
  AUDIT_CLIENT_ID     (app registration dedicated to Audit)
  AUDIT_CLIENT_SECRET (the analyst's individual secret within that app)
  MCP_ANALYST_NAME    (optional; analyst name for the audit log)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.auth import get_token, load_domain_credentials
from shared.graph_client import GraphClient
from shared.mcp_common import ok, audited, require_vault

TENANT_ID, CLIENT_ID, CLIENT_SECRET = load_domain_credentials("AUDIT")
graph = GraphClient(lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET))

server = Server("mcp-audit")


@server.list_tools()
async def list_tools():
    return [

        types.Tool(
            name="get_ediscovery_cases",
            description=(
                "Lists eDiscovery cases in Microsoft Purview: name, status, "
                "custodians, description and creation date."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "top": {"type": "integer", "default": 20},
                },
            },
        ),

        types.Tool(
            name="get_ediscovery_case_details",
            description=(
                "Details of an eDiscovery case: custodians, active holds, "
                "associated content searches and their statistics."
            ),
            inputSchema={
                "type": "object",
                "required": ["case_id"],
                "properties": {
                    "case_id": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="get_audit_logs",
            description=(
                "Unified audit logs from Microsoft Purview (same source as AuditLog). "
                "Filter by user, operation, service or date range. "
                "Common services: Exchange, SharePoint, Teams, AzureActiveDirectory, Defender."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_email": {"type": "string"},
                    "operation": {
                        "type": "string",
                        "description": "Operation type (e.g. 'MailboxLogin', 'FileDownloaded', 'Add member to group')",
                    },
                    "service": {
                        "type": "string",
                        "description": "Microsoft service (e.g. Exchange, SharePoint, AzureActiveDirectory)",
                    },
                    "top": {"type": "integer", "default": 100},
                },
            },
        ),

        types.Tool(
            name="get_information_protection_labels",
            description=(
                "Lists the Microsoft Purview Information Protection sensitivity labels "
                "and their publishing policies. Useful to know which data classifications "
                "exist in the tenant when investigating information exfiltration."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),

    ]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("audit")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    if name == "get_ediscovery_cases":
        data = graph.get(
            "/compliance/ediscovery/cases",
            params={"$top": arguments.get("top", 20), "$select": "id,displayName,status,description,createdDateTime,lastModifiedDateTime"},
            beta=True,
        )
        return ok(data)

    elif name == "get_ediscovery_case_details":
        case_id = arguments["case_id"]
        case = graph.get(f"/compliance/ediscovery/cases/{case_id}", beta=True)
        try:
            custodians = graph.get(f"/compliance/ediscovery/cases/{case_id}/custodians", beta=True)
            case["_custodians"] = custodians.get("value", [])
        except Exception:
            pass
        try:
            searches = graph.get(f"/compliance/ediscovery/cases/{case_id}/searches", beta=True)
            case["_searches"] = searches.get("value", [])
        except Exception:
            pass
        return ok(case)

    elif name == "get_audit_logs":
        params = {"$top": arguments.get("top", 100), "$orderby": "activityDateTime desc"}
        filters = []
        if arguments.get("user_email"):
            filters.append(f"initiatedBy/user/userPrincipalName eq '{arguments['user_email']}'")
        if arguments.get("operation"):
            filters.append(f"activityDisplayName eq '{arguments['operation']}'")
        if arguments.get("service"):
            filters.append(f"category eq '{arguments['service']}'")
        if filters:
            params["$filter"] = " and ".join(filters)
        data = graph.get("/auditLogs/directoryAudits", params)
        return ok(data)

    elif name == "get_information_protection_labels":
        data = graph.get("/informationProtection/policy/labels", beta=True)
        return ok(data)

    else:
        raise ValueError(f"Tool '{name}' not found")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )

if __name__ == "__main__":
    import asyncio
    asyncio.run(_main())
