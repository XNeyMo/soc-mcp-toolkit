"""
MCP Server - Devices (Microsoft Intune)

Scope: querying devices managed by Intune - per-user inventory, device
details and compliance. This is not Defender XDR: isolating a device because
of an active alert is a Defender for Endpoint action (it lives in
mcp-defender); changing compliance policies or wiping a device is Intune
administration and would belong here.

Mode: read only.

Requires: pip install -r requirements.txt
Environment variables:
  AZURE_TENANT_ID      (shared across all mcp-* servers)
  INTUNE_CLIENT_ID     (app registration dedicated to Intune)
  INTUNE_CLIENT_SECRET (the analyst's individual secret within that app)
  MCP_ANALYST_NAME     (optional; analyst name for the audit log)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.auth import get_token, load_domain_credentials
from shared.graph_client import GraphClient
from shared.mcp_common import ok, err, audited, require_vault

TENANT_ID, CLIENT_ID, CLIENT_SECRET = load_domain_credentials("INTUNE")
graph = GraphClient(lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET))

server = Server("mcp-intune")


@server.list_tools()
async def list_tools():
    return [

        types.Tool(
            name="get_intune_devices_by_user",
            description=(
                "Lists all Intune devices registered to a user: "
                "name, OS, compliance status, encryption, last check-in, "
                "whether it is jailbroken/rooted, and risk level."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="get_intune_device_details",
            description=(
                "Full details of an Intune device by ID or name: "
                "hardware, OS, installed apps, compliance state, applied policies, "
                "certificates and Azure AD device ID (to correlate with Defender alerts)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "device_id": {
                        "type": "string",
                        "description": "Intune ID of the device",
                    },
                    "device_name": {
                        "type": "string",
                        "description": "Device name (alternative to the ID)",
                    },
                },
            },
        ),

        types.Tool(
            name="get_noncompliant_devices",
            description=(
                "Lists all Intune devices that do NOT meet compliance policies. "
                "Includes the reason for non-compliance. Useful to understand why "
                "compliance-based Conditional Access did not block an access."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

    ]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("intune")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    if name == "get_intune_devices_by_user":
        user = arguments["user_email"]
        data = graph.get(
            "/deviceManagement/managedDevices",
            params={
                "$filter": f"userPrincipalName eq '{user}'",
                "$select": "id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,jailBroken,azureADDeviceId,managedDeviceOwnerType,deviceEnrollmentType,deviceRegistrationState,deviceHealthAttestationState",
            },
        )
        return ok(data)

    elif name == "get_intune_device_details":
        if arguments.get("device_id"):
            data = graph.get(f"/deviceManagement/managedDevices/{arguments['device_id']}")
        elif arguments.get("device_name"):
            result = graph.get(
                "/deviceManagement/managedDevices",
                params={"$filter": f"deviceName eq '{arguments['device_name']}'"},
            )
            data = result.get("value", [])
        else:
            return err(ValueError("device_id or device_name is required"))
        return ok(data)

    elif name == "get_noncompliant_devices":
        data = graph.get(
            "/deviceManagement/managedDevices",
            params={
                "$filter": "complianceState eq 'noncompliant'",
                "$top": arguments.get("top", 50),
                "$select": "id,deviceName,userPrincipalName,operatingSystem,complianceState,lastSyncDateTime,azureADDeviceId",
            },
        )
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
