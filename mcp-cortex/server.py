"""
MCP Server - Cortex XDR (Palo Alto Networks)

Scope: investigation and response through Cortex XDR - incidents, alerts,
endpoints (isolate/unisolate/scan/file quarantine), hash block/allow lists and
IOC indicators. Complements mcp-defender: a malware hash seen in a Defender
incident can be added here to the Cortex block list; a malware scan of a device
is triggered here (Defender does not do that); having both products connected
helps correlate findings.

Auth: Cortex XDR Advanced API Key (Investigation Admin + Responder + Viewer roles), NOT OAuth/Entra
- see shared/cortex_client.py. It is a single key shared by the team; there is
no per-analyst secret as in the other mcp-* domains.

Requires: pip install -r requirements.txt
Environment variables:
  CORTEX_FQDN         (tenant identifier, e.g. "mytenant" - shown under Configurations >
                        API Keys when creating the key, in the example URL the portal displays)
  CORTEX_REGION       (tenant region, e.g. "us")
  CORTEX_API_KEY_ID   (Advanced API Key id)
  CORTEX_API_KEY      (Advanced API Key value)
  MCP_ANALYST_NAME    (optional; analyst name for the local audit log)

  The base_url (https://api-<CORTEX_FQDN>.xdr.<CORTEX_REGION>.paloaltonetworks.com) is built
  from these two variables in shared/cortex_client.py - no need to configure it
  as a full URL.

Known limitations:
- Most endpoints of this API are asynchronous: isolate/unisolate/scan return an
  action_id immediately; poll get_cortex_action_status to confirm the action
  finished on the endpoint. An HTTP 200 only confirms the order was accepted.
- add_cortex_ioc_indicator ONLY creates a detection indicator inside Cortex XDR.
  It does NOT publish it to the EDL (External Dynamic List) consumed by NGFW
  firewalls for blocking. Populating the EDL is a separate manual action in the
  portal (Action Center > Add to EDL); no documented REST endpoint automates it.
  Do not claim IP/domain blocking via this tool without that extra manual step.
- update_cortex_alerts uses /alerts/update_alerts with a request_data shape
  inferred by analogy with update_incident (alert_id_list + update_data). Unlike
  the other tools in this server, the exact body shape is not confirmed against
  official documentation; validate against your tenant before relying on it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.cortex_client import CortexClient, load_cortex_credentials
from shared.mcp_common import ok, err, audited, require_vault
from shared.audit_log import get_analyst_upn

BASE_URL, API_KEY_ID, API_KEY = load_cortex_credentials()
cortex = CortexClient(BASE_URL, API_KEY, API_KEY_ID)

server = Server("mcp-cortex")

IOC_TYPES = ["HASH", "IP", "DOMAIN_NAME", "FILENAME"]

# The tool schema exposes severity in lowercase (consistent with the rest of the
# server: update_cortex_incident/update_cortex_alerts use low/medium/high), but
# Cortex XDR's /indicators/insert_jsons/ requires exactly one of
# ['CRITICAL', 'HIGH', 'INFO', 'LOW', 'MEDIUM']. Note that "informational" does not
# map by simple uppercasing: the real value is "INFO", not "INFORMATIONAL".
IOC_SEVERITY_MAP = {
    "informational": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


def _endpoint_target(endpoint_id_list: list, incident_id=None) -> dict:
    """Isolate/unisolate/scan accept a bare endpoint_id for a single endpoint,
    or filters (operator 'in') for several. incident_id is optional in all three."""
    if not endpoint_id_list:
        raise ValueError("At least one endpoint_id is required")
    request_data: dict = {}
    if len(endpoint_id_list) == 1:
        request_data["endpoint_id"] = endpoint_id_list[0]
    else:
        request_data["filters"] = [
            {"field": "endpoint_id_list", "operator": "in", "value": endpoint_id_list}
        ]
    if incident_id:
        request_data["incident_id"] = incident_id
    return request_data


def _preview(action: str, target: dict, what_would_happen: str, **extra):
    """Same as the _preview in mcp-defender: every tool that writes/acts in Cortex XDR
    goes through here when confirmed=False (the default) - it never applies the change
    in that case, it only shows what it would do. The user must review and approve this
    preview before the tool is called again with confirmed=True."""
    payload = {
        "mode": "PREVIEW - action NOT executed",
        "action": action,
        "target": target,
        "what_would_happen": what_would_happen,
    }
    payload.update(extra)
    payload["next_step"] = "Call again with confirmed=True to execute."
    return ok(payload)


def _executed(action: str, result):
    return ok({
        "mode": "EXECUTED",
        "action": action,
        "result": result,
    })


def _current_incident(incident_id: str) -> dict:
    data = cortex.call("/incidents/get_incidents/", {
        "filters": [{"field": "incident_id_list", "operator": "in", "value": [incident_id]}]
    })
    incidents = data.get("incidents", [])
    return incidents[0] if incidents else {}


def _current_alerts(alert_id_list: list) -> list:
    data = cortex.call("/alerts/get_alerts", {
        "filters": [{"field": "alert_id_list", "operator": "in", "value": [int(a) for a in alert_id_list]}]
    })
    return data.get("alerts", [])


def _current_endpoints(endpoint_id_list: list) -> list:
    data = cortex.call("/endpoints/get_endpoint/", {
        "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_id_list}]
    })
    return data.get("endpoints", [])


@server.list_tools()
async def list_tools():
    return [

        # -- Incidents ------------------------------------------------------

        types.Tool(
            name="get_cortex_incidents",
            description=(
                "Lists Cortex XDR incidents filtered by status, specific IDs, or a creation/"
                "modification date range. Paginated with search_from/search_to."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "E.g. new, under_investigation, resolved_true_positive, resolved_false_positive"},
                    "incident_id_list": {"type": "array", "items": {"type": "string"}},
                    "creation_time_gte": {"type": "integer", "description": "Epoch ms"},
                    "creation_time_lte": {"type": "integer", "description": "Epoch ms"},
                    "modification_time_gte": {"type": "integer", "description": "Epoch ms"},
                    "modification_time_lte": {"type": "integer", "description": "Epoch ms"},
                    "search_from": {"type": "integer", "default": 0},
                    "search_to": {"type": "integer", "default": 100},
                    "sort_by": {"type": "string", "enum": ["creation_time", "modification_time"]},
                    "sort_order": {"type": "string", "enum": ["asc", "desc"]},
                },
            },
        ),

        types.Tool(
            name="get_cortex_incident_details",
            description=(
                "Full details of a Cortex XDR incident: related alerts, "
                "network artifacts and file artifacts."
            ),
            inputSchema={
                "type": "object",
                "required": ["incident_id"],
                "properties": {
                    "incident_id": {"type": "string"},
                    "alerts_limit": {"type": "integer", "default": 1000},
                },
            },
        ),

        types.Tool(
            name="update_cortex_incident",
            description=(
                "WARNING - MODIFIES DATA: updates status, manual severity, assigned analyst "
                "or comment of a Cortex XDR incident. resolve_comment is only accepted if "
                "status ends up as a resolved_* value. "
                "confirmed=False (default) only shows a preview of the changes; "
                "confirmed=True applies them."
            ),
            inputSchema={
                "type": "object",
                "required": ["incident_id"],
                "properties": {
                    "incident_id": {"type": "string"},
                    "status": {"type": "string"},
                    "severity": {"type": "string", "description": "manual_severity: low, medium, high"},
                    "assigned_user_mail": {"type": "string"},
                    "unassign_user": {"type": "boolean", "default": False},
                    "resolve_comment": {"type": "string"},
                    "add_comment": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # -- Alerts -----------------------------------------------------------

        types.Tool(
            name="get_cortex_alerts",
            description=(
                "Lists Cortex XDR alerts filtered by IDs, source, severity or creation date. "
                "For the alerts of a specific incident, call get_cortex_incident_details "
                "first and pass the alert_ids obtained there as alert_id_list."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id_list": {"type": "array", "items": {"type": "string"}},
                    "alert_source": {"type": "array", "items": {"type": "string"}},
                    "severity": {"type": "array", "items": {"type": "string", "enum": ["low", "medium", "high", "critical"]}},
                    "creation_time_gte": {"type": "integer", "description": "Epoch ms"},
                    "creation_time_lte": {"type": "integer", "description": "Epoch ms"},
                    "search_from": {"type": "integer", "default": 0},
                    "search_to": {"type": "integer", "default": 100},
                },
            },
        ),

        types.Tool(
            name="update_cortex_alerts",
            description=(
                "WARNING - MODIFIES DATA: updates severity, status or comment of one or more "
                "Cortex XDR alerts. NOTE: the body shape of this endpoint is not "
                "confirmed against official documentation (see module docstring) - verify "
                "the result against your tenant before relying on it in an active case. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["alert_id_list"],
                "properties": {
                    "alert_id_list": {"type": "array", "items": {"type": "string"}},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "status": {"type": "string"},
                    "comment": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # -- Endpoints -----------------------------------------------------------

        types.Tool(
            name="get_cortex_endpoints",
            description=(
                "Lists endpoints managed by Cortex XDR filtered by hostname, IP, "
                "group, platform, connection status or isolation status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "endpoint_id_list": {"type": "array", "items": {"type": "string"}},
                    "hostname": {"type": "array", "items": {"type": "string"}},
                    "ip_list": {"type": "array", "items": {"type": "string"}},
                    "group_name": {"type": "array", "items": {"type": "string"}},
                    "platform": {"type": "array", "items": {"type": "string"}, "description": "windows, linux, macos, android"},
                    "isolate": {"type": "string", "description": "isolated or unisolated"},
                    "endpoint_status": {"type": "string", "description": "connected, disconnected, lost"},
                    "search_from": {"type": "integer", "default": 0},
                    "search_to": {"type": "integer", "default": 30},
                },
            },
        ),

        types.Tool(
            name="isolate_cortex_endpoint",
            description=(
                "WARNING - MODIFIES DATA: isolates one or more endpoints from the network (only "
                "communication with Cortex XDR remains). Asynchronous action: poll "
                "get_cortex_action_status with the returned action_id. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["endpoint_id_list"],
                "properties": {
                    "endpoint_id_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="unisolate_cortex_endpoint",
            description=(
                "WARNING - MODIFIES DATA: reverts the isolation of one or more endpoints. "
                "Asynchronous action: poll get_cortex_action_status with the returned action_id. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["endpoint_id_list"],
                "properties": {
                    "endpoint_id_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="scan_cortex_endpoint",
            description=(
                "WARNING - MODIFIES DATA: starts a malware scan on one or more endpoints "
                "(or on all of them with scan_all=true). Asynchronous action: poll "
                "get_cortex_action_status with the returned action_id. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "endpoint_id_list": {"type": "array", "items": {"type": "string"}},
                    "scan_all": {"type": "boolean", "default": False},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="get_cortex_action_status",
            description="Returns the per-endpoint status of an asynchronous action (isolate/unisolate/scan/quarantine) by action_id.",
            inputSchema={
                "type": "object",
                "required": ["action_id"],
                "properties": {
                    "action_id": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="quarantine_cortex_file",
            description=(
                "WARNING - MODIFIES DATA: quarantines a specific file (by hash and "
                "path) on one or more endpoints. Reversible with restore_cortex_file. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["endpoint_id_list", "file_path", "file_hash"],
                "properties": {
                    "endpoint_id_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "file_path": {"type": "string"},
                    "file_hash": {"type": "string", "description": "SHA256"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="restore_cortex_file",
            description=(
                "WARNING - MODIFIES DATA: restores from quarantine a file previously "
                "quarantined by quarantine_cortex_file. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["file_hash"],
                "properties": {
                    "file_hash": {"type": "string", "description": "SHA256"},
                    "endpoint_id": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # -- Hash exceptions (Action Center: Allow List/Block List) ------------

        types.Tool(
            name="block_cortex_file_hash",
            description=(
                "WARNING - MODIFIES DATA: adds one or more SHA256 hashes to the global block list "
                "of Cortex XDR - prevents them from executing on any managed endpoint. Use "
                "when a malware hash is identified while investigating an incident (e.g. in "
                "Defender). confirmed=False (default) only shows a preview; confirmed=True "
                "executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["hash_list"],
                "properties": {
                    "hash_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "comment": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="unblock_cortex_file_hash",
            description=(
                "WARNING - MODIFIES DATA: removes one or more SHA256 hashes from the Cortex XDR "
                "block list (they will be able to execute again on managed endpoints). "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["hash_list"],
                "properties": {
                    "hash_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "comment": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="allow_cortex_file_hash",
            description=(
                "WARNING - MODIFIES DATA: adds one or more SHA256 hashes to the global allow list of "
                "Cortex XDR (prevention exception; a wrongly identified hash could allow "
                "a malicious file to run). confirmed=False (default) only shows a "
                "preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["hash_list"],
                "properties": {
                    "hash_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "comment": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="unallow_cortex_file_hash",
            description=(
                "WARNING - MODIFIES DATA: removes one or more SHA256 hashes from the Cortex XDR "
                "allow list (they will be subject to normal prevention rules again). "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["hash_list"],
                "properties": {
                    "hash_list": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                    "comment": {"type": "string"},
                    "incident_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # -- IOC indicators -----------------------------------------------------

        types.Tool(
            name="add_cortex_ioc_indicator",
            description=(
                "WARNING - MODIFIES DATA: creates an IOC indicator (hash, IP, domain or file name) "
                "in Cortex XDR for detection/hunting. IMPORTANT: this does NOT automatically "
                "block the IP/domain at the firewall - IOCs inserted this way are "
                "detection-only. Blocking an IP/domain at the firewall via EDL requires the "
                "manual 'Add to EDL' action in Action Center in the portal; there is no "
                "confirmed REST endpoint to automate that step. By default the 'Source' shown "
                "in the portal is the analyst UPN (MCP_ANALYST_NAME) instead of 'Public "
                "API' - pass an explicit 'source' to use another value. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["indicator", "type"],
                "properties": {
                    "indicator": {"type": "string", "description": "The IOC value: hash, IP or domain"},
                    "type": {"type": "string", "enum": IOC_TYPES},
                    "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"], "default": "informational"},
                    "reputation": {"type": "string", "enum": ["GOOD", "BAD", "SUSPICIOUS", "UNKNOWN"]},
                    "comment": {"type": "string"},
                    "expiration_date": {"type": "integer", "description": "Epoch ms; omit for the type default, or use -1 for 'Never'"},
                    "source": {
                        "type": "string",
                        "description": "Shown as the indicator 'Source' in the Cortex portal. Omit it - it is auto-filled from MCP_ANALYST_NAME (the real analyst on this machine). NEVER use the conversation context's 'userEmail' here (that is the user's general attribution identity, not the analyst UPN).",
                    },
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

    ]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("cortex")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    if name == "get_cortex_incidents":
        request_data: dict = {
            "search_from": arguments.get("search_from", 0),
            "search_to": arguments.get("search_to", 100),
        }
        filters = []
        if arguments.get("incident_id_list"):
            filters.append({"field": "incident_id_list", "operator": "in", "value": arguments["incident_id_list"]})
        if arguments.get("status"):
            filters.append({"field": "status", "operator": "eq", "value": arguments["status"]})
        if arguments.get("creation_time_gte"):
            filters.append({"field": "creation_time", "operator": "gte", "value": arguments["creation_time_gte"]})
        if arguments.get("creation_time_lte"):
            filters.append({"field": "creation_time", "operator": "lte", "value": arguments["creation_time_lte"]})
        if arguments.get("modification_time_gte"):
            filters.append({"field": "modification_time", "operator": "gte", "value": arguments["modification_time_gte"]})
        if arguments.get("modification_time_lte"):
            filters.append({"field": "modification_time", "operator": "lte", "value": arguments["modification_time_lte"]})
        if filters:
            request_data["filters"] = filters
        if arguments.get("sort_by"):
            request_data["sort"] = {"field": arguments["sort_by"], "keyword": arguments.get("sort_order", "desc")}

        data = cortex.call("/incidents/get_incidents/", request_data)
        return ok(data)

    elif name == "get_cortex_incident_details":
        request_data = {
            "incident_id": arguments["incident_id"],
            "alerts_limit": arguments.get("alerts_limit", 1000),
        }
        data = cortex.call("/incidents/get_incident_extra_data/", request_data)
        return ok(data)

    elif name == "update_cortex_incident":
        if arguments.get("unassign_user") and arguments.get("assigned_user_mail"):
            return err(ValueError("unassign_user and assigned_user_mail cannot be passed together"))
        confirmed = arguments.get("confirmed", False)

        update_data: dict = {}
        if arguments.get("unassign_user"):
            update_data["assigned_user_mail"] = "none"
        elif arguments.get("assigned_user_mail"):
            update_data["assigned_user_mail"] = arguments["assigned_user_mail"]
        if arguments.get("status"):
            update_data["status"] = arguments["status"]
        if arguments.get("severity"):
            update_data["manual_severity"] = arguments["severity"]
        if arguments.get("resolve_comment"):
            update_data["resolve_comment"] = arguments["resolve_comment"]
        if arguments.get("add_comment"):
            update_data["comment"] = {"comment_action": "add", "value": arguments["add_comment"]}
        if not update_data:
            return err(ValueError("No change was specified"))

        if not confirmed:
            current = _current_incident(arguments["incident_id"])
            changes = {}
            if "status" in update_data:
                changes["status"] = {"from": current.get("status"), "to": update_data["status"]}
            if "manual_severity" in update_data:
                changes["manual_severity"] = {"from": current.get("manual_severity") or current.get("severity"), "to": update_data["manual_severity"]}
            if "assigned_user_mail" in update_data:
                changes["assigned_user_mail"] = {"from": current.get("assigned_user_mail"), "to": update_data["assigned_user_mail"]}
            if "resolve_comment" in update_data:
                changes["resolve_comment"] = {"from": None, "to": update_data["resolve_comment"]}
            if "comment" in update_data:
                changes["comment"] = {"from": None, "to": update_data["comment"]["value"]}
            return _preview(
                "update_cortex_incident",
                {"incident_id": arguments["incident_id"]},
                f"Incident {arguments['incident_id']} will be updated with the indicated changes.",
                changes=changes,
            )

        request_data = {"incident_id": arguments["incident_id"], "update_data": update_data}
        data = cortex.call("/incidents/update_incident/", request_data)
        return _executed("update_cortex_incident", data)

    elif name == "get_cortex_alerts":
        request_data: dict = {
            "search_from": arguments.get("search_from", 0),
            "search_to": arguments.get("search_to", 100),
        }
        filters = []
        if arguments.get("alert_id_list"):
            filters.append({"field": "alert_id_list", "operator": "in", "value": [int(a) for a in arguments["alert_id_list"]]})
        if arguments.get("alert_source"):
            filters.append({"field": "alert_source", "operator": "in", "value": arguments["alert_source"]})
        if arguments.get("severity"):
            filters.append({"field": "severity", "operator": "in", "value": arguments["severity"]})
        if arguments.get("creation_time_gte"):
            filters.append({"field": "creation_time", "operator": "gte", "value": arguments["creation_time_gte"]})
        if arguments.get("creation_time_lte"):
            filters.append({"field": "creation_time", "operator": "lte", "value": arguments["creation_time_lte"]})
        if filters:
            request_data["filters"] = filters

        data = cortex.call("/alerts/get_alerts", request_data)
        return ok(data)

    elif name == "update_cortex_alerts":
        confirmed = arguments.get("confirmed", False)
        alert_id_list = [int(a) for a in arguments["alert_id_list"]]
        update_data: dict = {}
        if arguments.get("severity"):
            update_data["severity"] = arguments["severity"]
        if arguments.get("status"):
            update_data["status"] = arguments["status"]
        if arguments.get("comment"):
            update_data["comment"] = arguments["comment"]
        if not update_data:
            return err(ValueError("No change was specified"))

        if not confirmed:
            current = _current_alerts(alert_id_list)
            return _preview(
                "update_cortex_alerts",
                {"alert_id_list": alert_id_list},
                "The indicated alerts will be updated with the specified changes. NOTE: the exact "
                "shape of this endpoint is not confirmed - see module docstring.",
                changes=update_data,
                current_alerts=[
                    {"alert_id": a.get("alert_id"), "severity": a.get("severity"), "status": a.get("status")}
                    for a in current
                ],
            )

        request_data = {"alert_id_list": alert_id_list, "update_data": update_data}
        data = cortex.call("/alerts/update_alerts", request_data)
        return _executed("update_cortex_alerts", data)

    elif name == "get_cortex_endpoints":
        request_data: dict = {
            "search_from": arguments.get("search_from", 0),
            "search_to": arguments.get("search_to", 30),
        }
        filters = []
        if arguments.get("endpoint_id_list"):
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": arguments["endpoint_id_list"]})
        if arguments.get("hostname"):
            filters.append({"field": "hostname", "operator": "in", "value": arguments["hostname"]})
        if arguments.get("ip_list"):
            filters.append({"field": "ip_list", "operator": "in", "value": arguments["ip_list"]})
        if arguments.get("group_name"):
            filters.append({"field": "group_name", "operator": "in", "value": arguments["group_name"]})
        if arguments.get("platform"):
            filters.append({"field": "platform", "operator": "in", "value": arguments["platform"]})
        if arguments.get("isolate"):
            filters.append({"field": "isolate", "operator": "in", "value": [arguments["isolate"]]})
        if arguments.get("endpoint_status"):
            filters.append({"field": "endpoint_status", "operator": "eq", "value": arguments["endpoint_status"]})
        if filters:
            request_data["filters"] = filters

        data = cortex.call("/endpoints/get_endpoint/", request_data)
        return ok(data)

    elif name == "isolate_cortex_endpoint":
        confirmed = arguments.get("confirmed", False)
        endpoint_ids = arguments["endpoint_id_list"]

        if not confirmed:
            current = _current_endpoints(endpoint_ids)
            return _preview(
                "isolate_cortex_endpoint",
                {
                    "endpoint_id_list": endpoint_ids,
                    "endpoints": [
                        {"endpoint_id": e.get("endpoint_id"), "endpoint_name": e.get("endpoint_name"), "is_isolated": e.get("is_isolated")}
                        for e in current
                    ],
                },
                "This action will cut ALL network connectivity of the indicated endpoints (only "
                "communication with Cortex XDR remains). It is asynchronous: use "
                "get_cortex_action_status with the returned action_id to confirm completion.",
            )

        request_data = _endpoint_target(endpoint_ids, arguments.get("incident_id"))
        data = cortex.call("/endpoints/isolate", request_data)
        return _executed("isolate_cortex_endpoint", data)

    elif name == "unisolate_cortex_endpoint":
        confirmed = arguments.get("confirmed", False)
        endpoint_ids = arguments["endpoint_id_list"]

        if not confirmed:
            current = _current_endpoints(endpoint_ids)
            return _preview(
                "unisolate_cortex_endpoint",
                {
                    "endpoint_id_list": endpoint_ids,
                    "endpoints": [
                        {"endpoint_id": e.get("endpoint_id"), "endpoint_name": e.get("endpoint_name"), "is_isolated": e.get("is_isolated")}
                        for e in current
                    ],
                },
                "Normal network connectivity of the indicated endpoints will be restored. It is "
                "asynchronous: use get_cortex_action_status with the returned action_id to "
                "confirm completion.",
            )

        request_data = _endpoint_target(endpoint_ids, arguments.get("incident_id"))
        data = cortex.call("/endpoints/unisolate", request_data)
        return _executed("unisolate_cortex_endpoint", data)

    elif name == "scan_cortex_endpoint":
        confirmed = arguments.get("confirmed", False)
        if not arguments.get("scan_all") and not arguments.get("endpoint_id_list"):
            return err(ValueError("endpoint_id_list or scan_all=true is required"))

        if not confirmed:
            target = {"scan_all": True} if arguments.get("scan_all") else {"endpoint_id_list": arguments["endpoint_id_list"]}
            return _preview(
                "scan_cortex_endpoint",
                target,
                "A malware scan will be started on the indicated endpoints. It is asynchronous: use "
                "get_cortex_action_status with the returned action_id to confirm completion.",
            )

        request_data: dict = {}
        if arguments.get("scan_all"):
            request_data["filters"] = "all"
        else:
            request_data["filters"] = [
                {"field": "endpoint_id_list", "operator": "in", "value": arguments["endpoint_id_list"]}
            ]
        if arguments.get("incident_id"):
            request_data["incident_id"] = arguments["incident_id"]

        data = cortex.call("/endpoints/scan/", request_data)
        return _executed("scan_cortex_endpoint", data)

    elif name == "get_cortex_action_status":
        data = cortex.call("/actions/get_action_status/", {"group_action_id": arguments["action_id"]})
        return ok(data)

    elif name == "quarantine_cortex_file":
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            return _preview(
                "quarantine_cortex_file",
                {
                    "endpoint_id_list": arguments["endpoint_id_list"],
                    "file_path": arguments["file_path"],
                    "file_hash": arguments["file_hash"],
                },
                "The file will be moved to quarantine on the indicated endpoints. Reversible with "
                "restore_cortex_file.",
            )

        request_data = {
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": arguments["endpoint_id_list"]}],
            "file_path": arguments["file_path"],
            "file_hash": arguments["file_hash"],
        }
        if arguments.get("incident_id"):
            request_data["incident_id"] = arguments["incident_id"]
        data = cortex.call("/endpoints/quarantine/", request_data)
        return _executed("quarantine_cortex_file", data)

    elif name == "restore_cortex_file":
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            return _preview(
                "restore_cortex_file",
                {"file_hash": arguments["file_hash"], "endpoint_id": arguments.get("endpoint_id")},
                "The file will be restored from quarantine.",
            )

        request_data = {"file_hash": arguments["file_hash"]}
        if arguments.get("endpoint_id"):
            request_data["endpoint_id"] = arguments["endpoint_id"]
        if arguments.get("incident_id"):
            request_data["incident_id"] = arguments["incident_id"]
        data = cortex.call("/endpoints/restore/", request_data)
        return _executed("restore_cortex_file", data)

    elif name in ("block_cortex_file_hash", "unblock_cortex_file_hash", "allow_cortex_file_hash", "unallow_cortex_file_hash"):
        confirmed = arguments.get("confirmed", False)
        hash_list = arguments["hash_list"]

        path, what = {
            "block_cortex_file_hash": (
                "/hash_exceptions/blocklist/",
                "Will be added to the global Cortex XDR BLOCK LIST - they will not be able to run on "
                "any managed endpoint.",
            ),
            "unblock_cortex_file_hash": (
                "/hash_exceptions/blocklist/remove/",
                "Will be removed from the block list - they will be able to run again on managed "
                "endpoints.",
            ),
            "allow_cortex_file_hash": (
                "/hash_exceptions/allowlist/",
                "Will be added to the global Cortex XDR ALLOW LIST (prevention exception).",
            ),
            "unallow_cortex_file_hash": (
                "/hash_exceptions/allowlist/remove/",
                "Will be removed from the allow list - they will be subject to normal prevention "
                "rules again.",
            ),
        }[name]

        if not confirmed:
            return _preview(name, {"hash_list": hash_list}, what)

        request_data: dict = {"hash_list": hash_list}
        if arguments.get("comment"):
            request_data["comment"] = arguments["comment"]
        if arguments.get("incident_id"):
            request_data["incident_id"] = arguments["incident_id"]
        data = cortex.call(path, request_data)
        return _executed(name, data)

    elif name == "add_cortex_ioc_indicator":
        confirmed = arguments.get("confirmed", False)
        indicator = {
            "indicator": arguments["indicator"],
            "type": arguments["type"],
            "severity": IOC_SEVERITY_MAP[arguments.get("severity", "informational")],
        }
        if arguments.get("reputation"):
            indicator["reputation"] = arguments["reputation"]
        if arguments.get("comment"):
            indicator["comment"] = arguments["comment"]
        if "expiration_date" in arguments:
            indicator["expiration_date"] = arguments["expiration_date"]

        # Without this, Cortex shows "Public API" as the indicator Source in the portal.
        # vendors[].vendor_name can override it with the analyst UPN, the same way
        # assigned_to is auto-filled from MCP_ANALYST_NAME in the other domains.
        source = arguments.get("source") or get_analyst_upn()
        vendor_entry = {"vendor_name": source}
        if indicator.get("reputation"):
            vendor_entry["reputation"] = indicator["reputation"]
        indicator["vendors"] = [vendor_entry]

        if not confirmed:
            return _preview(
                "add_cortex_ioc_indicator",
                indicator,
                "A DETECTION indicator will be created in Cortex XDR - it does NOT automatically "
                "block via EDL (see the limitation documented in this tool's description).",
            )

        data = cortex.call_raw("/indicators/insert_jsons/", {"request_data": [indicator]})
        return _executed("add_cortex_ioc_indicator", data)

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
