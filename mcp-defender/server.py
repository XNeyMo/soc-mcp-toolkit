"""
MCP Server - Microsoft 365 Defender (XDR)

Scope: investigation and response through Defender ONLY - Advanced Hunting,
Incidents, Alerts, Devices, Files, IPs, URLs, Users (as seen by MDE) and IOC
Indicators. It does not manage identities (Entra), mailboxes (Exchange) or
compliance/audit: those domains live in their own sibling servers
(mcp-identity, mcp-exchange, mcp-intune, mcp-audit) in this repository.

It talks to two APIs that share the same HTTP host (https://api.security.microsoft.com)
but are two distinct *resources/audiences* in Entra - each one needs its own
token even though the destination URL is the same:
  - Microsoft Threat Protection (scope https://api.security.microsoft.com/.default):
    hunting, incidents - permissions AdvancedHunting.Read.All, Incident.ReadWrite.All.
  - WindowsDefenderATP / MDE (scope https://api.securitycenter.microsoft.com/.default -
    the "legacy" resource, NOT the same as the host): devices, files, IPs, URLs,
    users (MDE view), IOC indicators - permissions Machine.*, File.Read.All, Ip.Read.All,
    Url.Read.All, User.Read.All, Ti.ReadWrite.All, AdvancedQuery.Read.All.
  Requesting a token with the wrong scope returns 403 "Missing application roles" even
  when the permission is granted in Entra, because it belongs to the other resource.
  Ref: https://learn.microsoft.com/defender-endpoint/api/apis-intro
  - Microsoft Graph (scope https://graph.microsoft.com/.default, host graph.microsoft.com):
    'resolvingComment' in update_incident (permission SecurityIncident.ReadWrite.All) and the
    WHOLE Alerts section - get_security_alerts/update_alert use /security/alerts_v2
    (permission SecurityAlert.ReadWrite.All) instead of the classic MDE /alerts API, because
    the latter ONLY knows native Defender for Endpoint alerts: alerts from other products
    (Cloud Apps, Office 365, Identity, Sentinel...) return 404 regardless of the ID format,
    since they do not exist in that store. alerts_v2 is the unified view across all products
    and uses the SAME id that get_incident_details already returns.
    Each of these Graph permissions has its own admin consent - they are separate resources
    from each other and from the two above.

Requires: pip install -r requirements.txt
Environment variables:
  AZURE_TENANT_ID        (shared across all mcp-* servers)
  DEFENDER_CLIENT_ID     (dedicated Defender app registration, e.g. api-mcp-defender)
  DEFENDER_CLIENT_SECRET (the analyst's individual secret within that app)
  MCP_ANALYST_NAME       (optional; analyst name/UPN used for the audit log and default assignment)
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.auth import get_token, load_domain_credentials
from shared.mtp_client import MtpClient
from shared.graph_client import GraphClient
from shared.mcp_common import ok, audited, require_vault
from shared.audit_log import get_analyst_upn

TENANT_ID, CLIENT_ID, CLIENT_SECRET = load_domain_credentials("DEFENDER")

# Microsoft Threat Protection: hunting (A) + incidents (B).
mtp = MtpClient(
    lambda: get_token(
        TENANT_ID, CLIENT_ID, CLIENT_SECRET,
        scope="https://api.security.microsoft.com/.default",
    )
)

# WindowsDefenderATP / MDE: devices (D-E), files (F), IPs (G), URLs (H),
# users MDE view (I), IOC indicators (J). Same host, different token
# (see module docstring) - using 'mtp' here produces 403 even though the permission
# is granted in Entra.
mde = MtpClient(
    lambda: get_token(
        TENANT_ID, CLIENT_ID, CLIENT_SECRET,
        scope="https://api.securitycenter.microsoft.com/.default",
    )
)

# Microsoft Graph Security API: used for 'resolvingComment' (the portal's "Explain
# why you resolved this incident" box), which does not exist in the classic API above,
# and for the alerts section (/security/alerts_v2).
# Requires additional application permissions: SecurityIncident.ReadWrite.All and
# SecurityAlert.ReadWrite.All (Microsoft Graph).
graph = GraphClient(
    lambda: get_token(
        TENANT_ID, CLIENT_ID, CLIENT_SECRET,
        scope="https://graph.microsoft.com/.default",
    )
)

server = Server("mcp-defender")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _kql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_enum(value, allowed: list, field_name: str) -> None:
    if value is not None and value not in allowed:
        raise ValueError(
            f"'{value}' is not valid for {field_name}. Allowed values: {allowed}"
        )


def _require_at_least_one(arguments: dict, fields: list) -> None:
    if not any(arguments.get(f) for f in fields):
        raise ValueError(f"At least one of the following is required: {', '.join(fields)}")


INCIDENT_CLASSIFICATIONS = ["unknown", "falsePositive", "truePositive", "informationalExpectedActivity"]

# Valid 'determination' values for incidents, grouped by classification
# (reference: https://learn.microsoft.com/defender-xdr/api-update-incidents).
# 'apt' and 'securityPersonnel' have been deprecated since 2022 and are no longer accepted.
INCIDENT_DETERMINATIONS_BY_CLASSIFICATION = {
    "unknown": ["notAvailable"],
    "truePositive": ["multiStagedAttack", "maliciousUserActivity", "malware", "phishing", "compromisedAccount", "unwantedSoftware", "other"],
    "informationalExpectedActivity": ["securityTesting", "lineOfBusinessApplication", "confirmedActivity", "other"],
    "falsePositive": ["notMalicious", "noEnoughDataToValidate", "other"],
}
INCIDENT_DETERMINATIONS = sorted({v for vs in INCIDENT_DETERMINATIONS_BY_CLASSIFICATION.values() for v in vs})

# update_alert uses Microsoft Graph (/security/alerts_v2), not the classic MDE API - its
# 'determination' enum matches the incident one except for a different name for
# false positive with insufficient evidence. Reference:
# https://learn.microsoft.com/graph/api/resources/security-alert
ALERT_DETERMINATIONS_BY_CLASSIFICATION = {
    "unknown": ["notAvailable"],
    "truePositive": ["multiStagedAttack", "maliciousUserActivity", "malware", "phishing", "compromisedAccount", "unwantedSoftware", "other"],
    "informationalExpectedActivity": ["securityTesting", "lineOfBusinessApplication", "confirmedActivity", "other"],
    "falsePositive": ["notMalicious", "notEnoughDataToValidate", "other"],
}
ALERT_DETERMINATIONS = sorted({v for vs in ALERT_DETERMINATIONS_BY_CLASSIFICATION.values() for v in vs})

MAX_HUNT_ROWS = 500


def _cap_hunt_results(results: list) -> dict:
    """Safety cap on what is returned to the MCP client - the query already
    ran in full server-side; this only prevents blowing the conversation's token
    limit with thousands of raw rows."""
    total = len(results)
    if total <= MAX_HUNT_ROWS:
        return {"results": results, "count": total}
    return {
        "results": results[:MAX_HUNT_ROWS],
        "count": MAX_HUNT_ROWS,
        "total_found": total,
        "_warning": (
            f"Truncated to the first {MAX_HUNT_ROWS} of {total} rows to avoid exceeding the conversation "
            "limit. Add more filters, reduce days_back, or use '| summarize'/'| limit' in the query "
            "to control the result size."
        ),
    }


def _hunt(query: str) -> dict:
    data = mtp.post("/advancedhunting/run", {"Query": query})
    results = data.get("Results", [])
    return _cap_hunt_results(results)


def _preview(action: str, target: dict, what_would_happen: str, **extra):
    payload = {
        "mode": "PREVIEW — action NOT executed",
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


MAX_PAGED_ITEMS = 2000


def _get_all_pages(path: str, params: dict = None, client=None) -> dict:
    """Follows @odata.nextLink until results are exhausted or MAX_PAGED_ITEMS is reached.
    Returns {"items": [...], "truncated": bool} - truncated=True indicates that
    there may be more results that were not fetched, so a count is never
    silently incomplete."""
    client = client or mtp
    items = []
    next_url = None
    truncated = False
    while True:
        data = client.get(next_url) if next_url else client.get(path, params)
        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
        if len(items) >= MAX_PAGED_ITEMS:
            truncated = bool(next_url)
            items = items[:MAX_PAGED_ITEMS]
            break
        if not next_url:
            break
    return {"items": items, "truncated": truncated}


def _resolve_user_id(arguments: dict) -> str:
    user_id = arguments.get("user_id")
    user_upn = arguments.get("user_upn")
    if not user_id and not user_upn:
        raise ValueError("At least one of the following is required: user_id, user_upn")
    if user_id:
        return user_id
    if "@" not in user_upn:
        raise ValueError(f"Invalid user_upn: '{user_upn}' - expected format user@domain.com")
    username, domain = user_upn.split("@", 1)
    return f"{domain};{username}"


INDICATOR_TYPES = ["FileSha256", "FileSha1", "IpAddress", "Url", "DomainName"]
INDICATOR_ACTIONS = ["Alert", "AlertAndBlock", "Allowed"]
INDICATOR_SEVERITIES = ["Informational", "Low", "Medium", "High"]


# ---------------------------------------------------------------------------
# K1 - Hunting query library (no API calls)
# ---------------------------------------------------------------------------

HUNTING_QUERY_LIBRARY = [
    {
        "name": "Phishing - delivered executable attachments",
        "description": "Detects delivered (not blocked) emails with executable/script attachment types.",
        "mitre_tactic": "InitialAccess",
        "mitre_technique": "T1566",
        "tables": ["EmailAttachmentInfo", "EmailEvents"],
        "query": """let attachments = EmailAttachmentInfo
| where FileType in ("exe","dll","js","vbs","ps1","bat","cmd","hta","lnk")
| project NetworkMessageId, FileName, FileType;
EmailEvents
| where DeliveryAction == "Delivered"
| join kind=inner attachments on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType, DeliveryAction
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Phishing - delivered URLs that were not blocked",
        "description": "Detects delivered emails containing URLs; useful for reviewing link-based phishing that passed the filters.",
        "mitre_tactic": "InitialAccess",
        "mitre_technique": "T1566",
        "tables": ["EmailUrlInfo", "EmailEvents"],
        "query": """let urls = EmailUrlInfo
| project NetworkMessageId, Url, UrlDomain;
EmailEvents
| where DeliveryAction == "Delivered"
| join kind=inner urls on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "PowerShell with encoded command (Base64)",
        "description": "Detects PowerShell executions with Base64-encoded commands, a common technique for obfuscating payloads.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","-ec ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Certutil como downloader (LOLBin)",
        "description": "Detects use of certutil.exe to download or decode files, a living-off-the-land binary common in malware.",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache","decode","-f ","http")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Scheduled task created by non-system process",
        "description": "Detects scheduled task creation by accounts other than SYSTEM/LOCAL SERVICE, a possible persistence mechanism.",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where InitiatingProcessAccountName !in ("SYSTEM","LOCAL SERVICE")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Run key modified (autostart registry)",
        "description": "Detects writes/creation of values in the CurrentVersion\\Run registry keys, a classic autostart mechanism.",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547",
        "tables": ["DeviceRegistryEvents"],
        "query": """DeviceRegistryEvents
| where RegistryKey has "CurrentVersion\\\\Run"
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Token impersonation - handle to privileged process",
        "description": "Detects handle opens to processes with SeImpersonatePrivilege, a technique used for privilege escalation (e.g. RoguePotato/JuicyPotato).",
        "mitre_tactic": "PrivilegeEscalation",
        "mitre_technique": "T1134",
        "tables": ["DeviceEvents"],
        "query": """DeviceEvents
| where ActionType == "OpenProcess"
| where AdditionalFields has "SeImpersonatePrivilege"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, AdditionalFields
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Service created by non-system process",
        "description": "Detects Windows service creation by accounts other than SYSTEM, a possible persistence/escalation mechanism.",
        "mitre_tactic": "PrivilegeEscalation",
        "mitre_technique": "T1543",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| where InitiatingProcessAccountName !~ "SYSTEM"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "LSASS access (possible Mimikatz)",
        "description": "Detects handle opens to lsass.exe by processes other than the Defender engine itself, an indicator of credential dumping.",
        "mitre_tactic": "CredentialAccess",
        "mitre_technique": "T1003",
        "tables": ["DeviceEvents"],
        "query": """DeviceEvents
| where ActionType == "OpenProcess"
| where FileName == "lsass.exe"
| where ProcessCommandLine !has "MsMpEng"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Password spray - many logon failures from the same IP",
        "description": "Detects IPs with many failed logon attempts against multiple accounts in short time windows, a password spray pattern.",
        "mitre_tactic": "CredentialAccess",
        "mitre_technique": "T1110",
        "tables": ["IdentityLogonEvents"],
        "query": """IdentityLogonEvents
| where ActionType == "LogonFailed"
| summarize FailCount=count(), Accounts=dcount(AccountUpn) by IPAddress, bin(Timestamp, 5m)
| where FailCount > 20 and Accounts > 5
| order by FailCount desc
| limit 500""",
    },
    {
        "name": "PsExec or lateral SMB (ADMIN$ share access)",
        "description": "Detects connections to port 445 initiated by non-standard processes, an indicator of lateral movement via SMB/PsExec.",
        "mitre_tactic": "LateralMovement",
        "mitre_technique": "T1021",
        "tables": ["DeviceNetworkEvents"],
        "query": """DeviceNetworkEvents
| where RemotePort == 445
| where InitiatingProcessFileName !in~ ("System","svchost.exe")
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "WMI remote execution",
        "description": "Detects child processes launched by WmiPrvSE.exe, an indicator of remote execution via WMI.",
        "mitre_tactic": "LateralMovement",
        "mitre_technique": "T1047",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ ("WmiPrvSE.exe","scrcons.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Unusual outbound data volume per endpoint",
        "description": "Detects devices that sent an unusually high volume of data within a one-hour window, possible exfiltration.",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "tables": ["DeviceNetworkEvents"],
        "query": """DeviceNetworkEvents
| summarize TotalBytes=sum(BytesSent) by DeviceName, bin(Timestamp, 1h)
| where TotalBytes > 100000000
| order by TotalBytes desc
| limit 500""",
    },
    {
        "name": "Upload to cloud storage services",
        "description": "Detects significant-volume uploads to cloud storage services frequently used for exfiltration.",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1567",
        "tables": ["DeviceNetworkEvents"],
        "query": """DeviceNetworkEvents
| where RemoteUrl has_any ("mega.nz","dropbox.com","wetransfer.com","gofile.io","anonfiles.com","transfer.sh")
| where BytesSent > 1000000
| project Timestamp, DeviceName, RemoteUrl, BytesSent, InitiatingProcessFileName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Beaconing - regular connections to the same external IP",
        "description": "Detects regular connection patterns (low variance over time) toward an external IP, an indicator of C2 beaconing.",
        "mitre_tactic": "CommandAndControl",
        "mitre_technique": "T1071",
        "tables": ["DeviceNetworkEvents"],
        "query": """DeviceNetworkEvents
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| summarize Count=count(), StdDev=stdev(toreal(Timestamp)) by DeviceName, RemoteIP, bin(Timestamp, 24h)
| where Count > 20 and StdDev < 60
| order by Count desc
| limit 500""",
    },
    {
        "name": "Connections to non-standard ports",
        "description": "Detects successful outbound connections to uncommon ports, possible C2 traffic on non-standard ports.",
        "mitre_tactic": "CommandAndControl",
        "mitre_technique": "T1571",
        "tables": ["DeviceNetworkEvents"],
        "query": """DeviceNetworkEvents
| where RemotePort !in (80, 443, 53, 8080, 8443)
| where ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10."
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Shadow copy deletion (ransomware precursor)",
        "description": "Detects typical commands that delete shadow copies or disable recovery, a common ransomware precursor.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1490",
        "tables": ["DeviceProcessEvents"],
        "query": """DeviceProcessEvents
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled no")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
| limit 500""",
    },
    {
        "name": "Mass file encryption",
        "description": "Detects processes that create/modify a large number of files within a few minutes, a mass-encryption pattern typical of ransomware.",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "tables": ["DeviceFileEvents"],
        "query": """DeviceFileEvents
| where ActionType in ("FileCreated","FileModified")
| summarize FileCount=count() by InitiatingProcessFileName, DeviceName, bin(Timestamp, 5m)
| where FileCount > 100
| order by FileCount desc
| limit 500""",
    },
]


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools():
    return [

        # ── A. HUNTING (AdvancedHunting.Read.All) ───────────────────────────

        types.Tool(
            name="hunt_emails_by_subject",
            description=(
                "Searches emails by subject using KQL in Microsoft 365 Defender. "
                "Returns: first seen, last seen, unique senders, delivered vs blocked counts, "
                "origin domains and recipient list. Ideal for establishing the scope of a phishing campaign."
            ),
            inputSchema={
                "type": "object",
                "required": ["subject_pattern"],
                "properties": {
                    "subject_pattern": {"type": "string", "description": "Text to search for in the subject (partial match). E.g. 'Verify your identity'"},
                    "days_back": {"type": "integer", "default": 30, "description": "How many days back to search (max 30 in Advanced Hunting)"},
                },
            },
        ),

        types.Tool(
            name="hunt_emails_by_sender",
            description=(
                "Searches all emails sent from a specific address or domain. "
                "Returns recipients, dates, subjects, delivery action and whether they were blocked."
            ),
            inputSchema={
                "type": "object",
                "required": ["sender"],
                "properties": {
                    "sender": {"type": "string", "description": "Full email address or domain (@domain.com)"},
                    "days_back": {"type": "integer", "default": 30},
                },
            },
        ),

        types.Tool(
            name="trace_email_delivery",
            description=(
                "Traces the delivery of a specific email: why it arrived, whether it was blocked, "
                "which folder it landed in, and whether it was moved by a rule. "
                "Uses KQL EmailEvents + EmailPostDeliveryEvents for full traceability. "
                "Requires at least one of: sender_email, recipient_email, subject_contains."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "sender_email": {"type": "string"},
                    "recipient_email": {"type": "string"},
                    "subject_contains": {"type": "string"},
                    "days_back": {"type": "integer", "default": 7},
                },
            },
        ),

        types.Tool(
            name="run_kql_hunting",
            description=(
                "Runs a KQL query in Microsoft 365 Defender Advanced Hunting. "
                "Available tables: EmailEvents, EmailUrlInfo, EmailAttachmentInfo, "
                "EmailPostDeliveryEvents, DeviceEvents, DeviceProcessEvents, "
                "DeviceNetworkEvents, DeviceLogonEvents, DeviceFileEvents, DeviceRegistryEvents, "
                "IdentityLogonEvents, IdentityQueryEvents, CloudAppEvents. "
                "Maximum 30 days of retention. Read-only."
            ),
            inputSchema={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "Valid KQL query for Advanced Hunting"},
                },
            },
        ),

        types.Tool(
            name="hunt_emails_by_url",
            description="Searches delivered emails that contain a URL matching the given pattern.",
            inputSchema={
                "type": "object",
                "required": ["url_pattern"],
                "properties": {
                    "url_pattern": {"type": "string", "description": "Text to search for in the URL (partial match)"},
                    "days_back": {"type": "integer", "default": 30},
                },
            },
        ),

        types.Tool(
            name="hunt_emails_by_attachment_hash",
            description="Searches emails carrying an attachment with a specific SHA256 hash.",
            inputSchema={
                "type": "object",
                "required": ["sha256"],
                "properties": {
                    "sha256": {"type": "string"},
                    "days_back": {"type": "integer", "default": 30},
                },
            },
        ),

        types.Tool(
            name="hunt_device_process_events",
            description=(
                "Searches process creation events on devices. "
                "Requires at least one of: device_name, process_name, command_line_contains, sha256."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "device_name": {"type": "string"},
                    "process_name": {"type": "string"},
                    "command_line_contains": {"type": "string"},
                    "sha256": {"type": "string"},
                    "days_back": {"type": "integer", "default": 7},
                },
            },
        ),

        types.Tool(
            name="hunt_device_network_events",
            description=(
                "Searches network events on devices. "
                "Requires at least one of: device_name, remote_ip, remote_url, remote_port."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "device_name": {"type": "string"},
                    "remote_ip": {"type": "string"},
                    "remote_url": {"type": "string"},
                    "remote_port": {"type": "integer"},
                    "days_back": {"type": "integer", "default": 7},
                },
            },
        ),

        types.Tool(
            name="hunt_identity_logon_events",
            description=(
                "Searches identity logon events (Entra/AD via Defender for Identity). "
                "Requires at least one of: account_upn, src_ip."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "account_upn": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "failed_only": {"type": "boolean", "default": False},
                    "days_back": {"type": "integer", "default": 14},
                },
            },
        ),

        types.Tool(
            name="hunt_cloud_app_events",
            description=(
                "Searches cloud application events (Cloud App Security). "
                "Requires at least one of: account_upn, app_name, action_type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "account_upn": {"type": "string", "description": "Compared against AccountDisplayName (UPN or display name, depending on the connector)"},
                    "app_name": {"type": "string"},
                    "action_type": {"type": "string"},
                    "days_back": {"type": "integer", "default": 14},
                },
            },
        ),

        # ── B. INCIDENTS (Incident.ReadWrite.All) ──────────────────────────

        types.Tool(
            name="get_security_incidents",
            description=(
                "Microsoft 365 Defender incidents with their grouped alerts, "
                "affected users, involved devices and detected tactics. "
                "By default returns up to 'top' incidents from a single page. Use fetch_all=True "
                "to retrieve ALL of them (paginates automatically, max 2000) - "
                "needed for exact counts, e.g. 'how many active incidents are there?'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["active", "resolved", "inProgress"]},
                    "top": {"type": "integer", "default": 10},
                    "fetch_all": {"type": "boolean", "default": False, "description": "Ignores 'top' and paginates until all results are retrieved (max 2000)."},
                },
            },
        ),

        types.Tool(
            name="get_incident_details",
            description="Details of an incident, including its associated alerts.",
            inputSchema={
                "type": "object",
                "required": ["incident_id"],
                "properties": {"incident_id": {"type": "string"}},
            },
        ),

        types.Tool(
            name="update_incident",
            description=(
                "⚠️ Updates status/classification/determination/assignment/tags of an incident and optionally "
                "adds comments. confirmed=False (default) only shows a preview of the changes; "
                "confirmed=True applies them.\n"
                "- assigned_to: if omitted, it is auto-filled with the UPN of the locally configured analyst "
                "(MCP_ANALYST_NAME) - so the incident is always assigned to whoever is handling it.\n"
                "- tags: call list_incident_tags first to see the tags already existing in the tenant and reuse them; "
                "only create a new one if none of the existing ones apply. More than one can be sent.\n"
                "- resolving_comment: fills the portal's \"Explain why you resolved this incident\" box (via "
                "Microsoft Graph, requires SecurityIncident.ReadWrite.All). It MUST be a SINGLE-PARAGRAPH summary "
                "(no blank lines) - extended detail goes in 'comment' and in 'alert_comments'.\n"
                "- alert_comments: a specific comment for EACH alert of the incident (use get_incident_details "
                "to see the alertIds). They can be more detailed than resolving_comment - one per cause/evidence. "
                "They are added via Microsoft Graph (SecurityAlert.ReadWrite.All), separately from the alert's "
                "classification/determination (which does cascade automatically from the incident).\n"
                "- When setting status='resolved' you MUST also send: classification, determination, at "
                "least 1 tag, comment, resolving_comment, and one alert_comments entry for EACH alert of the "
                "incident - an incident cannot be closed leaving any alert without its own comment."
            ),
            inputSchema={
                "type": "object",
                "required": ["incident_id"],
                "properties": {
                    "incident_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["active", "resolved", "inProgress"]},
                    "classification": {"type": "string", "enum": INCIDENT_CLASSIFICATIONS},
                    "determination": {"type": "string", "enum": INCIDENT_DETERMINATIONS, "description": f"Must match the chosen classification: {INCIDENT_DETERMINATIONS_BY_CLASSIFICATION}"},
                    "assigned_to": {"type": "string", "description": "UPN of the assigned analyst - rarely needs to be passed: omit it so it is auto-filled with MCP_ANALYST_NAME (the real analyst on this machine). Pass it explicitly ONLY to reassign to an analyst other than the one handling the incident. NEVER use the conversation context's 'userEmail' here (that is the user's identity for general attribution, not necessarily the Defender analyst's UPN)."},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "One or more incident tags. Call list_incident_tags before creating a new one."},
                    "comment": {"type": "string", "description": "General note explaining the investigation/resolution of the incident."},
                    "resolving_comment": {"type": "string", "description": "SINGLE-PARAGRAPH summary for the portal's 'Explain why you resolved this incident' box. Requires the SecurityIncident.ReadWrite.All permission (Graph)."},
                    "alert_comments": {
                        "type": "array",
                        "description": "One comment per alert of the incident. Mandatory (covering ALL alerts) when resolving.",
                        "items": {
                            "type": "object",
                            "required": ["alert_id", "comment"],
                            "properties": {
                                "alert_id": {"type": "string", "description": "The 'alertId' as returned by get_incident_details."},
                                "comment": {"type": "string", "description": "Specific explanation for this alert - may be detailed."},
                            },
                        },
                    },
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="add_incident_comment",
            description="Adds a comment to an incident. Does not require confirmation (non-destructive).",
            inputSchema={
                "type": "object",
                "required": ["incident_id", "comment"],
                "properties": {
                    "incident_id": {"type": "string"},
                    "comment": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="list_incident_tags",
            description=(
                "Lists the tags already used in the tenant's incidents (the Defender API has no separate tag "
                "catalog, so they are aggregated from existing incidents). Use it BEFORE setting a new tag "
                "in update_incident, to reuse an existing one instead of duplicating it under another name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "sample_size": {"type": "integer", "default": 500, "description": "How many recent incidents to scan when collecting tags (max 2000)."},
                },
            },
        ),

        # ── C. ALERTS (Microsoft Graph: SecurityAlert.ReadWrite.All) ───────

        types.Tool(
            name="get_security_alerts",
            description=(
                "Microsoft 365 Defender alerts via Microsoft Graph (/security/alerts_v2) - covers ALL "
                "products (Defender for Endpoint, Cloud Apps, Office 365, Identity, Sentinel...), not just endpoint. "
                "Filter by severity, status or source. Includes MITRE ATT&CK tactics. "
                "By default returns up to 'top' alerts from a single page. Use fetch_all=True "
                "to retrieve ALL of them (paginates automatically, max 2000) - "
                "needed for exact counts.\n"
                "- user_email: Graph does not support filtering alerts by user server-side, so this fetches "
                "alerts (honoring the other filters) and locally discards those whose evidence does not mention "
                "that UPN/email - it can be slower with fetch_all=True in large tenants."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["high", "medium", "low", "informational"]},
                    "status": {"type": "string", "enum": ["new", "inProgress", "resolved"]},
                    "user_email": {"type": "string", "description": "Filter (locally, after fetching results) alerts whose evidence mentions this user"},
                    "top": {"type": "integer", "default": 25},
                    "fetch_all": {"type": "boolean", "default": False, "description": "Ignores 'top' and paginates until all results are retrieved (max 2000)."},
                },
            },
        ),

        types.Tool(
            name="update_alert",
            description=(
                "⚠️ Updates status/classification/determination/assignment of an alert (via Microsoft Graph "
                "/security/alerts_v2 - works for alerts from ANY product, not just Defender for Endpoint) "
                "and adds a comment explaining the closure - Defender uses the classification+determination+comment "
                "of resolved alerts to tune future detection, so it should always be recorded at the level of "
                "EACH alert of the incident, not only at the incident level. "
                "confirmed=False (default) only shows a preview of the changes; confirmed=True applies them.\n"
                "- alert_id: use the same 'alertId' returned by get_incident_details or get_security_alerts.\n"
                "- assigned_to: if omitted, it is auto-filled with the UPN of the locally configured analyst (MCP_ANALYST_NAME).\n"
                "- When setting status='resolved' you MUST also send: classification, determination and comment."
            ),
            inputSchema={
                "type": "object",
                "required": ["alert_id"],
                "properties": {
                    "alert_id": {"type": "string"},
                    "status": {"type": "string", "enum": ["new", "inProgress", "resolved"]},
                    "classification": {"type": "string", "enum": INCIDENT_CLASSIFICATIONS},
                    "determination": {"type": "string", "enum": ALERT_DETERMINATIONS, "description": f"Must match the chosen classification: {ALERT_DETERMINATIONS_BY_CLASSIFICATION}"},
                    "assigned_to": {"type": "string", "description": "UPN of the assigned analyst - rarely needs to be passed: omit it so it is auto-filled with MCP_ANALYST_NAME (the real analyst on this machine). Pass it explicitly ONLY to reassign to an analyst other than the one handling the incident. NEVER use the conversation context's 'userEmail' here (that is the user's identity for general attribution, not necessarily the Defender analyst's UPN)."},
                    "comment": {"type": "string", "description": "Explains why it was classified/resolved this way - feeds Defender's learning about this alert."},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── D. DEVICES - READ (Machine.Read.All) ────────────────────

        types.Tool(
            name="get_device_info",
            description="Device information by ID or by name. Requires at least one of: device_id, device_name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "device_name": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="get_device_alerts",
            description="Alerts associated with a device.",
            inputSchema={
                "type": "object",
                "required": ["device_id"],
                "properties": {
                    "device_id": {"type": "string"},
                    "top": {"type": "integer", "default": 25},
                },
            },
        ),

        types.Tool(
            name="get_device_logon_users",
            description="Users who have logged on to a device.",
            inputSchema={
                "type": "object",
                "required": ["device_id"],
                "properties": {"device_id": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_device_missing_kbs",
            description="Missing patches (KBs) on a device - useful for correlating known vulnerabilities with an endpoint.",
            inputSchema={
                "type": "object",
                "required": ["device_id"],
                "properties": {"device_id": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_device_investigations",
            description="Automated investigations (AIR) associated with a device.",
            inputSchema={
                "type": "object",
                "required": ["device_id"],
                "properties": {"device_id": {"type": "string"}},
            },
        ),

        # ── E. DEVICE ACTIONS ────────────────────────────────────────────────

        types.Tool(
            name="isolate_device",
            description=(
                "⚠️ ACTION WITH SIDE EFFECTS - isolates a device from the network. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["device_id", "comment"],
                "properties": {
                    "device_id": {"type": "string"},
                    "isolation_type": {"type": "string", "enum": ["Full", "Selective"], "default": "Full"},
                    "comment": {"type": "string", "description": "Reason for the action (required)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="unisolate_device",
            description=(
                "⚠️ ACTION WITH SIDE EFFECTS - reverts the isolation of a device. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["device_id", "comment"],
                "properties": {
                    "device_id": {"type": "string"},
                    "comment": {"type": "string", "description": "Reason for the action (required)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="run_antivirus_scan",
            description=(
                "⚠️ ACTION WITH SIDE EFFECTS - starts an antivirus scan on a device. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["device_id", "comment"],
                "properties": {
                    "device_id": {"type": "string"},
                    "scan_type": {"type": "string", "enum": ["Quick", "Full"], "default": "Quick"},
                    "comment": {"type": "string", "description": "Reason for the action (required)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="collect_investigation_package",
            description=(
                "⚠️ ACTION WITH SIDE EFFECTS - collects a forensic package from a device (takes several minutes, "
                "returns a machineAction ID for tracking). "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["device_id", "comment"],
                "properties": {
                    "device_id": {"type": "string"},
                    "comment": {"type": "string", "description": "Reason for the action (required)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="stop_and_quarantine_file",
            description=(
                "⚠️ DESTRUCTIVE AND IRREVERSIBLE ACTION on the device - terminates the process and quarantines "
                "the file. Requires SHA1 (not SHA256). "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["device_id", "sha1", "comment"],
                "properties": {
                    "device_id": {"type": "string"},
                    "sha1": {"type": "string", "description": "SHA1 of the file (NOT SHA256)"},
                    "comment": {"type": "string", "description": "Reason for the action (required)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── F. FILES (File.Read.All) ─────────────────────────────────────

        types.Tool(
            name="get_file_info",
            description="Reputation/prevalence information for a file by its SHA256.",
            inputSchema={
                "type": "object",
                "required": ["sha256"],
                "properties": {"sha256": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_file_machines",
            description="Devices where a file has been observed - useful for measuring the blast radius of a malicious hash.",
            inputSchema={
                "type": "object",
                "required": ["sha1"],
                "properties": {
                    "sha1": {"type": "string", "description": "SHA1 of the file (NOT SHA256 - this Defender endpoint only accepts SHA1)"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="get_file_alerts",
            description="Alerts related to a file by its SHA256.",
            inputSchema={
                "type": "object",
                "required": ["sha256"],
                "properties": {"sha256": {"type": "string"}},
            },
        ),

        # ── G. IPs (Ip.Read.All) ─────────────────────────────────────────────

        types.Tool(
            name="get_ip_info",
            description="Organizational prevalence and alerts related to an IP.",
            inputSchema={
                "type": "object",
                "required": ["ip"],
                "properties": {"ip": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_ip_machines",
            description="Devices that communicated with an IP.",
            inputSchema={
                "type": "object",
                "required": ["ip"],
                "properties": {
                    "ip": {"type": "string"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        # ── H. URLs (Url.Read.All) ───────────────────────────────────────────

        types.Tool(
            name="get_url_info",
            description="Organizational prevalence and alerts related to a URL.",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {"url": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_url_machines",
            description="Devices that accessed a URL.",
            inputSchema={
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        # ── I. USERS - MDE view (User.Read.All) ─────────────────────────

        types.Tool(
            name="get_user_devices",
            description=(
                "Devices associated with a user (MDE view). Accepts user_id (format 'domain;user') "
                "or user_upn (format 'user@domain.com'); at least one is required."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "MDE format: domain;user"},
                    "user_upn": {"type": "string", "description": "UPN format: user@domain.com"},
                },
            },
        ),

        types.Tool(
            name="get_user_alerts",
            description=(
                "Alerts where a user is a related entity (MDE view). Accepts user_id or user_upn; "
                "at least one is required."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "MDE format: domain;user"},
                    "user_upn": {"type": "string", "description": "UPN format: user@domain.com"},
                },
            },
        ),

        # ── J. IOC INDICATORS (Ti.ReadWrite.All) ───────────────────────────

        types.Tool(
            name="get_indicators",
            description="Lists IOC indicators configured in the tenant, filterable by type and action.",
            inputSchema={
                "type": "object",
                "properties": {
                    "indicator_type": {"type": "string", "enum": INDICATOR_TYPES},
                    "action": {"type": "string", "enum": INDICATOR_ACTIONS},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="get_indicator_by_value",
            description="Checks whether an IOC (hash, IP, URL, domain) already exists as an indicator - useful before creating one.",
            inputSchema={
                "type": "object",
                "required": ["indicator_value"],
                "properties": {"indicator_value": {"type": "string"}},
            },
        ),

        types.Tool(
            name="add_ioc_indicator",
            description=(
                "⚠️ ACTION WITH SIDE EFFECTS - creates an IOC indicator. If action=AlertAndBlock, it will block the "
                "indicator on ALL devices in the tenant. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["indicator_type", "indicator_value", "action", "title"],
                "properties": {
                    "indicator_type": {"type": "string", "enum": INDICATOR_TYPES},
                    "indicator_value": {"type": "string"},
                    "action": {"type": "string", "enum": INDICATOR_ACTIONS},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string", "enum": INDICATOR_SEVERITIES, "default": "Medium"},
                    "expiration_days": {"type": "integer", "default": 30},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="update_ioc_indicator",
            description=(
                "⚠️ Updates an existing IOC indicator. "
                "confirmed=False (default) only shows a preview of the changes; confirmed=True applies them."
            ),
            inputSchema={
                "type": "object",
                "required": ["indicator_id"],
                "properties": {
                    "indicator_id": {"type": "string"},
                    "action": {"type": "string", "enum": INDICATOR_ACTIONS},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string", "enum": INDICATOR_SEVERITIES},
                    "expiration_days": {"type": "integer"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="delete_ioc_indicator",
            description=(
                "⚠️ DESTRUCTIVE ACTION - deletes an IOC indicator. "
                "confirmed=False (default) only shows a preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["indicator_id"],
                "properties": {
                    "indicator_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── K. HELPERS (no API calls) ───────────────────────────────

        types.Tool(
            name="get_hunting_query_library",
            description=(
                "Library of reference KQL queries organized by MITRE ATT&CK tactic, ready to "
                "run directly in run_kql_hunting. Filterable by mitre_tactic and/or keyword."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "mitre_tactic": {"type": "string"},
                    "keyword": {"type": "string"},
                },
            },
        ),

    ]


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("defender")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    # ── A. HUNTING ───────────────────────────────────────────────────────

    if name == "hunt_emails_by_subject":
        days = arguments.get("days_back", 30)
        pattern = _kql_escape(arguments["subject_pattern"])
        query = f"""
EmailEvents
| where Timestamp > ago({days}d)
| where Subject has "{pattern}"
| summarize
    TotalEmails = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    UniqueRecipients = dcount(RecipientEmailAddress),
    Delivered = countif(DeliveryAction == "Delivered"),
    Blocked = countif(DeliveryAction in ("Blocked", "Junked")),
    Recipients = make_set(RecipientEmailAddress, 100)
  by SenderFromAddress, SenderDisplayName, SenderIPv4, Subject, DeliveryAction
| order by TotalEmails desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "hunt_emails_by_sender":
        days = arguments.get("days_back", 30)
        sender = _kql_escape(arguments["sender"])
        op = "has" if sender.startswith("@") else "=~"
        field = "SenderFromDomain" if sender.startswith("@") else "SenderFromAddress"
        domain = sender.lstrip("@") if sender.startswith("@") else sender
        query = f"""
EmailEvents
| where Timestamp > ago({days}d)
| where {field} {op} "{domain}"
| project Timestamp, SenderFromAddress, SenderDisplayName, SenderIPv4,
    RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
    ThreatTypes, DetectionMethods, UrlCount, AttachmentCount
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "trace_email_delivery":
        _require_at_least_one(arguments, ["sender_email", "recipient_email", "subject_contains"])
        days = arguments.get("days_back", 7)
        conditions = [f"Timestamp > ago({days}d)"]
        if arguments.get("sender_email"):
            conditions.append(f'SenderFromAddress =~ "{_kql_escape(arguments["sender_email"])}"')
        if arguments.get("recipient_email"):
            conditions.append(f'RecipientEmailAddress =~ "{_kql_escape(arguments["recipient_email"])}"')
        if arguments.get("subject_contains"):
            conditions.append(f'Subject has "{_kql_escape(arguments["subject_contains"])}"')
        where_clause = " | where ".join(conditions)
        query = f"""
let emails = EmailEvents
| where {where_clause}
| project NetworkMessageId, Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, DeliveryAction, DeliveryLocation, ThreatTypes, DetectionMethods;
let post_delivery = EmailPostDeliveryEvents
| project NetworkMessageId, Timestamp, Action, ActionType, ActionResult, ActionTrigger;
emails
| join kind=leftouter post_delivery on NetworkMessageId
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "run_kql_hunting":
        query = arguments["query"]
        try:
            data = mtp.post("/advancedhunting/run", {"Query": query})
        except RuntimeError as e:
            status_str = str(e).split(":", 1)[0]
            if status_str.isdigit() and 400 <= int(status_str) < 500:
                data = mde.post("/advancedqueries/run", {"Query": query})
            else:
                raise
        results = data.get("Results", data.get("results", []))
        return ok(_cap_hunt_results(results))

    elif name == "hunt_emails_by_url":
        days = arguments.get("days_back", 30)
        pattern = _kql_escape(arguments["url_pattern"])
        query = f"""
let urls = EmailUrlInfo
| where Timestamp > ago({days}d)
| where Url has "{pattern}"
| project NetworkMessageId, Url, UrlDomain, UrlLocation;
EmailEvents
| where Timestamp > ago({days}d)
| join kind=inner urls on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, Url, UrlDomain, DeliveryAction,
    DeliveryLocation, ThreatTypes
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "hunt_emails_by_attachment_hash":
        days = arguments.get("days_back", 30)
        sha256 = _kql_escape(arguments["sha256"])
        query = f"""
let attachments = EmailAttachmentInfo
| where Timestamp > ago({days}d)
| where SHA256 =~ "{sha256}"
| project NetworkMessageId, FileName, FileSize, SHA256;
EmailEvents
| where Timestamp > ago({days}d)
| join kind=inner attachments on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
    Subject, FileName, FileSize, SHA256,
    DeliveryAction, DeliveryLocation
| order by Timestamp desc
| limit 200
"""
        return ok(_hunt(query))

    elif name == "hunt_device_process_events":
        _require_at_least_one(arguments, ["device_name", "process_name", "command_line_contains", "sha256"])
        days = arguments.get("days_back", 7)
        filters = [f"Timestamp > ago({days}d)"]
        if arguments.get("device_name"):
            filters.append(f'DeviceName has "{_kql_escape(arguments["device_name"])}"')
        if arguments.get("process_name"):
            filters.append(f'FileName =~ "{_kql_escape(arguments["process_name"])}"')
        if arguments.get("command_line_contains"):
            filters.append(f'ProcessCommandLine has "{_kql_escape(arguments["command_line_contains"])}"')
        if arguments.get("sha256"):
            filters.append(f'SHA256 =~ "{_kql_escape(arguments["sha256"])}"')
        where_clause = "\n| where ".join(filters)
        query = f"""
DeviceProcessEvents
| where {where_clause}
| project Timestamp, DeviceName, AccountName, AccountDomain,
    FileName, FolderPath, ProcessCommandLine, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "hunt_device_network_events":
        _require_at_least_one(arguments, ["device_name", "remote_ip", "remote_url", "remote_port"])
        days = arguments.get("days_back", 7)
        filters = [f"Timestamp > ago({days}d)"]
        if arguments.get("device_name"):
            filters.append(f'DeviceName has "{_kql_escape(arguments["device_name"])}"')
        if arguments.get("remote_ip"):
            filters.append(f'RemoteIP == "{_kql_escape(arguments["remote_ip"])}"')
        if arguments.get("remote_url"):
            filters.append(f'RemoteUrl has "{_kql_escape(arguments["remote_url"])}"')
        if arguments.get("remote_port") is not None:
            filters.append(f"RemotePort == {int(arguments['remote_port'])}")
        where_clause = "\n| where ".join(filters)
        query = f"""
DeviceNetworkEvents
| where {where_clause}
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
    RemotePort, LocalIP, LocalPort,
    InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType,
    BytesSent, BytesReceived
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    elif name == "hunt_identity_logon_events":
        if not arguments.get("account_upn") and not arguments.get("src_ip"):
            raise ValueError("At least one of the following is required: account_upn, src_ip")
        days = arguments.get("days_back", 14)
        filters = [f"Timestamp > ago({days}d)"]
        if arguments.get("account_upn"):
            filters.append(f'AccountUpn =~ "{_kql_escape(arguments["account_upn"])}"')
        if arguments.get("src_ip"):
            filters.append(f'IPAddress == "{_kql_escape(arguments["src_ip"])}"')
        if arguments.get("failed_only"):
            filters.append('ActionType == "LogonFailed"')
        where_clause = "\n| where ".join(filters)
        query = f"""
IdentityLogonEvents
| where {where_clause}
| project Timestamp, AccountUpn, AccountDomain, IPAddress,
    Location, LogonType, Protocol, ActionType,
    FailureReason, TargetDeviceName, Application
| order by Timestamp desc
| limit 1000
"""
        return ok(_hunt(query))

    elif name == "hunt_cloud_app_events":
        # CloudAppEvents has no AccountUpn column (that belongs to EmailEvents/IdentityLogonEvents);
        # the account identifier in this table is AccountDisplayName (sometimes a UPN, sometimes
        # a display name, depending on the connector) and AccountObjectId (Entra GUID).
        _require_at_least_one(arguments, ["account_upn", "app_name", "action_type"])
        days = arguments.get("days_back", 14)
        filters = [f"Timestamp > ago({days}d)"]
        if arguments.get("account_upn"):
            filters.append(f'AccountDisplayName =~ "{_kql_escape(arguments["account_upn"])}"')
        if arguments.get("app_name"):
            filters.append(f'Application =~ "{_kql_escape(arguments["app_name"])}"')
        if arguments.get("action_type"):
            filters.append(f'ActionType =~ "{_kql_escape(arguments["action_type"])}"')
        where_clause = "\n| where ".join(filters)
        query = f"""
CloudAppEvents
| where {where_clause}
| project Timestamp, AccountDisplayName, AccountObjectId, Application, ActionType,
    ActivityType, ObjectName, ObjectType,
    IPAddress, CountryCode, ISP, UserAgent
| order by Timestamp desc
| limit 500
"""
        return ok(_hunt(query))

    # ── B. INCIDENTS ────────────────────────────────────────────────────

    elif name == "get_security_incidents":
        status = arguments.get("status")
        _validate_enum(status, ["active", "resolved", "inProgress"], "status")
        base_params = {}
        if status:
            base_params["$filter"] = f"status eq '{status}'"

        if arguments.get("fetch_all"):
            paged = _get_all_pages("/incidents", base_params)
            payload = {"count": len(paged["items"]), "incidents": paged["items"]}
            if paged["truncated"]:
                payload["_warning"] = f"Safety limit of {MAX_PAGED_ITEMS} incidents reached; there may be more that were not retrieved."
            return ok(payload)

        params = {**base_params, "$top": arguments.get("top", 10)}
        data = mtp.get("/incidents", params)
        return ok(data)

    elif name == "get_incident_details":
        data = mtp.get(f"/incidents/{arguments['incident_id']}", params={"$expand": "alerts"})
        return ok(data)

    elif name == "update_incident":
        incident_id = arguments["incident_id"]
        status = arguments.get("status")
        classification = arguments.get("classification")
        determination = arguments.get("determination")
        assigned_to = arguments.get("assigned_to") or get_analyst_upn()
        tags = arguments.get("tags")
        comment = arguments.get("comment")
        resolving_comment = arguments.get("resolving_comment")
        alert_comments = arguments.get("alert_comments") or []
        confirmed = arguments.get("confirmed", False)

        _validate_enum(status, ["active", "resolved", "inProgress"], "status")
        _validate_enum(classification, INCIDENT_CLASSIFICATIONS, "classification")
        _validate_enum(determination, INCIDENT_DETERMINATIONS, "determination")

        if resolving_comment and ("\n\n" in resolving_comment or resolving_comment.count("\n") > 2):
            raise ValueError(
                "resolving_comment must be a SINGLE-PARAGRAPH summary (no blank lines). "
                "Move the extended detail to 'comment' and 'alert_comments'."
            )

        incident_alert_ids = None
        if status == "resolved":
            incident_alert_ids = [a["alertId"] for a in mtp.get(f"/incidents/{incident_id}", params={"$expand": "alerts"}).get("alerts", [])]
            commented_ids = {ac["alert_id"] for ac in alert_comments}
            missing_alert_comments = [aid for aid in incident_alert_ids if aid not in commented_ids]

            missing = [
                field for field, value in [
                    ("classification", classification), ("determination", determination),
                    ("tags", tags), ("comment", comment), ("resolving_comment", resolving_comment),
                ] if not value
            ]
            if missing_alert_comments:
                missing.append(f"alert_comments (missing comment for: {', '.join(missing_alert_comments)})")
            if missing:
                raise ValueError(
                    "To resolve an incident (status='resolved') you must also send: "
                    "classification, determination, tags (at least 1), comment, resolving_comment (1 paragraph), "
                    f"and one alert_comments entry per alert of the incident. Missing: {'; '.join(missing)}. "
                    "Use list_incident_tags to see existing tags before creating a new one, and "
                    "get_incident_details to see the alertIds still pending a comment."
                )

        if not confirmed:
            current = mtp.get(f"/incidents/{incident_id}")
            changes = {}
            for field, new_value in [("status", status), ("classification", classification), ("determination", determination), ("assignedTo", assigned_to), ("tags", tags)]:
                if new_value is not None:
                    changes[field] = {"from": current.get(field), "to": new_value}
            if comment:
                changes["comment"] = {"from": None, "to": comment}
            if resolving_comment:
                changes["resolvingComment"] = {"from": None, "to": resolving_comment}
            if alert_comments:
                changes["alert_comments"] = {"from": None, "to": alert_comments}
            return _preview(
                "update_incident",
                {"incident_id": incident_id},
                f"Incident {incident_id} will be updated with the indicated changes.",
                changes=changes,
            )

        body = {k: v for k, v in {
            "status": status, "classification": classification,
            "determination": determination, "assignedTo": assigned_to,
            "tags": tags, "comment": comment,
        }.items() if v is not None}
        result = mtp.patch(f"/incidents/{incident_id}", body) if body else {}
        if resolving_comment:
            # Not available in the classic API above - it is Graph-only and requires
            # the SecurityIncident.ReadWrite.All application permission (Microsoft Graph).
            graph.patch(f"/security/incidents/{incident_id}", {"resolvingComment": resolving_comment})
            result = dict(result or {})
            result["resolvingComment"] = resolving_comment
        if alert_comments:
            result = dict(result or {})
            result["alert_comments_added"] = []
            for ac in alert_comments:
                graph.post(f"/security/alerts_v2/{ac['alert_id']}/comments", {
                    "@odata.type": "microsoft.graph.security.alertComment",
                    "comment": ac["comment"],
                })
                result["alert_comments_added"].append(ac["alert_id"])
        return _executed("update_incident", result)

    elif name == "add_incident_comment":
        result = mtp.patch(f"/incidents/{arguments['incident_id']}", {"comment": arguments["comment"]})
        return ok(result)

    elif name == "list_incident_tags":
        sample_size = min(arguments.get("sample_size", 500), MAX_PAGED_ITEMS)
        items = []
        next_url = None
        while len(items) < sample_size:
            data = mtp.get(next_url) if next_url else mtp.get("/incidents", {"$top": min(sample_size, 100)})
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
            if not next_url:
                break
        tags = sorted({tag for incident in items[:sample_size] for tag in (incident.get("tags") or [])})
        return ok({"tags": tags, "incidents_scanned": min(len(items), sample_size)})

    # ── C. ALERTS (Microsoft Graph /security/alerts_v2) ─────────────────

    elif name == "get_security_alerts":
        severity = arguments.get("severity")
        status = arguments.get("status")
        user_email = arguments.get("user_email")
        _validate_enum(severity, ["high", "medium", "low", "informational"], "severity")
        _validate_enum(status, ["new", "inProgress", "resolved"], "status")
        filters = []
        if severity:
            filters.append(f"severity eq '{severity}'")
        if status:
            filters.append(f"status eq '{status}'")

        base_params = {}
        if filters:
            base_params["$filter"] = " and ".join(filters)

        if arguments.get("fetch_all"):
            paged = _get_all_pages("/security/alerts_v2", base_params, client=graph)
            items = paged["items"]
            truncated = paged["truncated"]
        else:
            data = graph.get("/security/alerts_v2", {**base_params, "$top": arguments.get("top", 25)})
            items = data.get("value", [])
            truncated = False

        if user_email:
            needle = user_email.lower()
            items = [a for a in items if needle in json.dumps(a.get("evidence", [])).lower()]

        payload = {"count": len(items), "alerts": items}
        if truncated:
            payload["_warning"] = f"Safety limit of {MAX_PAGED_ITEMS} alerts reached; there may be more that were not retrieved."
        return ok(payload)

    elif name == "update_alert":
        alert_id = arguments["alert_id"]
        status = arguments.get("status")
        classification = arguments.get("classification")
        determination = arguments.get("determination")
        assigned_to = arguments.get("assigned_to") or get_analyst_upn()
        comment = arguments.get("comment")
        confirmed = arguments.get("confirmed", False)

        _validate_enum(status, ["new", "inProgress", "resolved"], "status")
        _validate_enum(classification, INCIDENT_CLASSIFICATIONS, "classification")
        _validate_enum(determination, ALERT_DETERMINATIONS, "determination")

        if status == "resolved":
            missing = [
                field for field, value in [
                    ("classification", classification), ("determination", determination), ("comment", comment),
                ] if not value
            ]
            if missing:
                raise ValueError(
                    "To resolve an alert (status='resolved') you must also send: classification, "
                    f"determination and a comment explaining the closure. Missing: {', '.join(missing)}. This comment "
                    "is what Defender uses to learn from already-resolved alerts."
                )

        if not confirmed:
            current = graph.get(f"/security/alerts_v2/{alert_id}")
            changes = {}
            for field, new_value in [("status", status), ("classification", classification), ("determination", determination), ("assignedTo", assigned_to)]:
                if new_value is not None:
                    changes[field] = {"from": current.get(field), "to": new_value}
            if comment:
                changes["comment"] = {"from": None, "to": comment}
            return _preview(
                "update_alert",
                {"alert_id": alert_id},
                f"Alert {alert_id} will be updated with the indicated changes.",
                changes=changes,
            )

        body = {k: v for k, v in {
            "status": status, "classification": classification,
            "determination": determination, "assignedTo": assigned_to,
        }.items() if v is not None}
        result = graph.patch(f"/security/alerts_v2/{alert_id}", body) if body else {}
        if comment:
            # Not a field of the PATCH above - it is a separate endpoint, and it returns
            # the full updated comment list (not the alert), unlike the PATCH.
            comments_result = graph.post(f"/security/alerts_v2/{alert_id}/comments", {
                "@odata.type": "microsoft.graph.security.alertComment",
                "comment": comment,
            })
            result = dict(result or {})
            result["comments"] = (comments_result or {}).get("value", [])
        return _executed("update_alert", result)

    # ── D. DEVICES - READ ────────────────────────────────────────

    elif name == "get_device_info":
        _require_at_least_one(arguments, ["device_id", "device_name"])
        if arguments.get("device_id"):
            data = mde.get(f"/machines/{arguments['device_id']}")
        else:
            result = mde.get("/machines", params={"$filter": f"computerDnsName eq '{arguments['device_name']}'"})
            data = result.get("value", result) if isinstance(result, dict) else result
        return ok(data)

    elif name == "get_device_alerts":
        data = mde.get(f"/machines/{arguments['device_id']}/alerts", params={"$top": arguments.get("top", 25)})
        return ok(data)

    elif name == "get_device_logon_users":
        data = mde.get(f"/machines/{arguments['device_id']}/logonusers")
        return ok(data)

    elif name == "get_device_missing_kbs":
        data = mde.get(f"/machines/{arguments['device_id']}/missingkbs")
        return ok(data)

    elif name == "get_device_investigations":
        data = mde.get(f"/machines/{arguments['device_id']}/investigations")
        return ok(data)

    # ── E. DEVICE ACTIONS ────────────────────────────────────────────────

    elif name == "isolate_device":
        device_id = arguments["device_id"]
        isolation_type = arguments.get("isolation_type", "Full")
        comment = arguments["comment"]
        confirmed = arguments.get("confirmed", False)
        _validate_enum(isolation_type, ["Full", "Selective"], "isolation_type")

        if not confirmed:
            device = mde.get(f"/machines/{device_id}")
            return _preview(
                "isolate_device",
                {"device_id": device_id, "device_name": device.get("computerDnsName"), "isolation_type": isolation_type},
                "This action will cut ALL of the device's network connectivity. "
                "Only communication with the Defender service will remain active.",
            )
        result = mde.post(f"/machines/{device_id}/isolate", {"Comment": comment, "IsolationType": isolation_type})
        return _executed("isolate_device", result)

    elif name == "unisolate_device":
        device_id = arguments["device_id"]
        comment = arguments["comment"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            device = mde.get(f"/machines/{device_id}")
            return _preview(
                "unisolate_device",
                {"device_id": device_id, "device_name": device.get("computerDnsName")},
                "The device's normal network connectivity will be restored.",
            )
        result = mde.post(f"/machines/{device_id}/unisolate", {"Comment": comment})
        return _executed("unisolate_device", result)

    elif name == "run_antivirus_scan":
        device_id = arguments["device_id"]
        scan_type = arguments.get("scan_type", "Quick")
        comment = arguments["comment"]
        confirmed = arguments.get("confirmed", False)
        _validate_enum(scan_type, ["Quick", "Full"], "scan_type")

        if not confirmed:
            device = mde.get(f"/machines/{device_id}")
            return _preview(
                "run_antivirus_scan",
                {"device_id": device_id, "device_name": device.get("computerDnsName"), "scan_type": scan_type},
                f"A {scan_type} antivirus scan will be started on the device.",
            )
        result = mde.post(f"/machines/{device_id}/runAntiVirusScan", {"Comment": comment, "ScanType": scan_type})
        return _executed("run_antivirus_scan", result)

    elif name == "collect_investigation_package":
        device_id = arguments["device_id"]
        comment = arguments["comment"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            device = mde.get(f"/machines/{device_id}")
            return _preview(
                "collect_investigation_package",
                {"device_id": device_id, "device_name": device.get("computerDnsName")},
                "Collection takes several minutes. A machineAction ID is returned for tracking.",
            )
        result = mde.post(f"/machines/{device_id}/collectInvestigationPackage", {"Comment": comment})
        return _executed("collect_investigation_package", {
            "machineAction_id": result.get("id") if isinstance(result, dict) else None,
            "raw": result,
        })

    elif name == "stop_and_quarantine_file":
        device_id = arguments["device_id"]
        sha1 = arguments["sha1"]
        comment = arguments["comment"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            device = mde.get(f"/machines/{device_id}")
            return _preview(
                "stop_and_quarantine_file",
                {"device_id": device_id, "device_name": device.get("computerDnsName"), "sha1": sha1},
                "IRREVERSIBLE on this device. The process will be terminated and the file moved to quarantine.",
            )
        result = mde.post(f"/machines/{device_id}/stopAndQuarantineFile", {"Comment": comment, "Sha1": sha1})
        return _executed("stop_and_quarantine_file", result)

    # ── F. FILES ──────────────────────────────────────────────────────

    elif name == "get_file_info":
        data = mde.get(f"/files/{arguments['sha256']}")
        return ok(data)

    elif name == "get_file_machines":
        data = mde.get(f"/files/{arguments['sha1']}/machines", params={"$top": arguments.get("top", 50)})
        return ok(data)

    elif name == "get_file_alerts":
        data = mde.get(f"/files/{arguments['sha256']}/alerts")
        return ok(data)

    # ── G. IPs ───────────────────────────────────────────────────────────

    elif name == "get_ip_info":
        ip = arguments["ip"]
        encoded = quote(ip, safe="")
        stats = mde.get(f"/ips/{encoded}/stats")
        alerts = mde.get(f"/ips/{encoded}/alerts")
        return ok({"ip": ip, "stats": stats, "alerts": alerts})

    elif name == "get_ip_machines":
        ip = arguments["ip"]
        data = mde.get(f"/ips/{quote(ip, safe='')}/machines", params={"$top": arguments.get("top", 50)})
        return ok(data)

    # ── H. URLs ──────────────────────────────────────────────────────────

    elif name == "get_url_info":
        url = arguments["url"]
        encoded = quote(url, safe="")
        stats = mde.get(f"/urls/{encoded}/stats")
        alerts = mde.get(f"/urls/{encoded}/alerts")
        return ok({"url": url, "stats": stats, "alerts": alerts})

    elif name == "get_url_machines":
        url = arguments["url"]
        data = mde.get(f"/urls/{quote(url, safe='')}/machines", params={"$top": arguments.get("top", 50)})
        return ok(data)

    # ── I. USERS (MDE view) ──────────────────────────────────────────

    elif name == "get_user_devices":
        user_id = _resolve_user_id(arguments)
        data = mde.get(f"/users/{user_id}/machines")
        return ok(data)

    elif name == "get_user_alerts":
        user_id = _resolve_user_id(arguments)
        data = mde.get(f"/users/{user_id}/alerts")
        return ok(data)

    # ── J. IOC INDICATORS ───────────────────────────────────────────────

    elif name == "get_indicators":
        indicator_type = arguments.get("indicator_type")
        ioc_action = arguments.get("action")
        _validate_enum(indicator_type, INDICATOR_TYPES, "indicator_type")
        _validate_enum(ioc_action, INDICATOR_ACTIONS, "action")
        filters = []
        if indicator_type:
            filters.append(f"indicatorType eq '{indicator_type}'")
        if ioc_action:
            filters.append(f"action eq '{ioc_action}'")
        params = {"$top": arguments.get("top", 50)}
        if filters:
            params["$filter"] = " and ".join(filters)
        data = mde.get("/indicators", params)
        return ok(data)

    elif name == "get_indicator_by_value":
        value = arguments["indicator_value"]
        data = mde.get("/indicators", params={"$filter": f"indicatorValue eq '{value}'"})
        return ok(data)

    elif name == "add_ioc_indicator":
        indicator_type = arguments["indicator_type"]
        indicator_value = arguments["indicator_value"]
        ioc_action = arguments["action"]
        title = arguments["title"]
        description = arguments.get("description")
        severity = arguments.get("severity", "Medium")
        expiration_days = arguments.get("expiration_days", 30)
        confirmed = arguments.get("confirmed", False)

        _validate_enum(indicator_type, INDICATOR_TYPES, "indicator_type")
        _validate_enum(ioc_action, INDICATOR_ACTIONS, "action")
        _validate_enum(severity, INDICATOR_SEVERITIES, "severity")

        expiration_time = (datetime.now(timezone.utc) + timedelta(days=expiration_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "action": ioc_action,
            "title": title,
            "description": description or title,
            "severity": severity,
            "expirationTime": expiration_time,
        }

        if not confirmed:
            what = f"Indicator {indicator_value} ({indicator_type}) will be created with action {ioc_action}."
            if ioc_action == "AlertAndBlock":
                what += f" It WILL BLOCK {indicator_value} on ALL devices in the tenant."
            return _preview("add_ioc_indicator", body, what)

        result = mde.post("/indicators", body)
        return _executed("add_ioc_indicator", result)

    elif name == "update_ioc_indicator":
        indicator_id = arguments["indicator_id"]
        ioc_action = arguments.get("action")
        title = arguments.get("title")
        description = arguments.get("description")
        severity = arguments.get("severity")
        expiration_days = arguments.get("expiration_days")
        confirmed = arguments.get("confirmed", False)

        _validate_enum(ioc_action, INDICATOR_ACTIONS, "action")
        _validate_enum(severity, INDICATOR_SEVERITIES, "severity")

        if not confirmed:
            current = mde.get(f"/indicators/{indicator_id}")
            changes = {}
            for field, new_value in [("action", ioc_action), ("title", title), ("description", description), ("severity", severity)]:
                if new_value is not None:
                    changes[field] = {"from": current.get(field), "to": new_value}
            if expiration_days is not None:
                new_expiration = (datetime.now(timezone.utc) + timedelta(days=expiration_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
                changes["expirationTime"] = {"from": current.get("expirationTime"), "to": new_expiration}
            return _preview(
                "update_ioc_indicator",
                {"indicator_id": indicator_id},
                f"Indicator {indicator_id} will be updated with the indicated changes.",
                changes=changes,
            )

        body = {k: v for k, v in {
            "action": ioc_action, "title": title, "description": description, "severity": severity,
        }.items() if v is not None}
        if expiration_days is not None:
            body["expirationTime"] = (datetime.now(timezone.utc) + timedelta(days=expiration_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = mde.patch(f"/indicators/{indicator_id}", body)
        return _executed("update_ioc_indicator", result)

    elif name == "delete_ioc_indicator":
        indicator_id = arguments["indicator_id"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            current = mde.get(f"/indicators/{indicator_id}")
            target = {
                "indicator_id": indicator_id,
                "indicatorValue": current.get("indicatorValue"),
                "indicatorType": current.get("indicatorType"),
                "action": current.get("action"),
                "title": current.get("title"),
            }
            return _preview("delete_ioc_indicator", target, f"Indicator {indicator_id} will be permanently deleted.")

        mde.delete(f"/indicators/{indicator_id}")
        return _executed("delete_ioc_indicator", {"indicator_id": indicator_id, "deleted": True})

    # ── K. HELPERS ────────────────────────────────────────────────────

    elif name == "get_hunting_query_library":
        mitre_tactic = arguments.get("mitre_tactic")
        keyword = arguments.get("keyword")
        results = HUNTING_QUERY_LIBRARY
        if mitre_tactic:
            results = [q for q in results if q["mitre_tactic"].lower() == mitre_tactic.lower()]
        if keyword:
            kw = keyword.lower()
            results = [q for q in results if kw in q["name"].lower() or kw in q["description"].lower()]
        return ok({"count": len(results), "queries": results})

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


# ── REQUIRED PERMISSIONS ─────────────────────────────────────
# App registration: dedicated Defender app (e.g. api-mcp-defender)
#
# Microsoft Threat Protection
# (APIs my organization uses -> "Microsoft Threat Protection"):
#   AdvancedHunting.Read.All  -> Section A (hunting)
#   Incident.ReadWrite.All    -> Section B (incidents)
#
# WindowsDefenderATP
# (APIs my organization uses -> "WindowsDefenderATP"):
#   AdvancedQuery.Read.All     -> run_kql_hunting fallback
#   File.Read.All              -> Section F (files/hashes)
#   Ip.Read.All                -> Section G (IPs)
#   Machine.CollectForensics   -> E4 collect_investigation_package
#   Machine.Isolate            -> E1/E2 isolate/unisolate_device
#   Machine.Read.All           -> Section D (device info)
#   Machine.Scan               -> E3 run_antivirus_scan
#   Machine.StopAndQuarantine  -> E5 stop_and_quarantine_file
#   Ti.ReadWrite.All           -> Section J (IOC indicators)
#   Url.Read.All               -> Section H (URLs)
#   User.Read.All              -> Section I (MDE users)
#
# Microsoft Graph (Application):
#   SecurityIncident.ReadWrite.All -> update_incident 'resolvingComment'
#   SecurityAlert.ReadWrite.All    -> Section C (alerts via /security/alerts_v2) and
#                                     alert_comments in update_incident
# ─────────────────────────────────────────────────────────────
