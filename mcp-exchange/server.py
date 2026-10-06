"""
MCP Server - Exchange Online (mail)

Scope: users/mailboxes, reading and acting on emails, mailbox rules, mailbox
settings, Transport Rules, Connectors, protection policies, Quarantine and
auditing. This is Exchange, not Defender: KQL hunting over EmailEvents
(including trace_email_delivery, the functional replacement for Message Trace,
see the PERMISSIONS comment at the end of the file) lives in mcp-defender;
this server administers the Exchange mailbox/tenant itself.

Talks to three APIs:
  - Microsoft Graph (graph.microsoft.com): users, mailboxes, emails, rules
  - Exchange Online Admin API (outlook.office365.com): Transport Rules,
    Connectors, policies.
  - Security & Compliance PowerShell (ps.compliance.protection.outlook.com): Quarantine
    (Get/Release/Delete/Report-QuarantineMessage). This is a DIFFERENT host and scope
    from Exchange Online; it also requires the app's service principal to have an
    Exchange role assignment (New-ManagementRoleAssignment, e.g. role
    "Transport Hygiene"), not just the Exchange.ManageAsApp permission in Entra. Without
    that role assignment this host returns 500 "Could not find the organization
    container" instead of a normal 401/403.

Requires: pip install -r requirements.txt
Environment variables:
  AZURE_TENANT_ID        (shared across all mcp-* servers)
  EXCHANGE_CLIENT_ID     (app registration dedicated to Exchange: sec-exchange-mcp)
  EXCHANGE_CLIENT_SECRET (the analyst's individual secret within that app)
  MCP_ANALYST_NAME       (optional; analyst name for the audit log)
"""

import json
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.auth import get_token, load_domain_credentials
from shared.graph_client import GraphClient
from shared.exo_client import ExoClient
from shared.mcp_common import ok, audited, require_vault

TENANT_ID, CLIENT_ID, CLIENT_SECRET = load_domain_credentials("EXCHANGE")

graph = GraphClient(
    lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET, scope="https://graph.microsoft.com/.default")
)
exo = ExoClient(
    lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET, scope="https://outlook.office365.com/.default"),
    tenant_id=TENANT_ID,
)
# Quarantine lives in Security & Compliance PowerShell, not Exchange Online: different
# host and scope (see the module docstring).
compliance = ExoClient(
    lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET, scope="https://ps.compliance.protection.outlook.com/.default"),
    tenant_id=TENANT_ID,
    host="ps.compliance.protection.outlook.com",
)

server = Server("mcp-exchange")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_enum(value, allowed: list, field_name: str) -> None:
    if value is not None and value not in allowed:
        raise ValueError(
            f"'{value}' is not valid for {field_name}. Allowed values: {allowed}"
        )


def _require_at_least_one(arguments: dict, fields: list) -> None:
    if not any(arguments.get(f) for f in fields):
        raise ValueError(f"At least one of the following is required: {', '.join(fields)}")


def _odata_key(value: str) -> str:
    """Escape an identifier for use as an OData key in a path,
    e.g. /TransportRule('{id}') - avoids breaking the URL or injecting quotes
    if the identifier contains ' or special characters."""
    return urllib.parse.quote(str(value).replace("'", "''"), safe="")


def _dry_run_preview(criteria: dict, what_would_happen: str, affected_items: list, **extra):
    payload = {
        "mode": "DRY_RUN - no action executed",
        "criteria": criteria,
        "what_would_happen": what_would_happen,
        "affected_count": len(affected_items),
        "affected_items": affected_items,
    }
    payload.update(extra)
    payload["next_step"] = "Call with dry_run=False to execute."
    return ok(payload)


def _confirm_preview(action: str, target: dict, what_would_happen: str, **extra):
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


def _build_message_filter(arguments: dict) -> list:
    clauses = []
    if arguments.get("subject_contains"):
        clauses.append(f"contains(subject,'{arguments['subject_contains']}')")
    if arguments.get("from_address"):
        clauses.append(f"from/emailAddress/address eq '{arguments['from_address']}'")
    if arguments.get("received_after"):
        clauses.append(f"receivedDateTime ge {arguments['received_after']}")
    if arguments.get("received_before"):
        clauses.append(f"receivedDateTime le {arguments['received_before']}")
    if arguments.get("has_attachments") is not None:
        clauses.append(f"hasAttachments eq {str(arguments['has_attachments']).lower()}")
    return clauses


def _forbids_orderby(clauses: list) -> bool:
    """Exchange/Graph rejects (400 InefficientFilter) combining $orderby with a $filter that
    uses contains() OR filters on the nested property from/emailAddress/address -
    even with a simple 'eq', not just contains(). For example, 'from/emailAddress/
    address eq ... and receivedDateTime ge/le ...' + $orderby is already "too complex"."""
    return any("contains(" in c or "from/emailAddress/address" in c for c in clauses)


def _search_messages_paged(user_email: str, clauses: list, select: str, max_items: int = 500) -> list:
    items = []
    path = f"/users/{user_email}/messages"
    params = {
        "$filter": " and ".join(clauses),
        "$select": select,
        "$top": min(max_items, 999),
    }
    if not _forbids_orderby(clauses):
        params["$orderby"] = "receivedDateTime desc"
    next_url = None
    while True:
        data = graph.get(next_url) if next_url else graph.get(path, params)
        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
        if not next_url or len(items) >= max_items:
            break
    return items[:max_items]


def _graph_batch(requests_list: list) -> dict:
    """Run mixed requests (POST/DELETE) in batches of 20 via Graph $batch.
    Returns {"succeeded": int, "failed": [...]}."""
    succeeded = 0
    failed = []
    for i in range(0, len(requests_list), 20):
        chunk = requests_list[i:i + 20]
        for j, req in enumerate(chunk):
            req["id"] = str(i + j + 1)
        resp = graph.post("/$batch", {"requests": chunk})
        for r in resp.get("responses", []):
            status = r.get("status")
            if status is not None and 200 <= status < 300:
                succeeded += 1
            else:
                failed.append({"id": r.get("id"), "status": status, "body": r.get("body")})
    return {"succeeded": succeeded, "failed": failed}


QUARANTINE_TYPES = ["Bulk", "Phish", "Spam", "Malware", "TransportRule", "HighConfPhish"]


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools():
    return [

        # ── A. USERS ──────────────────────────────────────────────────────

        types.Tool(
            name="list_mailbox_users",
            description="Lists tenant users with an active mailbox (non-null mail). Filterable by name/email.",
            inputSchema={
                "type": "object",
                "properties": {
                    "search": {"type": "string", "description": "Filters by displayName or mail starting with this text"},
                    "top": {"type": "integer", "default": 50, "maximum": 999},
                },
            },
        ),

        # ── B. MAILBOX AND EMAIL READING ────────────────────────────────────

        types.Tool(
            name="get_mailbox_settings",
            description="Full mailbox configuration (automatic replies, language, time zone, delegates) plus the user's aliases/licenses/on-prem attributes.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_mailbox_rules",
            description="COMPLETE list (unfiltered and unclassified) of a user's inbox rules.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_mailbox_delegates",
            description="Mailbox-level forwarding (SMTP), forward+deliver, and a user's send-on-behalf permissions.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_email_full_content",
            description="Full email of a user including internetMessageHeaders (raw headers: Received, Message-ID, X-Mailer, SPF, DKIM, etc.). Requires the Graph messageId.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "message_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "message_id": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="search_mailbox_messages",
            description="Searches messages in a mailbox by subject, sender, date range and/or attachments. Requires at least one criterion.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "subject_contains": {"type": "string"},
                    "from_address": {"type": "string"},
                    "received_after": {"type": "string", "description": "ISO 8601"},
                    "received_before": {"type": "string", "description": "ISO 8601"},
                    "has_attachments": {"type": "boolean"},
                    "top": {"type": "integer", "default": 25, "maximum": 100},
                },
            },
        ),

        types.Tool(
            name="resolve_message_id",
            description=(
                "Defender -> Exchange bridge: given an internetMessageId (the RFC 822 Message-ID: header, "
                "as it appears in NetworkMessageId/EmailEvents in Advanced Hunting), returns the message's "
                "Graph id so it can be used with get_email_full_content."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email", "internet_message_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "internet_message_id": {"type": "string", "description": "With or without the < > of the header; they are added automatically if missing."},
                },
            },
        ),

        types.Tool(
            name="get_email_activity_report",
            description="Email activity report (sent/received/read) per user over a period.",
            inputSchema={
                "type": "object",
                "properties": {
                    "period": {"type": "string", "enum": ["D7", "D30", "D90", "D180"], "default": "D30"},
                },
            },
        ),

        # ── C. EMAIL ACTIONS ────────────────────────────────────────

        types.Tool(
            name="delete_emails_by_criteria",
            description=(
                "⚠️ Searches for and deletes emails in ONE mailbox by criteria. delete_type=soft moves to Deleted "
                "Items (recoverable); hard is a permanent, irreversible DELETE. "
                "dry_run=True (default) only lists what would be affected; dry_run=False executes. "
                "Requires at least one search criterion."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "subject_contains": {"type": "string"},
                    "from_address": {"type": "string"},
                    "received_after": {"type": "string", "description": "ISO 8601"},
                    "received_before": {"type": "string", "description": "ISO 8601"},
                    "delete_type": {"type": "string", "enum": ["soft", "hard"], "default": "soft"},
                    "dry_run": {"type": "boolean", "default": True},
                },
            },
        ),

        types.Tool(
            name="delete_emails_bulk_by_subject",
            description=(
                "⚠️ Org-wide version of delete_emails_by_criteria: scans up to max_users tenant mailboxes "
                "and deletes emails matching the subject (and optionally the sender). "
                "dry_run=True (default) only summarizes what would be affected per mailbox; dry_run=False executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["subject_contains"],
                "properties": {
                    "subject_contains": {"type": "string"},
                    "from_address": {"type": "string"},
                    "days_back": {"type": "integer", "default": 30},
                    "delete_type": {"type": "string", "enum": ["soft", "hard"], "default": "soft"},
                    "dry_run": {"type": "boolean", "default": True},
                    "max_users": {"type": "integer", "default": 200},
                },
            },
        ),

        types.Tool(
            name="move_email_to_folder",
            description="Moves a message to another mailbox folder. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "message_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "message_id": {"type": "string"},
                    "destination_folder": {"type": "string", "enum": ["junkemail", "deleteditems", "inbox", "archive"], "default": "junkemail"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── D. MAILBOX CONFIGURATION ────────────────────────────────────────

        types.Tool(
            name="disable_mailbox_forwarding",
            description="Removes the SMTP forwarding configured on a mailbox. confirmed=False (default) shows the preview; confirmed=True executes. If there is no forwarding, it reports that and does nothing.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="disable_mailbox_auto_reply",
            description=(
                "Neutralizes a mailbox's automatic reply (Out of Office): sets status='disabled' and "
                "empties internalReplyMessage/externalReplyMessage. Use it when a compromised mailbox has "
                "phishing/malicious content stored in its automatic reply (a common BEC "
                "persistence/self-propagation technique); even if already 'disabled', the malicious HTML stays "
                "stored until explicitly cleared. confirmed=False (default) shows the full current content "
                "before clearing it (to keep it as evidence); confirmed=True clears it. "
                "If no message is configured, it reports that and does nothing."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="delete_mailbox_rule",
            description="⚠️ Permanently deletes an inbox rule. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "rule_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="disable_mailbox_rule",
            description="Disables (without deleting) an inbox rule - preferable when there is no full certainty. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "rule_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── F. TRANSPORT RULES ───────────────────────────────────────────────

        types.Tool(
            name="get_transport_rules",
            description="Complete list (unfiltered and unclassified) of the tenant's transport rules, so the analyst can evaluate potentially malicious rules.",
            inputSchema={
                "type": "object",
                "properties": {
                    "enabled_only": {"type": "boolean", "default": False},
                    "top": {"type": "integer", "default": 100},
                },
            },
        ),

        types.Tool(
            name="get_transport_rule_detail",
            description="Full details of a transport rule by ID or name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "rule_name": {"type": "string"},
                },
            },
        ),

        types.Tool(
            name="create_transport_rule",
            description="⚠️ Creates a transport rule. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["name", "conditions", "actions"],
                "properties": {
                    "name": {"type": "string"},
                    "priority": {"type": "integer", "default": 0},
                    "conditions": {"type": "object", "description": "E.g.: {\"SenderDomainIs\": [\"malicious.com\"]}"},
                    "actions": {"type": "object", "description": "E.g.: {\"DeleteMessage\": true} or {\"QuarantineMessage\": true}"},
                    "comments": {"type": "string"},
                    "mode": {"type": "string", "enum": ["Enforce", "Audit", "AuditAndNotify"], "default": "Enforce"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="update_transport_rule",
            description="Updates the state/priority/comments of a transport rule - typically used to disable a malicious rule. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["rule_id"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "state": {"type": "string", "enum": ["Enabled", "Disabled"]},
                    "priority": {"type": "integer"},
                    "comments": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="delete_transport_rule",
            description="⚠️ IRREVERSIBLE - permanently deletes a transport rule. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["rule_id"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── G. CONNECTORS ────────────────────────────────────────────────────

        types.Tool(
            name="get_inbound_connectors",
            description="Inbound connectors of the tenant - a broad SenderIPAddresses or RestrictDomainsToIPAddresses=False may indicate an anti-spam filter bypass.",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="get_outbound_connectors",
            description="Outbound connectors of the tenant - an unrecognized external SmartHost may indicate mail exfiltration.",
            inputSchema={"type": "object", "properties": {}},
        ),

        # ── H. PROTECTION POLICIES ───────────────────────────────────────

        types.Tool(
            name="get_antispam_policies",
            description="Tenant anti-spam policies: actions for spam/phishing/bulk, thresholds, allow/block lists.",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="get_antiphishing_policies",
            description="Tenant anti-phishing policies: mailbox intelligence, spoof intelligence, targeted user protection, DMARC honoring.",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="get_dkim_config",
            description="DKIM configuration per domain - if Status != 'Valid' or Enabled=False, the domain is vulnerable to spoofing.",
            inputSchema={
                "type": "object",
                "properties": {"domain": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_blocked_sender_lists",
            description="Lists of blocked senders/domains in anti-spam policies, plus blocked/allowed IP lists in the connection filter.",
            inputSchema={"type": "object", "properties": {}},
        ),

        # ── I. QUARANTINE ────────────────────────────────────────────────────

        types.Tool(
            name="get_quarantine_messages",
            description="Quarantined messages, filterable by sender, recipient, subject, type and date range.",
            inputSchema={
                "type": "object",
                "properties": {
                    "sender_address": {"type": "string"},
                    "recipient_address": {"type": "string"},
                    "subject": {"type": "string"},
                    "quarantine_types": {"type": "array", "items": {"type": "string", "enum": QUARANTINE_TYPES}},
                    "start_date": {"type": "string", "description": "ISO 8601"},
                    "end_date": {"type": "string", "description": "ISO 8601"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="release_quarantine_message",
            description="⚠️ Releases a quarantined message to the recipient's mailbox. confirmed=False (default) shows the preview with a warning; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["identity", "release_to"],
                "properties": {
                    "identity": {"type": "string"},
                    "release_to": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="delete_quarantine_message",
            description="⚠️ IRREVERSIBLE - permanently deletes a quarantined message (it is never delivered). confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["identity"],
                "properties": {
                    "identity": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="report_quarantine_message",
            description=(
                "⚠️ NOT VERIFIED against a real tenant - reports a quarantined message to Microsoft as "
                "a false positive (NotJunk) or false negative (Phishing/Malware/Spam) using the "
                "/Report endpoint of the same QuarantineMessage resource. If your tenant rejects it, the official "
                "alternative is the Microsoft Graph Threat Submissions API (graph.microsoft.com/beta/security/"
                "threatSubmission). "
                "confirmed=False (default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["identity", "report_as"],
                "properties": {
                    "identity": {"type": "string"},
                    "report_as": {"type": "string", "enum": ["NotJunk", "Phishing", "Malware", "Spam"]},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="get_restricted_senders",
            description=(
                "⚠️ NOT VERIFIED against a real tenant - lists mailboxes blocked from sending mail by "
                "outbound anti-spam protection (equivalent to 'Restricted entities' in the Defender portal / "
                "the Get-BlockedSenderAddress cmdlet). The exact REST resource name is not confirmed; "
                "if your tenant returns 404, adjust the endpoint."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="unblock_sender",
            description=(
                "⚠️ NOT VERIFIED against a real tenant - removes a mailbox from the restricted senders "
                "list (equivalent to Remove-BlockedSenderAddress), typically after confirming "
                "the user is no longer compromised (password rotated, sessions revoked, MFA strengthened). "
                "confirmed=False (default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["sender_address"],
                "properties": {
                    "sender_address": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── K. HELPER: EMAIL CORRELATION ──────────────────────────────

        types.Tool(
            name="correlate_emails_by_subjects",
            description=(
                "Workflow generator (executes NOTHING): given a set of subjects, builds the KQL query "
                "ready for run_kql_hunting in mcp-defender (correlation by sending IP/domain, "
                "SPF/DKIM/DMARC, URL domains, attachment hashes) and, if user_email is given, suggests the "
                "search_mailbox_messages calls to reach the message_id and from there get_email_full_content."
            ),
            inputSchema={
                "type": "object",
                "required": ["subjects"],
                "properties": {
                    "subjects": {"type": "array", "items": {"type": "string"}},
                    "days_back": {"type": "integer", "default": 30},
                    "user_email": {"type": "string"},
                },
            },
        ),

    ]


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("exchange")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    # ── A. USERS ──────────────────────────────────────────────────────

    if name == "list_mailbox_users":
        search = arguments.get("search")
        top = arguments.get("top", 50)
        filter_clause = "mail ne null"
        if search:
            filter_clause += f" and (startsWith(displayName,'{search}') or startsWith(mail,'{search}'))"
        # The "ne" operator requires an advanced query (ConsistencyLevel: eventual + $count);
        # without it Graph returns 400 Request_UnsupportedQuery / NotEqualsMatch.
        data = graph.get("/users", params={
            "$select": "id,displayName,mail,userPrincipalName,accountEnabled",
            "$top": top,
            "$filter": filter_clause,
            "$count": "true",
        }, eventual=True)
        return ok(data)

    # ── B. MAILBOX AND EMAIL READING ────────────────────────────────────

    elif name == "get_mailbox_settings":
        user_email = arguments["user_email"]
        settings = graph.get(f"/users/{user_email}/mailboxSettings")
        profile = graph.get(f"/users/{user_email}", params={
            "$select": "mail,userPrincipalName,onPremisesExtensionAttributes,proxyAddresses,assignedLicenses",
        })
        return ok({"mailboxSettings": settings, "profile": profile})

    elif name == "get_mailbox_rules":
        user_email = arguments["user_email"]
        data = graph.get(f"/users/{user_email}/mailFolders/inbox/messageRules")
        return ok(data)

    elif name == "get_mailbox_delegates":
        user_email = arguments["user_email"]
        settings = graph.get(f"/users/{user_email}/mailboxSettings")
        exo_perms = exo.get(f"/Mailbox('{_odata_key(user_email)}')", params={
            "$select": "GrantSendOnBehalfTo,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward",
        })
        return ok({
            "forwardingSMTPAddress": settings.get("forwardingSMTPAddress"),
            "forwardingAddress": settings.get("forwardingAddress"),
            "exo_mailbox": exo_perms,
        })

    elif name == "get_email_full_content":
        user_email = arguments["user_email"]
        message_id = arguments["message_id"]
        data = graph.get(
            f"/users/{user_email}/messages/{message_id}",
            params={"$select": "id,subject,from,toRecipients,ccRecipients,bccRecipients,receivedDateTime,sentDateTime,body,uniqueBody,internetMessageHeaders,hasAttachments,attachments,internetMessageId,conversationId,isRead,importance,inferenceClassification"},
        )
        return ok(data)

    elif name == "search_mailbox_messages":
        user_email = arguments["user_email"]
        _require_at_least_one(arguments, ["subject_contains", "from_address", "received_after", "received_before", "has_attachments"])
        clauses = _build_message_filter(arguments)
        params = {
            "$filter": " and ".join(clauses),
            "$select": "id,subject,from,toRecipients,receivedDateTime,hasAttachments,internetMessageId,importance",
            "$top": arguments.get("top", 25),
        }
        if not _forbids_orderby(clauses):
            params["$orderby"] = "receivedDateTime desc"
        data = graph.get(f"/users/{user_email}/messages", params=params)
        return ok(data)

    elif name == "resolve_message_id":
        user_email = arguments["user_email"]
        internet_message_id = arguments["internet_message_id"]
        if not internet_message_id.startswith("<"):
            internet_message_id = f"<{internet_message_id}"
        if not internet_message_id.endswith(">"):
            internet_message_id = f"{internet_message_id}>"
        data = graph.get(f"/users/{user_email}/messages", params={
            "$filter": f"internetMessageId eq '{internet_message_id}'",
            "$select": "id,subject,from,receivedDateTime,internetMessageId",
        })
        return ok(data)

    elif name == "get_email_activity_report":
        period = arguments.get("period", "D30")
        data = graph.get(f"/reports/getEmailActivityUserDetail(period='{period}')")
        return ok(data)

    # ── C. EMAIL ACTIONS ────────────────────────────────────────

    elif name == "delete_emails_by_criteria":
        user_email = arguments["user_email"]
        delete_type = arguments.get("delete_type", "soft")
        dry_run = arguments.get("dry_run", True)
        _validate_enum(delete_type, ["soft", "hard"], "delete_type")
        _require_at_least_one(arguments, ["subject_contains", "from_address", "received_after", "received_before"])

        clauses = _build_message_filter(arguments)
        messages = _search_messages_paged(user_email, clauses, select="id,subject,from,receivedDateTime", max_items=500)

        criteria = {k: arguments.get(k) for k in ["subject_contains", "from_address", "received_after", "received_before"] if arguments.get(k) is not None}
        criteria["user_email"] = user_email
        criteria["delete_type"] = delete_type

        if dry_run:
            what = (
                f"{len(messages)} message(s) in mailbox {user_email} would be "
                f"{'permanently deleted' if delete_type == 'hard' else 'moved to Deleted Items'}."
            )
            extra = {}
            if delete_type == "hard":
                extra["_warning"] = "delete_type=hard is IRREVERSIBLE - messages do not go through Deleted Items."
            return _dry_run_preview(criteria, what, messages, **extra)

        if delete_type == "soft":
            requests_list = [
                {"method": "POST", "url": f"/users/{user_email}/messages/{m['id']}/move", "body": {"destinationId": "deleteditems"}, "headers": {"Content-Type": "application/json"}}
                for m in messages
            ]
        else:
            requests_list = [{"method": "DELETE", "url": f"/users/{user_email}/messages/{m['id']}"} for m in messages]

        result = _graph_batch(requests_list)
        return _executed("delete_emails_by_criteria", {
            "user_email": user_email,
            "delete_type": delete_type,
            "attempted": len(messages),
            "succeeded": result["succeeded"],
            "failed": result["failed"],
        })

    elif name == "delete_emails_bulk_by_subject":
        subject_contains = arguments["subject_contains"]
        from_address = arguments.get("from_address")
        days_back = arguments.get("days_back", 30)
        delete_type = arguments.get("delete_type", "soft")
        dry_run = arguments.get("dry_run", True)
        max_users = arguments.get("max_users", 200)
        _validate_enum(delete_type, ["soft", "hard"], "delete_type")

        received_after = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        clauses = [f"contains(subject,'{subject_contains}')", f"receivedDateTime ge {received_after}"]
        if from_address:
            clauses.append(f"from/emailAddress/address eq '{from_address}'")

        users_data = graph.get("/users", params={
            "$select": "id,userPrincipalName,mail", "$top": max_users,
            "$filter": "mail ne null", "$count": "true",
        }, eventual=True)
        users = users_data.get("value", [])

        per_mailbox = {}
        errors_by_mailbox = {}
        total_found = 0
        total_deleted = 0

        for user in users:
            upn = user.get("userPrincipalName")
            try:
                messages = _search_messages_paged(upn, clauses, select="id,subject,from,receivedDateTime", max_items=500)
            except Exception as ex:
                errors_by_mailbox[upn] = str(ex)
                continue
            if not messages:
                continue
            total_found += len(messages)
            per_mailbox[upn] = {"found": len(messages)}

            if not dry_run:
                if delete_type == "soft":
                    requests_list = [
                        {"method": "POST", "url": f"/users/{upn}/messages/{m['id']}/move", "body": {"destinationId": "deleteditems"}, "headers": {"Content-Type": "application/json"}}
                        for m in messages
                    ]
                else:
                    requests_list = [{"method": "DELETE", "url": f"/users/{upn}/messages/{m['id']}"} for m in messages]
                result = _graph_batch(requests_list)
                per_mailbox[upn]["deleted"] = result["succeeded"]
                total_deleted += result["succeeded"]
                if result["failed"]:
                    errors_by_mailbox[upn] = result["failed"]

        summary = {
            "mode": "DRY_RUN - no email was deleted" if dry_run else "EXECUTED",
            "total_mailboxes_scanned": len(users),
            "mailboxes_with_matches": len(per_mailbox),
            "total_messages_found": total_found,
            "per_mailbox": per_mailbox,
            "errors_by_mailbox": errors_by_mailbox,
        }
        if dry_run:
            summary["next_step"] = "Call with dry_run=False to execute."
        else:
            summary["total_deleted"] = total_deleted
        return ok(summary)

    elif name == "move_email_to_folder":
        user_email = arguments["user_email"]
        message_id = arguments["message_id"]
        destination_folder = arguments.get("destination_folder", "junkemail")
        confirmed = arguments.get("confirmed", False)
        _validate_enum(destination_folder, ["junkemail", "deleteditems", "inbox", "archive"], "destination_folder")

        if not confirmed:
            msg = graph.get(f"/users/{user_email}/messages/{message_id}", params={"$select": "subject,from,receivedDateTime"})
            return _confirm_preview(
                "move_email_to_folder",
                {"user_email": user_email, "message_id": message_id, "destination_folder": destination_folder, "message": msg},
                f"The message will be moved to the '{destination_folder}' folder.",
            )

        result = graph.post(f"/users/{user_email}/messages/{message_id}/move", {"destinationId": destination_folder})
        return _executed("move_email_to_folder", result)

    # ── D. MAILBOX CONFIGURATION ────────────────────────────────────────

    elif name == "disable_mailbox_forwarding":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)

        current = exo.get(f"/Mailbox('{_odata_key(user_email)}')", params={
            "$select": "ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward",
        })
        has_forwarding = bool(current.get("ForwardingAddress") or current.get("ForwardingSmtpAddress"))

        if not has_forwarding:
            return ok({
                "mode": "NO CHANGES - no forwarding is configured on this mailbox",
                "user_email": user_email,
                "current": current,
            })

        if not confirmed:
            return _confirm_preview(
                "disable_mailbox_forwarding",
                {"user_email": user_email, "current_forwarding": current},
                "The forwarding configured on this mailbox will be removed.",
            )

        graph.patch(f"/users/{user_email}/mailboxSettings", {"forwardingSmtpAddress": None, "automaticRepliesSetting": None})
        exo.patch(f"/Mailbox('{_odata_key(user_email)}')", {"ForwardingAddress": None, "ForwardingSmtpAddress": None, "DeliverToMailboxAndForward": False})
        return _executed("disable_mailbox_forwarding", {"user_email": user_email, "forwarding_removed": True})

    elif name == "disable_mailbox_auto_reply":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)

        current = graph.get(f"/users/{user_email}/mailboxSettings", params={"$select": "automaticRepliesSetting"}).get("automaticRepliesSetting", {})
        has_content = current.get("status") != "disabled" or current.get("internalReplyMessage") or current.get("externalReplyMessage")

        if not has_content:
            return ok({
                "mode": "NO CHANGES - no automatic reply is configured on this mailbox",
                "user_email": user_email,
                "current": current,
            })

        if not confirmed:
            return _confirm_preview(
                "disable_mailbox_auto_reply",
                {"user_email": user_email, "current_auto_reply": current},
                "status will be set to 'disabled' and internalReplyMessage/externalReplyMessage will be emptied; the "
                "current content (shown above) is lost, so save it if you need it as evidence.",
            )

        graph.patch(f"/users/{user_email}/mailboxSettings", {
            "automaticRepliesSetting": {
                "status": "disabled",
                "internalReplyMessage": "",
                "externalReplyMessage": "",
            },
        })
        return _executed("disable_mailbox_auto_reply", {"user_email": user_email, "auto_reply_cleared": True, "previous_content": current})

    elif name == "delete_mailbox_rule":
        user_email = arguments["user_email"]
        rule_id = arguments["rule_id"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            rule = graph.get(f"/users/{user_email}/mailFolders/inbox/messageRules/{rule_id}")
            return _confirm_preview(
                "delete_mailbox_rule",
                {"user_email": user_email, "rule_id": rule_id, "rule_name": rule.get("displayName"), "actions": rule.get("actions")},
                "This mailbox rule will be permanently deleted.",
            )

        graph.delete(f"/users/{user_email}/mailFolders/inbox/messageRules/{rule_id}")
        return _executed("delete_mailbox_rule", {"user_email": user_email, "rule_id": rule_id, "deleted": True})

    elif name == "disable_mailbox_rule":
        user_email = arguments["user_email"]
        rule_id = arguments["rule_id"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            rule = graph.get(f"/users/{user_email}/mailFolders/inbox/messageRules/{rule_id}")
            return _confirm_preview(
                "disable_mailbox_rule",
                {"user_email": user_email, "rule_id": rule_id, "rule_name": rule.get("displayName"), "is_enabled": rule.get("isEnabled")},
                "This mailbox rule will be disabled (not deleted).",
            )

        result = graph.patch(f"/users/{user_email}/mailFolders/inbox/messageRules/{rule_id}", {"isEnabled": False})
        return _executed("disable_mailbox_rule", result)

    # ── F. TRANSPORT RULES ───────────────────────────────────────────────

    elif name == "get_transport_rules":
        top = arguments.get("top", 100)
        data = exo.get("/TransportRule", params={"$top": top})
        rules = data.get("value", data) if isinstance(data, dict) else data
        if arguments.get("enabled_only") and isinstance(rules, list):
            rules = [r for r in rules if r.get("State") == "Enabled"]
        return ok(rules)

    elif name == "get_transport_rule_detail":
        identifier = arguments.get("rule_id") or arguments.get("rule_name")
        if not identifier:
            raise ValueError("rule_id or rule_name is required")
        data = exo.get(f"/TransportRule('{_odata_key(identifier)}')")
        return ok(data)

    elif name == "create_transport_rule":
        rule_name = arguments["name"]
        priority = arguments.get("priority", 0)
        conditions = arguments["conditions"]
        actions = arguments["actions"]
        comments = arguments.get("comments")
        mode = arguments.get("mode", "Enforce")
        confirmed = arguments.get("confirmed", False)
        _validate_enum(mode, ["Enforce", "Audit", "AuditAndNotify"], "mode")

        body = {
            "Name": rule_name,
            "Priority": priority,
            "Conditions": conditions,
            "Actions": actions,
            "Comments": comments or "",
            "Mode": mode,
        }

        if not confirmed:
            what = f"Transport rule '{rule_name}' will be created with priority {priority} in {mode} mode."
            if actions.get("DeleteMessage"):
                what += " WARNING: the DeleteMessage action is irreversible for messages that match the rule."
            return _confirm_preview("create_transport_rule", body, what)

        result = exo.post("/TransportRule", body)
        return _executed("create_transport_rule", result)

    elif name == "update_transport_rule":
        rule_id = arguments["rule_id"]
        state = arguments.get("state")
        priority = arguments.get("priority")
        comments = arguments.get("comments")
        confirmed = arguments.get("confirmed", False)
        _validate_enum(state, ["Enabled", "Disabled"], "state")

        current = exo.get(f"/TransportRule('{_odata_key(rule_id)}')")

        if not confirmed:
            changes = {}
            for field, new_value in [("State", state), ("Priority", priority), ("Comments", comments)]:
                if new_value is not None:
                    changes[field] = {"from": current.get(field), "to": new_value}
            return _confirm_preview(
                "update_transport_rule",
                {"rule_id": rule_id, "name": current.get("Name")},
                f"Transport rule '{current.get('Name')}' will be updated.",
                changes=changes,
            )

        body = {k: v for k, v in {"State": state, "Priority": priority, "Comments": comments}.items() if v is not None}
        result = exo.patch(f"/TransportRule('{_odata_key(rule_id)}')", body)
        return _executed("update_transport_rule", result)

    elif name == "delete_transport_rule":
        rule_id = arguments["rule_id"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            rule = exo.get(f"/TransportRule('{_odata_key(rule_id)}')")
            return _confirm_preview(
                "delete_transport_rule",
                {"rule_id": rule_id, "name": rule.get("Name"), "actions": rule.get("Actions")},
                "IRREVERSIBLE - this transport rule will be permanently deleted.",
            )

        exo.delete(f"/TransportRule('{_odata_key(rule_id)}')")
        return _executed("delete_transport_rule", {"rule_id": rule_id, "deleted": True})

    # ── G. CONNECTORS ────────────────────────────────────────────────────

    elif name == "get_inbound_connectors":
        data = exo.get("/InboundConnector")
        return ok(data)

    elif name == "get_outbound_connectors":
        data = exo.get("/OutboundConnector")
        return ok(data)

    # ── H. PROTECTION POLICIES ───────────────────────────────────────

    elif name == "get_antispam_policies":
        data = exo.get("/HostedContentFilterPolicy")
        return ok(data)

    elif name == "get_antiphishing_policies":
        data = exo.get("/AntiPhishPolicy")
        return ok(data)

    elif name == "get_dkim_config":
        data = exo.get("/DkimSigningConfig")
        domain = arguments.get("domain")
        if domain and isinstance(data, dict) and isinstance(data.get("value"), list):
            data = dict(data)
            data["value"] = [d for d in data["value"] if domain.lower() in str(d.get("Domain", "")).lower()]
        return ok(data)

    elif name == "get_blocked_sender_lists":
        spam_lists = exo.get("/HostedContentFilterPolicy", params={"$select": "BlockedSenders,BlockedSenderDomains"})
        ip_lists = exo.get("/HostedConnectionFilterPolicy", params={"$select": "IPBlockList,IPAllowList"})
        return ok({"spam_policy_lists": spam_lists, "connection_filter_lists": ip_lists})

    # ── I. QUARANTINE ────────────────────────────────────────────────────

    elif name == "get_quarantine_messages":
        clauses = []
        if arguments.get("sender_address"):
            clauses.append(f"SenderAddress eq '{arguments['sender_address']}'")
        if arguments.get("recipient_address"):
            clauses.append(f"RecipientAddress eq '{arguments['recipient_address']}'")
        if arguments.get("subject"):
            clauses.append(f"Subject eq '{arguments['subject']}'")
        quarantine_types = arguments.get("quarantine_types") or []
        for qt in quarantine_types:
            _validate_enum(qt, QUARANTINE_TYPES, "quarantine_types")
        if quarantine_types:
            clauses.append("(" + " or ".join(f"QuarantineTypes eq '{qt}'" for qt in quarantine_types) + ")")
        if arguments.get("start_date"):
            clauses.append(f"ReceivedTime ge {arguments['start_date']}")
        if arguments.get("end_date"):
            clauses.append(f"ReceivedTime le {arguments['end_date']}")

        params = {"$top": arguments.get("top", 50)}
        if clauses:
            params["$filter"] = " and ".join(clauses)
        data = compliance.get("/QuarantineMessage", params)
        return ok(data)

    elif name == "release_quarantine_message":
        identity = arguments["identity"]
        release_to = arguments["release_to"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            msg = compliance.get(f"/QuarantineMessage('{_odata_key(identity)}')")
            return _confirm_preview(
                "release_quarantine_message",
                {"identity": identity, "release_to": release_to, "message": msg},
                "The message will be delivered to the recipient's mailbox. Verify that it is not malicious.",
            )

        result = compliance.post(f"/QuarantineMessage('{_odata_key(identity)}')/Release", {"User": release_to})
        return _executed("release_quarantine_message", result)

    elif name == "delete_quarantine_message":
        identity = arguments["identity"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            msg = compliance.get(f"/QuarantineMessage('{_odata_key(identity)}')")
            return _confirm_preview(
                "delete_quarantine_message",
                {"identity": identity, "message": msg},
                "IRREVERSIBLE - the message is permanently deleted and is never delivered to anyone.",
            )

        compliance.delete(f"/QuarantineMessage('{_odata_key(identity)}')")
        return _executed("delete_quarantine_message", {"identity": identity, "deleted": True})

    elif name == "report_quarantine_message":
        identity = arguments["identity"]
        report_as = arguments["report_as"]
        confirmed = arguments.get("confirmed", False)
        _validate_enum(report_as, ["NotJunk", "Phishing", "Malware", "Spam"], "report_as")

        if not confirmed:
            msg = compliance.get(f"/QuarantineMessage('{_odata_key(identity)}')")
            return _confirm_preview(
                "report_quarantine_message",
                {"identity": identity, "report_as": report_as, "message": msg},
                f"This message will be reported to Microsoft as '{report_as}'. "
                "Endpoint not verified; if the tenant responds with an error, consider the "
                "Microsoft Graph Threat Submissions API as the official alternative.",
            )

        result = compliance.post(f"/QuarantineMessage('{_odata_key(identity)}')/Report", {"ReportType": report_as})
        return _executed("report_quarantine_message", result)

    elif name == "get_restricted_senders":
        data = exo.get("/BlockedSenderAddress")
        return ok(data)

    elif name == "unblock_sender":
        sender_address = arguments["sender_address"]
        confirmed = arguments.get("confirmed", False)

        if not confirmed:
            current = exo.get(f"/BlockedSenderAddress('{_odata_key(sender_address)}')")
            return _confirm_preview(
                "unblock_sender",
                {"sender_address": sender_address, "current": current},
                "This mailbox will be removed from the restricted senders list; only do this after confirming "
                "that the cause (leaked password, compromised session) has been remediated.",
            )

        exo.delete(f"/BlockedSenderAddress('{_odata_key(sender_address)}')")
        return _executed("unblock_sender", {"sender_address": sender_address, "unblocked": True})

    # ── K. HELPER: EMAIL CORRELATION ──────────────────────────────

    elif name == "correlate_emails_by_subjects":
        subjects = arguments["subjects"]
        days_back = arguments.get("days_back", 30)
        user_email = arguments.get("user_email")

        subjects_json = ", ".join(json.dumps(s) for s in subjects)
        kql_query = f"""let subjects = dynamic([{subjects_json}]);
EmailEvents
| where Timestamp > ago({days_back}d)
| where Subject has_any (subjects)
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago({days_back}d)
    | summarize UrlDomains=make_set(UrlDomain,20)
        by NetworkMessageId
  ) on NetworkMessageId
| join kind=leftouter (
    EmailAttachmentInfo
    | where Timestamp > ago({days_back}d)
    | summarize AttachmentHashes=make_set(SHA256,10),
                FileNames=make_set(FileName,10)
        by NetworkMessageId
  ) on NetworkMessageId
| summarize
    TotalEmails=count(),
    UniqueRecipients=dcount(RecipientEmailAddress),
    Recipients=make_set(RecipientEmailAddress,50),
    Delivered=countif(DeliveryAction=="Delivered"),
    Blocked=countif(DeliveryAction!="Delivered"),
    Subjects=make_set(Subject,20),
    UrlDomains=make_set(UrlDomains,30),
    AttachmentHashes=make_set(AttachmentHashes,20)
  by SenderFromAddress, SenderFromDomain,
     SenderIPv4, SenderDisplayName,
     AuthenticationDetails
| order by TotalEmails desc"""

        result = {
            "kql_query": kql_query,
            "instructions": (
                "1. Run 'kql_query' with run_kql_hunting in mcp-defender to see, per sender, how many "
                "emails with these subjects arrived, whether they share a sending IP/domain, the "
                "SPF/DKIM/DMARC result (AuthenticationDetails), and common URL domains and attachment hashes.\n"
                "2. If you need raw headers (Received, Message-ID, X-Mailer) of a specific message, use "
                "search_mailbox_messages (or the graph_queries suggested below if you gave user_email) to "
                "obtain its Graph 'id', and pass it to get_email_full_content on this same server."
            ),
            "graph_queries": [
                {"tool": "search_mailbox_messages", "arguments": {"user_email": user_email, "subject_contains": s, "top": 25}}
                for s in subjects
            ] if user_email else [],
        }
        return ok(result)

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
# App registration: sec-exchange-mcp
#
# Microsoft Graph (graph.microsoft.com):
#   Mail.Read              -> B1-B7, email search and reading
#   Mail.ReadWrite         -> C1-C3, delete/move emails
#   MailboxSettings.Read   -> B1, B3, mailbox configuration
#   MailboxSettings.ReadWrite -> D1, disable forwarding / auto-reply
#   User.ReadBasic.All     -> A1, list users with a mailbox
#
# Office 365 Exchange Online (outlook.office365.com, `exo` client):
#   Exchange.ManageAsApp   -> F, G, H, J - everything administrative except Quarantine
#
# Security & Compliance PowerShell (ps.compliance.protection.outlook.com, `compliance`
# client - DIFFERENT host and scope from the above):
#   Exchange.ManageAsApp (same permission, different resource/audience) -> I. QUARANTINE
#
# Do NOT use: full_access_as_app, Mail.Send, Exchange.ManageAsAppV2
#
# WARNING: Exchange.ManageAsApp (Graph consent) ONLY authenticates the app; it
# does not authorize which cmdlets it can run. For that, EXO/Compliance also requires one of:
#   (a) assigning the "Exchange Administrator" directory role (Entra ID) to the
#       app's service principal, or
#   (b) New-ManagementRoleAssignment -App <app_id> -Role "<EXO role>" in
#       Exchange Online PowerShell / Security & Compliance PowerShell (a role
#       matching each group: Transport Rules, Mail Recipients, View-Only Configuration,
#       Transport Hygiene, etc.)
# Without (a) or (b), the corresponding host fails - with 400 "Resource not found for
# the segment 'X'" (the segment does not even appear in the session's OData model if the
# role does not cover it) or with 500 "Could not find the organization container" (seen
# on ps.compliance.protection.outlook.com without the quarantine-capable role). This is NOT
# fixable in code - an admin must run (b) on the corresponding host.
#
# Tools intentionally not provided (no fix possible in code):
#   - Admin audit log search: Search-AdminAuditLog is retired from Exchange Online.
#     The real replacement is the Microsoft Purview Audit API in Graph (async,
#     requires AuditLogsQuery.Read.All).
#   - Message trace: /MessageTrace does not exist on this host; the only functional
#     resource, /HistoricalSearch, is an asynchronous jobs API, and the legacy
#     "Reporting Web Service" (reports.office365.com) has been retired by Microsoft.
#     Use mcp-defender.trace_email_delivery (Advanced Hunting over
#     EmailEvents/EmailPostDeliveryEvents) instead, which covers the same use
#     case synchronously.
# ─────────────────────────────────────────────────────────────
