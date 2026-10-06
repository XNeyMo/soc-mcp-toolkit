"""
MCP Server - Identity (Microsoft Entra ID)

Scope: identity investigation and administration - profile, sign-ins,
audit logs, MFA, sessions, account blocking, password reset, devices,
groups, directory roles, licenses, and Conditional Access policies /
authentication methods.

Requires: pip install -r requirements.txt
Environment variables:
  AZURE_TENANT_ID           (shared across all mcp-* servers)
  IDENTITY_CLIENT_ID        (dedicated app registration for Identity: sec-identity-mcp)
  IDENTITY_CLIENT_SECRET    (per-analyst secret within that app)
  MCP_ANALYST_NAME          (optional; analyst name for the audit log)
  MFA_ENFORCEMENT_GROUP_ID  (object ID of the Conditional Access security group
                             used by enforce_mfa; see MFA_ENFORCEMENT_GROUP_ID below)
"""

import os
import secrets
import string
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.auth import get_token, load_domain_credentials
from shared.graph_client import GraphClient
from shared.mcp_common import ok, audited, require_vault

TENANT_ID, CLIENT_ID, CLIENT_SECRET = load_domain_credentials("IDENTITY")
graph = GraphClient(lambda: get_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET))

server = Server("mcp-identity")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

def _generate_strong_password(length: int = 12) -> str:
    """Strong random password for a reset - IT support hands it to the user in person.

    Generated per call (never static) and only at the moment the reset is executed,
    so every reset gets a different password and none is hardcoded.
    """
    upper, lower, digits = string.ascii_uppercase, string.ascii_lowercase, string.digits
    symbols = "!@#$%^&*()-_=+"
    all_chars = upper + lower + digits + symbols

    chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]

    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)

# MFA enforcement via Conditional Access (security group "SG-MFA-Enforced").
# A Conditional Access policy targets this group and requires MFA for its members, so adding
# a user to the group is the mechanism for both general baseline enforcement and targeted
# containment of a single compromised account (per-user MFA state is deprecated).
# Set MFA_ENFORCEMENT_GROUP_ID in the environment to your group's object ID.
MFA_ENFORCEMENT_GROUP_ID = os.environ.get("MFA_ENFORCEMENT_GROUP_ID", "00000000-0000-0000-0000-000000000000")

USER_SELECT = (
    "id,displayName,userPrincipalName,mail,jobTitle,"
    "department,officeLocation,accountEnabled,"
    "createdDateTime,lastPasswordChangeDateTime,"
    "passwordPolicies,onPremisesSyncEnabled,"
    "onPremisesLastSyncDateTime,assignedLicenses,"
    "usageLocation,employeeId,employeeType,"
    "externalUserState,userType"
)


# Microsoft Graph is inconsistent with the suffix of its @odata.type values: some
# methods use "...AuthenticationMethod" and others (depending on tenant/API version)
# "...AuthMethod". _mfa_canonical_type() strips either suffix so this map works
# regardless of which one the API returns.
MFA_TYPE_NAMES = {
    "password": "Password",
    "microsoftAuthenticator": "Microsoft Authenticator",
    "phone": "Phone/SMS",
    "email": "Email OTP",
    "fido2": "FIDO2 key",
    "windowsHelloForBusiness": "Windows Hello",
    "softwareOath": "TOTP (app)",
    "temporaryAccessPass": "Temporary Access Pass",
}

MFA_DELETE_ENDPOINTS = {
    "microsoftAuthenticator": "microsoftAuthenticatorMethods",
    "phone": "phoneMethods",
    "email": "emailMethods",
    "fido2": "fido2Methods",
    "softwareOath": "softwareOathMethods",
    "temporaryAccessPass": "temporaryAccessPassMethods",
    "windowsHelloForBusiness": "windowsHelloForBusinessMethods",
}

SENSITIVE_ROLES = ["Global Administrator", "Privileged Role Administrator", "Security Administrator"]

LICENSE_NAMES = {
    "SPE_E3": "Microsoft 365 E3",
    "SPE_E5": "Microsoft 365 E5",
    "ENTERPRISEPACK": "Office 365 E3",
    "ENTERPRISEPREMIUM": "Office 365 E5",
    "STANDARDPACK": "Office 365 E1",
    "AAD_PREMIUM": "Entra ID P1",
    "AAD_PREMIUM_P2": "Entra ID P2",
    "EMS": "EMS E3",
    "EMSPREMIUM": "EMS E5",
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "SPB": "Microsoft 365 Business Premium",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_user(user_email: str) -> dict:
    return graph.get(f"/users/{user_email}", params={"$select": USER_SELECT})


def _validate_enum(value, allowed: list, field_name: str) -> None:
    if value is not None and value not in allowed:
        raise ValueError(
            f"'{value}' is not valid for {field_name}. Allowed values: {allowed}"
        )


def _mfa_canonical_type(odata_type: str) -> str:
    short = (odata_type or "").lstrip("#").split(".")[-1]
    for suffix in ("AuthenticationMethod", "AuthMethod"):
        if short.endswith(suffix):
            return short[: -len(suffix)]
    return short


def _mfa_label(odata_type: str) -> str:
    canonical = _mfa_canonical_type(odata_type)
    return MFA_TYPE_NAMES.get(canonical, canonical)


def _license_label(sku_part_number: str) -> str:
    return LICENSE_NAMES.get(sku_part_number, sku_part_number)


def _preview(action: str, target: dict, what_would_happen: str, **extra):
    payload = {
        "mode": "PREVIEW - action NOT executed",
        "action": action,
        "target": target,
        "what_would_happen": what_would_happen,
    }
    payload.update(extra)
    payload["next_step"] = "Call again with confirmed=True to execute."
    return ok(payload)


def _executed(action: str, target_upn: str, result):
    return ok({
        "mode": "EXECUTED",
        "action": action,
        "target_upn": target_upn,
        "result": result,
    })


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools():
    return [

        # ── A. USER INVESTIGATION ───────────────────────────────────────────

        types.Tool(
            name="investigate_user",
            description=(
                "Complete summary of a user: profile, groups, roles, registered devices, "
                "MFA methods, and licenses. Entry point for any user-centric "
                "investigation."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_mfa_coverage",
            description=(
                "MFA coverage percentage across the tenant (or a department). Makes N+1 requests "
                "(one per user) - can be slow with a high 'top'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "department": {"type": "string"},
                    "top": {"type": "integer", "default": 100},
                },
            },
        ),

        # ── B1. SIGN-INS ─────────────────────────────────────────────────────

        types.Tool(
            name="get_user_signin_history",
            description=(
                "Sign-in history for a user: IP, location, device, application, "
                "result, applied Conditional Access policies, and failure reason. Does not include which MFA "
                "method was used (authenticationDetails) - Graph rejects that property in $select with a 400 "
                "'Unsupported Query' on this tenant; use get_user_mfa_methods to see registered methods.\n"
                "- Without start_date/end_date, returns the 'top' MOST RECENT sign-ins (not a range) - if the account "
                "has recent noise (e.g. password spray), those 'top' results may ALL be from the last few "
                "days and never reach the date of the incident being investigated. When investigating an incident "
                "from a specific date, pass start_date/end_date bounded to that date instead of relying on the default.\n"
                "- This endpoint typically retains only ~30 days of history (a tenant limit, not a limit of this "
                "tool) - if the incident is older, finding nothing here is expected; do not read it "
                "as 'no activity', report it as 'outside the retention window'."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "start_date": {"type": "string", "description": "ISO 8601 (e.g. 2026-03-24T00:00:00Z). If omitted, no lower bound is applied."},
                    "end_date": {"type": "string", "description": "ISO 8601. If omitted, no upper bound is applied."},
                    "top": {"type": "integer", "default": 50},
                    "failed_only": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── B2-B3. AUDIT ─────────────────────────────────────────────────────

        types.Tool(
            name="get_user_activity_timeline",
            description=(
                "Audit Logs timeline: actions the user INITIATED and actions OTHERS "
                "performed ON their account (the _direction field distinguishes each case). Key for detecting "
                "post-compromise persistence."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "days_back": {"type": "integer", "default": 30},
                    "top": {"type": "integer", "default": 100},
                    "category": {"type": "string", "enum": ["UserManagement", "GroupManagement", "RoleManagement", "ApplicationManagement", "Authentication", "Policy", "Other"]},
                },
            },
        ),

        types.Tool(
            name="get_signin_stats",
            description=(
                "Aggregated sign-in statistics for a user over a period: failure rate, unique IPs/countries, "
                "apps, and suspicious patterns (impossible travel, high failure rate)."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "days_back": {"type": "integer", "default": 30},
                },
            },
        ),

        # ── D. MFA ───────────────────────────────────────────────────────────

        types.Tool(
            name="get_user_mfa_methods",
            description="Authentication methods registered by the user, with readable type and detail.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="revoke_mfa_methods",
            description=(
                "⚠️ Removes MFA methods from a user (never the password). If method_ids is not given, removes "
                "ALL methods except the password. confirmed=False (default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "method_ids": {"type": "array", "items": {"type": "string"}},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="enforce_mfa",
            description=(
                "⚠️ Enforces MFA by adding the user to the 'SG-MFA-Enforced' security group "
                "(Conditional Access) - replaces the legacy per-user MFA mechanism "
                "(perUserMfaState), which is deprecated. The user will have to complete "
                "MFA registration/use at their next sign-in. "
                "confirmed=False (default) shows the preview; confirmed=True executes."
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
            name="remove_single_mfa_method",
            description=(
                "⚠️ Removes EXACTLY one MFA method (never the password), identified by its method_id "
                "(see get_user_mfa_methods). Unlike revoke_mfa_methods (meant to clear all "
                "methods and force a full re-registration), this tool requires a single id - useful when only ONE "
                "method is suspicious (e.g. an unrecognized phone) and the others must not be touched. "
                "confirmed=False (default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email", "method_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "method_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="set_default_mfa_method",
            description=(
                "⚠️ Changes the user's DEFAULT secondary authentication method (signInPreferences, "
                "beta API) - required before the method that is currently the default can be removed (Graph rejects "
                "deleting a method while it is still marked as default). Uses a beta endpoint; verify its "
                "behavior against your tenant before relying on it. confirmed=False (default) shows the preview "
                "with the current default; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email", "method"],
                "properties": {
                    "user_email": {"type": "string"},
                    "method": {
                        "type": "string",
                        "enum": ["push", "oath", "voiceMobile", "voiceAlternateMobile", "voiceOffice", "sms"],
                        "description": "push=Microsoft Authenticator, oath=TOTP/software token, sms/voice*=phone",
                    },
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── E. SESSIONS ──────────────────────────────────────────────────────

        types.Tool(
            name="revoke_user_sessions",
            description=(
                "⚠️ Invalidates ALL of the user's refresh tokens - they will have to sign in again on all their "
                "devices and applications. confirmed=False (default) shows the preview with recent "
                "sessions; confirmed=True executes."
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

        # ── F. ACCOUNT BLOCKING ──────────────────────────────────────────────

        types.Tool(
            name="block_user",
            description="⚠️ Disables the user account (accountEnabled=False). confirmed=False (default) shows the preview; confirmed=True executes.",
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
            name="unblock_user",
            description="Re-enables the user account (accountEnabled=True). If it is already active, reports that and does nothing. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── G. PASSWORD ──────────────────────────────────────────────────────

        types.Tool(
            name="reset_user_password",
            description=(
                "⚠️ Sets a strong random 12-character password (upper case, lower case, digits "
                "and symbols, generated on the fly - not a fixed value) with forceChangePasswordNextSignIn=True. "
                "The generated password is returned in the execution result so IT support can hand it to the "
                "user in person. For accounts synced from on-premises AD, the reset only takes real effect if "
                "password writeback is enabled (otherwise reset it there). confirmed=False (default) shows "
                "the preview without generating any password; confirmed=True generates the password and executes."
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

        # ── H. DEVICES ───────────────────────────────────────────────────────

        types.Tool(
            name="get_user_devices",
            description="Devices registered to and/or owned by the user, deduplicated, with an _ownership field.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "include_registered": {"type": "boolean", "default": True},
                    "include_owned": {"type": "boolean", "default": True},
                },
            },
        ),

        # ── I. GROUPS ────────────────────────────────────────────────────────

        types.Tool(
            name="get_user_groups",
            description="Groups the user is a member of. security_only filters to static security groups only.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {
                    "user_email": {"type": "string"},
                    "security_only": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="add_user_to_group",
            description="Adds a user to a group. confirmed=False (default) shows the preview (including whether the user is already a member); confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "group_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "group_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="remove_user_from_group",
            description="Removes a user from a group. If the user is not a member, reports that and does nothing. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "group_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "group_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="list_groups",
            description=(
                "Lists/searches tenant groups by name (displayName contains). Without 'query', lists the "
                "first 'top' security groups. Useful for finding a group's group_id by name "
                "(e.g. SG-MFA-Enforced) instead of discovering it by chance through a specific user."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Substring of the displayName to search for"},
                    "security_only": {"type": "boolean", "default": True},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="get_group",
            description=(
                "Group detail by id: metadata, type, and ALL of its members - paginates automatically "
                "via @odata.nextLink (pages of 999, the Graph maximum), not limited to a single page. "
                "max_members caps how many are returned (default 2000, to avoid flooding the conversation "
                "with a huge dynamic group by accident); pass 0 or a negative value to fetch ALL without "
                "a limit. If the group has more members than max_members, _members_truncated=true indicates it."
            ),
            inputSchema={
                "type": "object",
                "required": ["group_id"],
                "properties": {
                    "group_id": {"type": "string"},
                    "max_members": {"type": "integer", "default": 2000, "description": "0 or negative = no limit"},
                },
            },
        ),

        types.Tool(
            name="create_group",
            description=(
                "⚠️ Creates a static security group (securityEnabled=true, mailEnabled=false) - e.g. as an "
                "anchor for a new Conditional Access policy. The preview warns if a group with the same "
                "displayName already exists, so you do not create a duplicate unknowingly. confirmed=False "
                "(default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["display_name"],
                "properties": {
                    "display_name": {"type": "string"},
                    "description": {"type": "string"},
                    "mail_nickname": {"type": "string", "description": "If omitted, derived from display_name (alphanumeric characters only)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── J. ROLES ─────────────────────────────────────────────────────────

        types.Tool(
            name="get_user_roles",
            description="Directory roles assigned to a user (Global Admin, Security Reader, Helpdesk Admin, etc.).",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_available_roles",
            description="Lists all directory roles activated in the tenant, with their id (useful before assigning/removing).",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="assign_directory_role",
            description=(
                "⚠️ Assigns a directory role to a user. Warns if the role is highly privileged "
                "(Global/Privileged Role/Security Administrator). confirmed=False (default) shows the "
                "preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email", "role_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "role_id": {"type": "string", "description": "id of the directoryRole (not the roleTemplate)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="remove_directory_role",
            description=(
                "⚠️ Removes a directory role from a user. Warns if the user appears to be the LAST "
                "Global Administrator of the tenant. confirmed=False (default) shows the preview; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_email", "role_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "role_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="get_role_members",
            description="CURRENT members (direct assignment, not PIM) of a directory role - the inverse census of get_user_roles.",
            inputSchema={
                "type": "object",
                "required": ["role_id"],
                "properties": {"role_id": {"type": "string", "description": "id of the activated directoryRole (see get_available_roles)"}},
            },
        ),

        types.Tool(
            name="get_pim_role_assignments",
            description=(
                "PIM assignments of a role: eligible (must be activated before using the role) and active/"
                "permanent, via roleEligibilityScheduleInstances/roleAssignmentScheduleInstances. NOTE: uses "
                "the role's roleTemplateId (the 'roleTemplateId' field from get_available_roles), NOT the "
                "directoryRole id used by get_role_members/assign_directory_role - in Graph these are two "
                "different values for the same role."
            ),
            inputSchema={
                "type": "object",
                "required": ["role_template_id"],
                "properties": {"role_template_id": {"type": "string"}},
            },
        ),

        # ── K. LICENSES ──────────────────────────────────────────────────────

        types.Tool(
            name="get_user_licenses",
            description="Licenses assigned to a user (with servicePlans) and the tenant SKU inventory, with readable names.",
            inputSchema={
                "type": "object",
                "required": ["user_email"],
                "properties": {"user_email": {"type": "string"}},
            },
        ),

        types.Tool(
            name="assign_license",
            description="⚠️ Assigns a license to a user. Checks availability before executing. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "sku_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "sku_id": {"type": "string", "description": "SKU GUID"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="remove_license",
            description="Removes a license from a user. If the user does not have it, reports that and does nothing. confirmed=False (default) shows the preview; confirmed=True executes.",
            inputSchema={
                "type": "object",
                "required": ["user_email", "sku_id"],
                "properties": {
                    "user_email": {"type": "string"},
                    "sku_id": {"type": "string"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── L. CONDITIONAL ACCESS ────────────────────────────────────────────

        types.Tool(
            name="get_conditional_access_policies",
            description="Lists the tenant Conditional Access policies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "state": {"type": "string", "enum": ["enabled", "disabled", "enabledForReportingButNotEnforced"]},
                },
            },
        ),

        types.Tool(
            name="get_auth_methods_policy",
            description="Tenant authentication methods policy: which methods are enabled, for which users/groups, and SSPR state.",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="get_mfa_registration_policy",
            description="Granular configuration per authentication method (Authenticator, SMS, FIDO2, TAP, etc.) - complements get_auth_methods_policy.",
            inputSchema={"type": "object", "properties": {}},
        ),

        types.Tool(
            name="create_conditional_access_policy",
            description=(
                "⚠️ Creates a new Conditional Access policy. 'policy' is the complete JSON body exactly "
                "as Graph expects it (displayName, state, conditions, grantControls, sessionControls, etc. - "
                "see the conditionalAccessPolicy resource in the Graph documentation). The content is not "
                "validated beyond what Graph itself rejects. confirmed=False (default) shows the "
                "preview with displayName/state; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["policy"],
                "properties": {
                    "policy": {"type": "object", "description": "Complete JSON body of the policy (Graph conditionalAccessPolicy resource)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        types.Tool(
            name="update_conditional_access_policy",
            description=(
                "⚠️ Updates (partial PATCH) an existing Conditional Access policy - including "
                "enabling/disabling by passing policy={'state': 'enabled'|'disabled'|'enabledForReportingButNotEnforced'} "
                "or any other field to modify. confirmed=False (default) shows the preview with the "
                "policy's current state and the fields that would change; confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["policy_id", "policy"],
                "properties": {
                    "policy_id": {"type": "string"},
                    "policy": {"type": "object", "description": "Fields to modify (partial PATCH, conditionalAccessPolicy resource)"},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── M. IDENTITY PROTECTION (RISK) ───────────────────────────────────

        types.Tool(
            name="get_risky_users",
            description="Lists users flagged as risky by Identity Protection (riskState, riskLevel, riskLastUpdatedDateTime).",
            inputSchema={
                "type": "object",
                "properties": {
                    "risk_state": {"type": "string", "enum": ["atRisk", "confirmedSafe", "remediated", "dismissed", "confirmedCompromised", "unknownFutureValue"]},
                    "risk_level": {"type": "string", "enum": ["low", "medium", "high", "none", "unknownFutureValue"]},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="get_risk_detections",
            description="Identity Protection risk detections (riskEventType, riskLevel, location, IP), optionally filtered by user.",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_email": {"type": "string"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="dismiss_risky_users",
            description=(
                "⚠️ Dismisses the risk of one or more users that are already contained/remediated - clears their "
                "state in the Identity Protection dashboard. Different from 'confirm safe': dismiss is "
                "the right action when the analyst has already contained the account by other means (password reset, "
                "session revocation, MFA) and only needs to reflect that in the risk dashboard. "
                "confirmed=False (default) shows the preview with each user's current risk; "
                "confirmed=True executes."
            ),
            inputSchema={
                "type": "object",
                "required": ["user_emails"],
                "properties": {
                    "user_emails": {"type": "array", "items": {"type": "string"}},
                    "confirmed": {"type": "boolean", "default": False},
                },
            },
        ),

        # ── N. APPLICATIONS / OAUTH CONSENTS ────────────────────────────────

        types.Tool(
            name="list_service_principals",
            description="Searches enterprise applications (service principals) by name. Without 'query', lists the first 'top'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Substring of the displayName to search for"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        types.Tool(
            name="get_service_principal_details",
            description=(
                "Detail of an enterprise application: metadata, granted application permissions "
                "(appRoleAssignments), and delegated consents (oauth2PermissionGrants) where this app is "
                "the client."
            ),
            inputSchema={
                "type": "object",
                "required": ["service_principal_id"],
                "properties": {"service_principal_id": {"type": "string"}},
            },
        ),

        types.Tool(
            name="get_oauth_consents",
            description=(
                "Inventory of the tenant's delegated OAuth consents (oauth2PermissionGrants) - which "
                "application holds which delegated permissions and on whose behalf. Filter by app (client_id) and/or "
                "by the consenting user (user_email); without filters, lists the first 'top' of the tenant."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "id (objectId) of the service principal that received the consent"},
                    "user_email": {"type": "string", "description": "user who granted the consent (consentType=Principal)"},
                    "top": {"type": "integer", "default": 50},
                },
            },
        ),

        # ── O. SECURE SCORE ──────────────────────────────────────────────────

        types.Tool(
            name="get_secure_score",
            description=(
                "Microsoft Secure Score for the tenant (currentScore/maxScore + controlScores by category). "
                "Graph does not expose a separate 'Identity Secure Score': it is the subset of controlScores with "
                "controlCategory='Identity' within this same response - no other tool is needed and nothing "
                "is filtered server-side; inspect that field in the result."
            ),
            inputSchema={
                "type": "object",
                "properties": {"top": {"type": "integer", "default": 1, "description": "How many historical measurements to fetch (1 = only the most recent)"}},
            },
        ),

    ]


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("identity")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    # ── A. USER INVESTIGATION ───────────────────────────────────────────

    if name == "investigate_user":
        user_email = arguments["user_email"]
        profile = _resolve_user(user_email)

        try:
            groups_list = graph.get(f"/users/{user_email}/memberOf", params={"$select": "id,displayName,groupTypes"}).get("value", [])
        except Exception:
            groups_list = []
        try:
            roles_list = graph.get(f"/users/{user_email}/transitiveMemberOf/microsoft.graph.directoryRole", params={"$select": "displayName,description"}).get("value", [])
        except Exception:
            roles_list = []
        try:
            devices_list = graph.get(f"/users/{user_email}/registeredDevices", params={"$select": "id,displayName,operatingSystem,isCompliant,isManaged,trustType"}).get("value", [])
        except Exception:
            devices_list = []
        try:
            mfa_methods = graph.get(f"/users/{user_email}/authentication/methods").get("value", [])
        except Exception:
            mfa_methods = []
        try:
            license_list = graph.get(f"/users/{user_email}/licenseDetails", params={"$select": "id,skuId,skuPartNumber,servicePlans"}).get("value", [])
        except Exception:
            license_list = []

        return ok({
            "profile": profile,
            "groups": groups_list,
            "directory_roles": roles_list,
            "registered_devices": devices_list,
            "mfa_methods_count": len(mfa_methods),
            "mfa_methods": mfa_methods,
            "license_details": license_list,
            "account_enabled": profile.get("accountEnabled"),
        })

    elif name == "get_mfa_coverage":
        department = arguments.get("department")
        top = arguments.get("top", 100)
        filter_clause = f"department eq '{department}'" if department else "accountEnabled eq true"
        users = graph.get("/users", params={
            "$select": "id,displayName,userPrincipalName,department,accountEnabled",
            "$top": top,
            "$filter": filter_clause,
        }).get("value", [])

        with_mfa = 0
        without_mfa = 0
        users_without_mfa = []
        for u in users:
            try:
                methods = graph.get(f"/users/{u['id']}/authentication/methods").get("value", [])
            except Exception:
                methods = []
            if len(methods) >= 2:
                with_mfa += 1
            else:
                without_mfa += 1
                users_without_mfa.append({"upn": u.get("userPrincipalName"), "displayName": u.get("displayName"), "department": u.get("department")})

        total = len(users)
        result = {
            "total_users": total,
            "with_mfa": with_mfa,
            "without_mfa": without_mfa,
            "coverage_percent": round((with_mfa / total * 100), 2) if total else 0.0,
            "users_without_mfa": users_without_mfa,
        }
        if total > 50:
            result["_note"] = f"Made {total} additional requests (one per user) to read MFA methods - may be slow with a high 'top'."
        return ok(result)

    # ── B1. SIGN-INS ─────────────────────────────────────────────────────

    elif name == "get_user_signin_history":
        user_email = arguments["user_email"]
        top = arguments.get("top", 50)
        filter_clauses = [f"userPrincipalName eq '{user_email}'"]
        if arguments.get("start_date"):
            filter_clauses.append(f"createdDateTime ge {arguments['start_date']}")
        if arguments.get("end_date"):
            filter_clauses.append(f"createdDateTime le {arguments['end_date']}")
        if arguments.get("failed_only"):
            filter_clauses.append("status/errorCode ne 0")
        params = {
            "$filter": " and ".join(filter_clauses),
            "$top": top,
            # 'authenticationDetails' is deliberately excluded: Graph returns 400 "Unsupported Query" as soon as
            # it appears in $select, with or without $filter/$orderby - it is not supported here,
            # contrary to what the beta documentation suggests.
            "$select": "id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,location,deviceDetail,status,conditionalAccessStatus,appliedConditionalAccessPolicies",
        }
        # $orderby is only valid on a property present in $filter - without start_date/
        # end_date, createdDateTime is not in $filter and Graph rejects the orderby with
        # "Unsupported Query"; the API already returns sign-ins in reverse chronological order
        # by default in that case, so it is not needed.
        if arguments.get("start_date") or arguments.get("end_date"):
            params["$orderby"] = "createdDateTime desc"
        data = graph.get("/auditLogs/signIns", params, beta=True)
        results = data.get("value", [])
        if len(results) >= top and not (arguments.get("start_date") or arguments.get("end_date")):
            data["_warning"] = (
                f"Reached 'top'={top} without a date bound - these are the {top} MOST RECENT sign-ins, "
                "not necessarily the range you are looking for. If you are investigating a specific date, call again with "
                "start_date/end_date bounded to that date."
            )
        return ok(data)

    # ── B2-B3. AUDIT ─────────────────────────────────────────────────────

    elif name == "get_user_activity_timeline":
        user_email = arguments["user_email"]
        days_back = arguments.get("days_back", 30)
        top = arguments.get("top", 100)
        category = arguments.get("category")
        _validate_enum(category, ["UserManagement", "GroupManagement", "RoleManagement", "ApplicationManagement", "Authentication", "Policy", "Other"], "category")

        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        select = "id,activityDateTime,activityDisplayName,category,result,resultReason,initiatedBy,targetResources,additionalDetails"

        filter_initiated = f"initiatedBy/user/userPrincipalName eq '{user_email}' and activityDateTime ge {since}"
        filter_target = f"targetResources/any(t:t/userPrincipalName eq '{user_email}') and activityDateTime ge {since}"
        if category:
            filter_initiated += f" and category eq '{category}'"
            filter_target += f" and category eq '{category}'"

        try:
            initiated = graph.get("/auditLogs/directoryAudits", params={"$filter": filter_initiated, "$top": top, "$select": select}).get("value", [])
            target = graph.get("/auditLogs/directoryAudits", params={"$filter": filter_target, "$top": top, "$select": select}).get("value", [])
        except RuntimeError as e:
            if "Minimum allowed time" in str(e):
                raise ValueError(
                    f"days_back={days_back} asks for events older than the Entra audit log retention limit "
                    "of this tenant (typically ~30 days with a standard license). This is not a query error: "
                    "Microsoft simply does not keep older events on this endpoint. Reduce days_back, or if "
                    "you need older history, check whether export to Sentinel/Log Analytics is configured."
                ) from e
            raise
        for e in initiated:
            e["_direction"] = "initiated_by_user"
        for e in target:
            e["_direction"] = "action_on_user"

        combined = {}
        for e in initiated + target:
            combined[e["id"]] = e
        events = sorted(combined.values(), key=lambda e: e.get("activityDateTime", ""), reverse=True)[:top]

        return ok({"count": len(events), "events": events})

    elif name == "get_signin_stats":
        user_email = arguments["user_email"]
        days_back = arguments.get("days_back", 30)
        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 'authenticationDetails' is deliberately excluded from $select: Graph returns 400 "Unsupported Query"
        # as soon as it appears, regardless of the rest of the query. For that reason
        # mfa_used_count cannot be computed here.
        signins = graph.get("/auditLogs/signIns", params={
            "$filter": f"userPrincipalName eq '{user_email}' and createdDateTime ge {since}",
            "$top": 1000,
            "$orderby": "createdDateTime desc",
            "$select": "createdDateTime,ipAddress,location,appDisplayName,status",
        }, beta=True).get("value", [])

        total = len(signins)
        successful = sum(1 for s in signins if (s.get("status") or {}).get("errorCode") == 0)
        failed = total - successful
        failure_rate = round((failed / total * 100), 2) if total else 0.0
        unique_ips = {s.get("ipAddress") for s in signins if s.get("ipAddress")}
        unique_countries = sorted({
            (s.get("location") or {}).get("countryOrRegion")
            for s in signins if (s.get("location") or {}).get("countryOrRegion")
        })
        apps = sorted({s.get("appDisplayName") for s in signins if s.get("appDisplayName")})
        dates = [s.get("createdDateTime") for s in signins if s.get("createdDateTime")]
        first_signin = min(dates) if dates else None
        last_signin = max(dates) if dates else None

        successful_signins = sorted(
            [s for s in signins if (s.get("status") or {}).get("errorCode") == 0 and s.get("createdDateTime")],
            key=lambda s: s["createdDateTime"],
        )
        impossible_travel = False
        for i in range(1, len(successful_signins)):
            prev, curr = successful_signins[i - 1], successful_signins[i]
            prev_country = (prev.get("location") or {}).get("countryOrRegion")
            curr_country = (curr.get("location") or {}).get("countryOrRegion")
            if prev_country and curr_country and prev_country != curr_country:
                try:
                    t_prev = datetime.fromisoformat(prev["createdDateTime"].replace("Z", "+00:00"))
                    t_curr = datetime.fromisoformat(curr["createdDateTime"].replace("Z", "+00:00"))
                    if abs((t_curr - t_prev).total_seconds()) < 2 * 3600:
                        impossible_travel = True
                        break
                except Exception:
                    pass

        return ok({
            "user": user_email,
            "period_days": days_back,
            "total_signins": total,
            "successful": successful,
            "failed": failed,
            "failure_rate_percent": failure_rate,
            "unique_ips": len(unique_ips),
            "unique_countries": unique_countries,
            "apps_accessed": apps,
            "first_signin": first_signin,
            "last_signin": last_signin,
            "suspicious_patterns": {
                "impossible_travel": impossible_travel,
                "new_countries": unique_countries,
                "high_failure_rate": failure_rate > 30,
            },
        })

    # ── D. MFA ───────────────────────────────────────────────────────────

    elif name == "get_user_mfa_methods":
        user_email = arguments["user_email"]
        methods = graph.get(f"/users/{user_email}/authentication/methods").get("value", [])
        formatted = [{
            "id": m.get("id"),
            "type": _mfa_label(m.get("@odata.type", "")),
            "odata_type": m.get("@odata.type", ""),
            "detail": m.get("displayName") or m.get("phoneNumber") or m.get("emailAddress") or "",
            "created": m.get("createdDateTime"),
        } for m in methods]
        has_mfa = any(_mfa_canonical_type(m.get("@odata.type", "")) != "password" for m in methods)
        return ok({"user": user_email, "total_methods": len(methods), "has_mfa": has_mfa, "methods": formatted})

    elif name == "revoke_mfa_methods":
        user_email = arguments["user_email"]
        method_ids = arguments.get("method_ids")
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        methods = graph.get(f"/users/{user_email}/authentication/methods").get("value", [])

        to_remove = []
        for m in methods:
            canonical = _mfa_canonical_type(m.get("@odata.type", ""))
            if canonical == "password":
                continue
            if method_ids and m.get("id") not in method_ids:
                continue
            to_remove.append(m)

        if not confirmed:
            preview_list = [{"id": m.get("id"), "type": _mfa_label(m.get("@odata.type", ""))} for m in to_remove]
            return _preview(
                "revoke_mfa_methods",
                {"user_email": user_email, "methods_to_remove": preview_list},
                f"{len(preview_list)} MFA method(s) will be removed. The password is never removed.",
            )

        removed, failed = [], []
        for m in to_remove:
            canonical = _mfa_canonical_type(m.get("@odata.type", ""))
            endpoint_segment = MFA_DELETE_ENDPOINTS.get(canonical)
            label = _mfa_label(m.get("@odata.type", ""))
            if not endpoint_segment:
                failed.append({"id": m.get("id"), "type": label, "error": "method type not supported for removal"})
                continue
            try:
                graph.delete(f"/users/{user_id}/authentication/{endpoint_segment}/{m['id']}")
                removed.append({"id": m.get("id"), "type": label})
            except Exception as e:
                failed.append({"id": m.get("id"), "type": label, "error": str(e)})

        return _executed("revoke_mfa_methods", user_email, {"removed": removed, "failed": failed})

    elif name == "enforce_mfa":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)
        user = _resolve_user(user_email)
        user_id = user["id"]

        check = graph.post(f"/users/{user_id}/checkMemberGroups", {"groupIds": [MFA_ENFORCEMENT_GROUP_ID]})
        already_member = MFA_ENFORCEMENT_GROUP_ID in check.get("value", [])

        if not confirmed:
            what = (
                "The user is already a member of SG-MFA-Enforced - no change would be made."
                if already_member else
                f"{user_email} will be added to the 'SG-MFA-Enforced' group (Conditional Access), enforcing MFA "
                "at their next sign-in."
            )
            return _preview(
                "enforce_mfa",
                {"user_email": user_email, "group_id": MFA_ENFORCEMENT_GROUP_ID, "already_member": already_member},
                what,
            )

        if already_member:
            return ok({"mode": "NO CHANGE - the user is already a member of SG-MFA-Enforced", "user_email": user_email})

        graph.post(f"/groups/{MFA_ENFORCEMENT_GROUP_ID}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"})
        return _executed("enforce_mfa", user_email, {"group_id": MFA_ENFORCEMENT_GROUP_ID, "group_name": "SG-MFA-Enforced", "added": True})

    elif name == "remove_single_mfa_method":
        user_email = arguments["user_email"]
        method_id = arguments["method_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        methods = graph.get(f"/users/{user_email}/authentication/methods").get("value", [])
        target = next((m for m in methods if m.get("id") == method_id), None)
        if not target:
            raise ValueError(f"method_id '{method_id}' does not exist among the MFA methods of {user_email}")
        canonical = _mfa_canonical_type(target.get("@odata.type", ""))
        if canonical == "password":
            raise ValueError("The password cannot be removed with this tool.")
        label = _mfa_label(target.get("@odata.type", ""))
        endpoint_segment = MFA_DELETE_ENDPOINTS.get(canonical)
        if not endpoint_segment:
            raise ValueError(f"Method type '{label}' is not supported for individual removal.")

        if not confirmed:
            return _preview(
                "remove_single_mfa_method",
                {
                    "user_email": user_email,
                    "method_id": method_id,
                    "type": label,
                    "detail": target.get("displayName") or target.get("phoneNumber") or target.get("emailAddress") or "",
                },
                f"ONLY this method ({label}) will be removed. The user's other MFA methods are not touched.",
            )

        graph.delete(f"/users/{user_id}/authentication/{endpoint_segment}/{method_id}")
        return _executed("remove_single_mfa_method", user_email, {"method_id": method_id, "type": label, "removed": True})

    elif name == "set_default_mfa_method":
        user_email = arguments["user_email"]
        method = arguments["method"]
        confirmed = arguments.get("confirmed", False)
        _validate_enum(method, ["push", "oath", "voiceMobile", "voiceAlternateMobile", "voiceOffice", "sms"], "method")

        user = _resolve_user(user_email)
        user_id = user["id"]
        try:
            current = graph.get(f"/users/{user_id}/authentication/signInPreferences", beta=True)
            current_default = current.get("userPreferredMethodForSecondaryAuthentication")
        except Exception:
            current_default = None

        if not confirmed:
            return _preview(
                "set_default_mfa_method",
                {"user_email": user_email, "current_default": current_default, "new_default": method},
                f"The default MFA method of {user_email} will be changed to '{method}'.",
            )

        result = graph.patch(
            f"/users/{user_id}/authentication/signInPreferences",
            {"userPreferredMethodForSecondaryAuthentication": method},
            beta=True,
        )
        return _executed("set_default_mfa_method", user_email, result or {"userPreferredMethodForSecondaryAuthentication": method})

    # ── E. SESSIONS ──────────────────────────────────────────────────────

    elif name == "revoke_user_sessions":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)
        user = _resolve_user(user_email)
        user_id = user["id"]

        if not confirmed:
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            signins = graph.get("/auditLogs/signIns", params={
                "$filter": f"userPrincipalName eq '{user_email}' and createdDateTime ge {since}",
                "$top": 10,
                "$select": "appDisplayName,ipAddress,location,createdDateTime,status",
            }).get("value", [])
            return _preview(
                "revoke_user_sessions",
                {"user_email": user_email, "recent_signins_24h": signins},
                "This invalidates ALL refresh tokens. The user will have to sign in again on all their devices and applications.",
            )

        result = graph.post(f"/users/{user_id}/revokeSignInSessions", {})
        return _executed("revoke_user_sessions", user_email, result)

    # ── F. ACCOUNT BLOCKING ──────────────────────────────────────────────

    elif name == "block_user":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)
        user = _resolve_user(user_email)
        user_id = user["id"]

        if not confirmed:
            return _preview(
                "block_user",
                {"user_email": user_email, "accountEnabled": user.get("accountEnabled"), "jobTitle": user.get("jobTitle"), "department": user.get("department")},
                "The user will not be able to sign in until manually unblocked.",
            )

        result = graph.patch(f"/users/{user_id}", {"accountEnabled": False})
        return _executed("block_user", user_email, result or {"accountEnabled": False})

    elif name == "unblock_user":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)
        user = _resolve_user(user_email)
        user_id = user["id"]

        if user.get("accountEnabled"):
            return ok({"mode": "NO CHANGE - the user is already active (accountEnabled=True)", "user_email": user_email})

        if not confirmed:
            return _preview(
                "unblock_user",
                {"user_email": user_email, "accountEnabled": user.get("accountEnabled")},
                "The user's access will be re-enabled.",
            )

        result = graph.patch(f"/users/{user_id}", {"accountEnabled": True})
        return _executed("unblock_user", user_email, result or {"accountEnabled": True})

    # ── G. PASSWORD ──────────────────────────────────────────────────────

    elif name == "reset_user_password":
        user_email = arguments["user_email"]
        confirmed = arguments.get("confirmed", False)
        user = _resolve_user(user_email)
        user_id = user["id"]

        onprem_note = {}
        if user.get("onPremisesSyncEnabled"):
            onprem_note["_note"] = (
                f"'{user_email}' is an account synced from on-premises AD. This assumes Password "
                "Writeback is enabled, so a reset via Graph propagates to the local AD - if writeback is "
                "ever disabled, this reset would have no real effect even though the API responds OK."
            )

        if not confirmed:
            return _preview(
                "reset_user_password",
                {"user_email": user_email, "displayName": user.get("displayName")},
                "A strong random 12-character password (upper case, lower case, digits and "
                "symbols) will be generated and set with forceChangePasswordNextSignIn=True. The password is generated only "
                "on confirmation and returned in the result - IT support must hand it to the user in person.",
                **onprem_note,
            )

        new_password = _generate_strong_password()

        try:
            graph.patch(f"/users/{user_id}", {
                "passwordProfile": {"password": new_password, "forceChangePasswordNextSignIn": True},
            })
            step_result = {
                "ok": True,
                "detail": "Temporary password set; a change will be forced at next sign-in.",
                "temporary_password": new_password,
            }
        except Exception as ex:
            step_result = {"ok": False, "error": str(ex)}

        return _executed("reset_user_password", user_email, {**step_result, **onprem_note})

    # ── H. DEVICES ───────────────────────────────────────────────────────

    elif name == "get_user_devices":
        user_email = arguments["user_email"]
        include_registered = arguments.get("include_registered", True)
        include_owned = arguments.get("include_owned", True)

        registered = graph.get(f"/users/{user_email}/registeredDevices", params={
            "$select": "id,displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,approximateLastSignInDateTime,registrationDateTime,deviceId,onPremisesSyncEnabled",
        }).get("value", []) if include_registered else []

        owned = graph.get(f"/users/{user_email}/ownedDevices", params={
            "$select": "id,displayName,operatingSystem,isCompliant,isManaged,trustType,approximateLastSignInDateTime",
        }).get("value", []) if include_owned else []

        owned_ids = {d["id"] for d in owned}
        combined = {}
        for d in registered:
            combined[d["id"]] = dict(d)
            combined[d["id"]]["_ownership"] = "registered_and_owned" if d["id"] in owned_ids else "registered"
        for d in owned:
            if d["id"] not in combined:
                combined[d["id"]] = dict(d)
                combined[d["id"]]["_ownership"] = "owned"

        return ok({"count": len(combined), "devices": list(combined.values())})

    # ── I. GROUPS ────────────────────────────────────────────────────────

    elif name == "get_user_groups":
        user_email = arguments["user_email"]
        security_only = arguments.get("security_only", False)
        groups = graph.get(f"/users/{user_email}/memberOf", params={
            "$select": "id,displayName,groupTypes,securityEnabled,mailEnabled,description,membershipRule",
        }).get("value", [])
        if security_only:
            groups = [g for g in groups if g.get("securityEnabled") and "DynamicMembership" not in (g.get("groupTypes") or [])]
        return ok({"count": len(groups), "groups": groups})

    elif name == "add_user_to_group":
        user_email = arguments["user_email"]
        group_id = arguments["group_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        group = graph.get(f"/groups/{group_id}", params={"$select": "displayName,description,groupTypes,securityEnabled"})
        check = graph.post(f"/users/{user_id}/checkMemberGroups", {"groupIds": [group_id]})
        already_member = group_id in check.get("value", [])

        if not confirmed:
            what = "The user is already a member of this group - no change would be made." if already_member else f"{user_email} will be added to group '{group.get('displayName')}'."
            return _preview(
                "add_user_to_group",
                {"user_email": user_email, "group_id": group_id, "group_name": group.get("displayName"), "already_member": already_member},
                what,
            )

        if already_member:
            return ok({"mode": "NO CHANGE - the user is already a member of this group", "user_email": user_email, "group_id": group_id})

        graph.post(f"/groups/{group_id}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"})
        return _executed("add_user_to_group", user_email, {"group_id": group_id, "group_name": group.get("displayName"), "added": True})

    elif name == "remove_user_from_group":
        user_email = arguments["user_email"]
        group_id = arguments["group_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        group = graph.get(f"/groups/{group_id}", params={"$select": "displayName"})
        check = graph.post(f"/users/{user_id}/checkMemberGroups", {"groupIds": [group_id]})
        is_member = group_id in check.get("value", [])

        if not is_member:
            return ok({"mode": "NO CHANGE - the user is not a member of this group", "user_email": user_email, "group_id": group_id, "group_name": group.get("displayName")})

        if not confirmed:
            return _preview(
                "remove_user_from_group",
                {"user_email": user_email, "group_id": group_id, "group_name": group.get("displayName")},
                f"{user_email} will be removed from group '{group.get('displayName')}'.",
            )

        graph.delete(f"/groups/{group_id}/members/{user_id}/$ref")
        return _executed("remove_user_from_group", user_email, {"group_id": group_id, "group_name": group.get("displayName"), "removed": True})

    elif name == "list_groups":
        query = arguments.get("query")
        security_only = arguments.get("security_only", True)
        top = arguments.get("top", 50)
        params = {
            "$select": "id,displayName,description,groupTypes,securityEnabled,mailEnabled,membershipRule",
            "$top": top,
            "$count": "true",
        }
        if security_only:
            params["$filter"] = "securityEnabled eq true"
        if query:
            params["$search"] = f'"displayName:{query}"'
        data = graph.get("/groups", params=params, eventual=True)
        return ok(data)

    elif name == "get_group":
        group_id = arguments["group_id"]
        max_members = arguments.get("max_members", 2000)
        group = graph.get(f"/groups/{group_id}", params={
            "$select": "id,displayName,description,groupTypes,securityEnabled,mailEnabled,membershipRule,createdDateTime,mail",
        })

        members = []
        truncated = False
        url = f"/groups/{group_id}/members"
        params = {"$select": "id,displayName,userPrincipalName,userType", "$top": 999}
        while url:
            page = graph.get(url, params=params)
            members.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
            params = None  # nextLink already carries the encoded query params; do not repeat them
            if max_members and max_members > 0 and len(members) >= max_members:
                members = members[:max_members]
                truncated = bool(url)
                break

        group["_members"] = members
        group["_members_count"] = len(members)
        group["_members_truncated"] = truncated
        if truncated:
            group["_note"] = f"Reached max_members={max_members} - the group has more members. Raise max_members (or pass 0 to fetch all) and call again."
        return ok(group)

    elif name == "create_group":
        display_name = arguments["display_name"]
        description = arguments.get("description", "")
        mail_nickname = arguments.get("mail_nickname") or "".join(c for c in display_name if c.isalnum())
        confirmed = arguments.get("confirmed", False)

        existing = graph.get("/groups", params={"$filter": f"displayName eq '{display_name}'", "$select": "id,displayName"}).get("value", [])

        if not confirmed:
            what = (
                f"⚠️ A group with this exact displayName already exists (id={existing[0]['id']}) - check whether it is the "
                "same one before creating a duplicate."
                if existing else
                f"Security group '{display_name}' will be created (mailNickname='{mail_nickname}')."
            )
            return _preview(
                "create_group",
                {"display_name": display_name, "mail_nickname": mail_nickname, "existing_matches": existing},
                what,
            )

        body = {
            "displayName": display_name,
            "description": description,
            "mailEnabled": False,
            "mailNickname": mail_nickname,
            "securityEnabled": True,
        }
        result = graph.post("/groups", body)
        return _executed("create_group", display_name, result)

    # ── J. ROLES ─────────────────────────────────────────────────────────

    elif name == "get_user_roles":
        user_email = arguments["user_email"]
        data = graph.get(f"/users/{user_email}/transitiveMemberOf/microsoft.graph.directoryRole", params={"$select": "id,displayName,description,roleTemplateId"})
        return ok(data)

    elif name == "get_available_roles":
        data = graph.get("/directoryRoles", params={"$select": "id,displayName,description,roleTemplateId"})
        return ok(data)

    elif name == "assign_directory_role":
        user_email = arguments["user_email"]
        role_id = arguments["role_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        role = graph.get(f"/directoryRoles/{role_id}", params={"$select": "displayName,description"})
        current_roles = graph.get(f"/users/{user_email}/transitiveMemberOf/microsoft.graph.directoryRole", params={"$select": "id,displayName"}).get("value", [])
        already_assigned = any(r.get("id") == role_id for r in current_roles)

        if not confirmed:
            if already_assigned:
                what = "The user already has this role assigned - no change would be made."
            else:
                what = f"Role '{role.get('displayName')}' will be assigned to {user_email}."
                if role.get("displayName") in SENSITIVE_ROLES:
                    what += f" ⚠️ WARNING: '{role.get('displayName')}' is a highly privileged role."
            return _preview(
                "assign_directory_role",
                {"user_email": user_email, "role_id": role_id, "role_name": role.get("displayName"), "already_assigned": already_assigned},
                what,
            )

        if already_assigned:
            return ok({"mode": "NO CHANGE - the user already has this role", "user_email": user_email, "role_id": role_id})

        graph.post(f"/directoryRoles/{role_id}/members/$ref", {"@odata.id": f"https://graph.microsoft.com/v1.0/users/{user_id}"})
        return _executed("assign_directory_role", user_email, {"role_id": role_id, "role_name": role.get("displayName"), "assigned": True})

    elif name == "remove_directory_role":
        user_email = arguments["user_email"]
        role_id = arguments["role_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        role = graph.get(f"/directoryRoles/{role_id}", params={"$select": "displayName"})
        current_roles = graph.get(f"/users/{user_email}/transitiveMemberOf/microsoft.graph.directoryRole", params={"$select": "id,displayName"}).get("value", [])
        has_role = any(r.get("id") == role_id for r in current_roles)

        if not has_role:
            return ok({"mode": "NO CHANGE - the user does not have this role assigned", "user_email": user_email, "role_id": role_id, "role_name": role.get("displayName")})

        extra = {}
        if role.get("displayName") == "Global Administrator":
            members = graph.get(f"/directoryRoles/{role_id}/members", params={"$select": "id"}).get("value", [])
            if len(members) <= 1:
                extra["_warning"] = "⚠️ This user appears to be the LAST Global Administrator of the tenant. Removing the role may leave the tenant without administration."

        if not confirmed:
            return _preview(
                "remove_directory_role",
                {"user_email": user_email, "role_id": role_id, "role_name": role.get("displayName")},
                f"Role '{role.get('displayName')}' will be removed from {user_email}.",
                **extra,
            )

        graph.delete(f"/directoryRoles/{role_id}/members/{user_id}/$ref")
        return _executed("remove_directory_role", user_email, {"role_id": role_id, "role_name": role.get("displayName"), "removed": True})

    elif name == "get_role_members":
        role_id = arguments["role_id"]
        data = graph.get(f"/directoryRoles/{role_id}/members", params={"$select": "id,displayName,userPrincipalName,userType"})
        return ok(data)

    elif name == "get_pim_role_assignments":
        role_template_id = arguments["role_template_id"]
        filter_clause = f"roleDefinitionId eq '{role_template_id}'"
        try:
            eligible = graph.get("/roleManagement/directory/roleEligibilityScheduleInstances", params={"$filter": filter_clause}).get("value", [])
        except Exception:
            eligible = []
        try:
            active = graph.get("/roleManagement/directory/roleAssignmentScheduleInstances", params={"$filter": filter_clause}).get("value", [])
        except Exception:
            active = []
        for e in eligible:
            e["_assignment_type"] = "eligible_pim"
        for a in active:
            a["_assignment_type"] = "active"
        return ok({"role_template_id": role_template_id, "eligible_count": len(eligible), "active_count": len(active), "eligible": eligible, "active": active})

    # ── K. LICENSES ──────────────────────────────────────────────────────

    elif name == "get_user_licenses":
        user_email = arguments["user_email"]
        details = graph.get(f"/users/{user_email}/licenseDetails", params={"$select": "id,skuId,skuPartNumber,servicePlans"}).get("value", [])
        for d in details:
            d["_friendly_name"] = _license_label(d.get("skuPartNumber"))
        tenant_skus = graph.get("/subscribedSkus", params={"$select": "skuId,skuPartNumber,consumedUnits,prepaidUnits"}).get("value", [])
        for s in tenant_skus:
            s["_friendly_name"] = _license_label(s.get("skuPartNumber"))
        return ok({"user_licenses": details, "tenant_skus": tenant_skus})

    elif name == "assign_license":
        user_email = arguments["user_email"]
        sku_id = arguments["sku_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        tenant_skus = graph.get("/subscribedSkus", params={"$select": "skuId,skuPartNumber,consumedUnits,prepaidUnits"}).get("value", [])
        sku = next((s for s in tenant_skus if s.get("skuId") == sku_id), None)
        if not sku:
            raise ValueError(f"sku_id '{sku_id}' does not exist in the tenant")
        enabled = (sku.get("prepaidUnits") or {}).get("enabled", 0)
        consumed = sku.get("consumedUnits", 0)
        available = enabled - consumed
        label = _license_label(sku.get("skuPartNumber"))

        if not confirmed:
            what = f"License '{label}' will be assigned to {user_email}." if available > 0 else f"NO licenses available for '{label}' ({consumed}/{enabled} in use)."
            return _preview(
                "assign_license",
                {"user_email": user_email, "sku_id": sku_id, "license_name": label, "available": available},
                what,
            )

        if available <= 0:
            raise ValueError(f"No licenses available for '{label}' ({consumed}/{enabled} in use)")

        result = graph.post(f"/users/{user_id}/assignLicense", {"addLicenses": [{"skuId": sku_id}], "removeLicenses": []})
        return _executed("assign_license", user_email, result)

    elif name == "remove_license":
        user_email = arguments["user_email"]
        sku_id = arguments["sku_id"]
        confirmed = arguments.get("confirmed", False)

        user = _resolve_user(user_email)
        user_id = user["id"]
        details = graph.get(f"/users/{user_email}/licenseDetails", params={"$select": "id,skuId,skuPartNumber"}).get("value", [])
        current = next((d for d in details if d.get("skuId") == sku_id), None)

        if not current:
            return ok({"mode": "NO CHANGE - the user does not have this license", "user_email": user_email, "sku_id": sku_id})

        label = _license_label(current.get("skuPartNumber"))
        if not confirmed:
            return _preview(
                "remove_license",
                {"user_email": user_email, "sku_id": sku_id, "license_name": label},
                f"License '{label}' will be removed from {user_email}.",
            )

        result = graph.post(f"/users/{user_id}/assignLicense", {"addLicenses": [], "removeLicenses": [sku_id]})
        return _executed("remove_license", user_email, result)

    # ── L. CONDITIONAL ACCESS ────────────────────────────────────────────

    elif name == "get_conditional_access_policies":
        state = arguments.get("state")
        _validate_enum(state, ["enabled", "disabled", "enabledForReportingButNotEnforced"], "state")
        params = {}
        if state:
            params["$filter"] = f"state eq '{state}'"
        data = graph.get("/identity/conditionalAccess/policies", params)
        return ok(data)

    elif name == "get_auth_methods_policy":
        data = graph.get("/policies/authenticationMethodsPolicy")
        return ok(data)

    elif name == "get_mfa_registration_policy":
        data = graph.get("/policies/authenticationMethodsPolicy/authenticationMethodConfigurations")
        return ok(data)

    elif name == "create_conditional_access_policy":
        policy = arguments["policy"]
        confirmed = arguments.get("confirmed", False)
        if not isinstance(policy, dict) or not policy.get("displayName"):
            raise ValueError("'policy' must be an object with at least 'displayName' and 'state'.")

        if not confirmed:
            return _preview(
                "create_conditional_access_policy",
                {"displayName": policy.get("displayName"), "state": policy.get("state")},
                f"A new Conditional Access policy '{policy.get('displayName')}' will be created with state='{policy.get('state')}'.",
                policy_body=policy,
            )

        result = graph.post("/identity/conditionalAccess/policies", policy)
        return _executed("create_conditional_access_policy", policy.get("displayName", ""), result)

    elif name == "update_conditional_access_policy":
        policy_id = arguments["policy_id"]
        patch_body = arguments["policy"]
        confirmed = arguments.get("confirmed", False)

        current = graph.get(f"/identity/conditionalAccess/policies/{policy_id}")

        if not confirmed:
            what = f"Policy '{current.get('displayName')}' (id={policy_id}) will be updated."
            if "state" in patch_body:
                what += f" State: '{current.get('state')}' → '{patch_body['state']}'."
            return _preview(
                "update_conditional_access_policy",
                {"policy_id": policy_id, "displayName": current.get("displayName"), "current_state": current.get("state"), "changes": patch_body},
                what,
            )

        graph.patch(f"/identity/conditionalAccess/policies/{policy_id}", patch_body)
        return _executed("update_conditional_access_policy", current.get("displayName", policy_id), {"policy_id": policy_id, "changes_applied": patch_body})

    # ── M. IDENTITY PROTECTION (RISK) ───────────────────────────────────

    elif name == "get_risky_users":
        params = {"$top": arguments.get("top", 50)}
        filters = []
        if arguments.get("risk_state"):
            filters.append(f"riskState eq '{arguments['risk_state']}'")
        if arguments.get("risk_level"):
            filters.append(f"riskLevel eq '{arguments['risk_level']}'")
        if filters:
            params["$filter"] = " and ".join(filters)
        data = graph.get("/identityProtection/riskyUsers", params)
        return ok(data)

    elif name == "get_risk_detections":
        params = {"$top": arguments.get("top", 50), "$orderby": "activityDateTime desc"}
        if arguments.get("user_email"):
            params["$filter"] = f"userPrincipalName eq '{arguments['user_email']}'"
        data = graph.get("/identityProtection/riskDetections", params)
        return ok(data)

    elif name == "dismiss_risky_users":
        user_emails = arguments["user_emails"]
        confirmed = arguments.get("confirmed", False)

        resolved = []
        for email in user_emails:
            user = _resolve_user(email)
            try:
                risk = graph.get(f"/identityProtection/riskyUsers/{user['id']}")
            except Exception:
                risk = {}
            resolved.append({"user_email": email, "id": user["id"], "riskState": risk.get("riskState"), "riskLevel": risk.get("riskLevel")})

        if not confirmed:
            return _preview(
                "dismiss_risky_users",
                {"users": resolved},
                f"The risk of {len(resolved)} user(s) will be dismissed in Identity Protection.",
            )

        result = graph.post("/identityProtection/riskyUsers/dismiss", {"userIds": [u["id"] for u in resolved]})
        return _executed("dismiss_risky_users", ", ".join(user_emails), result or {"dismissed": [u["id"] for u in resolved]})

    # ── N. APPLICATIONS / OAUTH CONSENTS ────────────────────────────────

    elif name == "list_service_principals":
        query = arguments.get("query")
        top = arguments.get("top", 50)
        params = {
            "$select": "id,appId,displayName,servicePrincipalType,accountEnabled,publisherName,tags",
            "$top": top,
            "$count": "true",
        }
        if query:
            params["$search"] = f'"displayName:{query}"'
        data = graph.get("/servicePrincipals", params=params, eventual=True)
        return ok(data)

    elif name == "get_service_principal_details":
        sp_id = arguments["service_principal_id"]
        sp = graph.get(f"/servicePrincipals/{sp_id}", params={
            "$select": "id,appId,displayName,servicePrincipalType,accountEnabled,publisherName,replyUrls,tags,appOwnerOrganizationId",
        })
        try:
            app_role_assignments = graph.get(f"/servicePrincipals/{sp_id}/appRoleAssignments").get("value", [])
        except Exception:
            app_role_assignments = []
        try:
            oauth_grants = graph.get("/oauth2PermissionGrants", params={"$filter": f"clientId eq '{sp_id}'"}).get("value", [])
        except Exception:
            oauth_grants = []
        sp["_app_role_assignments"] = app_role_assignments
        sp["_oauth2_permission_grants"] = oauth_grants
        return ok(sp)

    elif name == "get_oauth_consents":
        top = arguments.get("top", 50)
        params = {"$top": top}
        filters = []
        if arguments.get("client_id"):
            filters.append(f"clientId eq '{arguments['client_id']}'")
        if arguments.get("user_email"):
            user = _resolve_user(arguments["user_email"])
            filters.append(f"consentType eq 'Principal' and principalId eq '{user['id']}'")
        if filters:
            params["$filter"] = " and ".join(filters)
        data = graph.get("/oauth2PermissionGrants", params)
        return ok(data)

    # ── O. SECURE SCORE ──────────────────────────────────────────────────

    elif name == "get_secure_score":
        top = arguments.get("top", 1)
        data = graph.get("/security/secureScores", params={"$top": top})
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


# ── REQUIRED PERMISSIONS ─────────────────────────────────────
# App registration: sec-identity-mcp
# API: Microsoft Graph - Application permissions
#
#  User.ReadWrite.All
#    → A1, A2, F1, F2, G1 - profile, blocking, password
#  UserAuthenticationMethod.ReadWrite.All
#    → A2, D1, D2, D3, D4 - MFA: read, revoke (bulk and single), signInPreferences (default method)
#  GroupMember.ReadWrite.All
#    → D5 (enforce_mfa, adds the user to the CA group "SG-MFA-Enforced"; no longer uses perUserMfaState/
#    UserAuthenticationMethod.ReadWrite.All), I1, I2 - group membership
#  Group.ReadWrite.All
#    → I3, I4, I5 (list_groups, get_group, create_group) - unlike GroupMember.ReadWrite.All
#    (membership only), this permission is required to list/read/create tenant groups.
#  User.RevokeSessions.All
#    → E1 - revoke active sessions
#  AuditLog.Read.All
#    → B1, B2, B3 - sign-ins and directoryAudits
#  Policy.Read.All
#    → L1, L2 - auth methods policy and mfa registration policy
#  Policy.ReadWrite.ConditionalAccess
#    → L3, L4, L5 (get/create/update_conditional_access_policy) - Policy.Read.All is NOT enough
#    for writes; this additional permission is required.
#  Device.Read.All
#    → H1 - user devices
#  RoleManagement.ReadWrite.Directory
#    → J1, J2, J3, J4 - directory roles (direct assignment); also covers reading
#    roleEligibilityScheduleInstances/roleAssignmentScheduleInstances (PIM census, get_pim_role_assignments)
#  LicenseAssignment.ReadWrite
#    → K1, K2, K3 - licenses
#  IdentityRiskyUser.ReadWrite.All
#    → get_risky_users, dismiss_risky_users - Identity Protection
#  IdentityRiskEvent.Read.All
#    → get_risk_detections - Identity Protection
#  Application.Read.All
#    → list_service_principals, get_service_principal_details - enterprise application inventory
#  DelegatedPermissionGrant.Read.All
#    → get_service_principal_details, get_oauth_consents - delegated OAuth consents
#  SecurityEvents.Read.All
#    → get_secure_score - Microsoft Secure Score / Identity Secure Score (subset by controlCategory)
# ─────────────────────────────────────────────────────────────
