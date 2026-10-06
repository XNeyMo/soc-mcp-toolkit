"""
MCP Server - Banner (Ellucian Banner student information system)

Scope: READ ONLY. Exposes two endpoints of the institution's Banner API
Gateway (the student information system, which holds personal information
about students, employees and faculty) so you can look up what Banner has
registered for a person - emails and phone numbers, among other data - and
compare it in conversation against what exists in Entra ID (mcp-identity:
get_user_signin_history, investigate_user, etc.). The comparison itself does
NOT live in this server - combine the raw JSON returned here with the
mcp-identity tools in the same conversation.

Talks to the institution's custom ETHOS Integration API gateway at
sis-gateway.example.com (NOT directly to Oracle ORDS, which sits behind it).
Auth: OAuth2 client_credentials - the client_id/secret are sent as a Basic
Auth header to the token endpoint (BANNER_TOKEN_URL), with no scope, which is
the standard Oracle ORDS scheme. See shared/oauth2_client_credentials.py (it
does not reuse shared/auth.py: that module is tied to MSAL/Entra, and Banner
does not go through it).

Endpoints (EXAMPLE custom ETHOS endpoints - adapt the paths and parameter
names to your own ETHOS integration):
  GET /v2/sis/persons/personal-information?student_code={code}
      Personal information registered in Banner (includes emails and phone
      numbers). The parameter name (student_code) is the one used by the API
      itself - it applies equally to employee codes, not only students; the
      code is the same value as the employeeId in Entra ID.
  GET /v2/sis/persons/{id}/roles
      Institutional roles of the person (e.g. EMPLOYEE, FACULTY, STUDENT,
      ALUMNI). {id} accepts a Banner username, institutional email (the @ is
      encoded as %40), Banner code, or national ID number - the backend is
      expected to resolve any of the four.

Note: the endpoint shapes above are examples to adapt. get_personal_information
returns the raw Banner JSON as delivered by the API, without assuming field
names for email/phone: if the real shape differs from what you expect, no
information is lost - you just read whichever fields actually come back.

Requires: pip install -r requirements.txt
Environment variables:
  BANNER_CLIENT_ID     (Banner/ORDS OAuth2 client id)
  BANNER_CLIENT_SECRET (Banner/ORDS OAuth2 client secret)
  BANNER_TOKEN_URL     (OAuth2 token endpoint, e.g. https://.../oauth/token)
  MCP_ANALYST_NAME     (optional; analyst name for the audit log)
"""

import sys
import urllib.parse
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

from shared.oauth2_client_credentials import (
    get_client_credentials_token,
    invalidate_client_credentials_token,
    load_banner_credentials,
)
from shared.mcp_common import ok, audited, require_vault

BASE_URL = "https://sis-gateway.example.com/v2/sis"

TOKEN_URL, CLIENT_ID, CLIENT_SECRET = load_banner_credentials()


class BannerClient:
    def __init__(self, token_url: str, client_id: str, client_secret: str):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret

    def _token(self) -> str:
        return get_client_credentials_token(self.token_url, self.client_id, self.client_secret)

    def get(self, path: str, params: Optional[dict] = None, _retried: bool = False) -> dict:
        url = f"{BASE_URL}{path}"
        headers = {"Authorization": f"Bearer {self._token()}"}
        r = httpx.get(url, headers=headers, params=params, timeout=60)

        if r.status_code == 401 and not _retried:
            invalidate_client_credentials_token(self.token_url, self.client_id)
            return self.get(path, params=params, _retried=True)

        if r.status_code >= 400:
            raise RuntimeError(f"{r.status_code}: {r.text}")
        return r.json()


banner = BannerClient(TOKEN_URL, CLIENT_ID, CLIENT_SECRET)

server = Server("mcp-banner")


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools():
    return [

        types.Tool(
            name="get_personal_information",
            description=(
                "Personal information registered in Banner for a person (includes emails and "
                "phone numbers, among other institutional data). Useful to compare against what "
                "is registered in Entra ID (mcp-identity) and detect inconsistencies - outdated "
                "data, emails/phones that do not match between systems, etc. "
                "Returns the raw Banner JSON exactly as delivered by the API."
            ),
            inputSchema={
                "type": "object",
                "required": ["student_code"],
                "properties": {
                    "student_code": {
                        "type": "string",
                        "description": (
                            "The person's code in Banner (the same value as the employeeId "
                            "in Entra ID). The parameter name is the one required by the API - "
                            "it applies equally to employee codes, not only student codes."
                        ),
                    },
                },
            },
        ),

        types.Tool(
            name="get_person_roles",
            description=(
                "Institutional roles of a person in Banner (e.g. EMPLOYEE, FACULTY, "
                "STUDENT, ALUMNI)."
            ),
            inputSchema={
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {
                        "type": "string",
                        "description": (
                            "Accepts a Banner username, institutional email, Banner code, "
                            "or national ID number - the backend resolves any of the four."
                        ),
                    },
                },
            },
        ),

    ]


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------

@server.call_tool()
@audited("banner")
@require_vault  # AUDIT GATE: no tool (read or write) runs unless the team audit vault (claudian) is reachable and writable first. See shared/mcp_common.py and README section "Audit gate (require_vault)".
async def call_tool(name: str, arguments: dict):

    if name == "get_personal_information":
        code = arguments["student_code"]
        data = banner.get("/persons/personal-information", params={"student_code": code})
        return ok(data)

    elif name == "get_person_roles":
        person_id = arguments["id"]
        data = banner.get(f"/persons/{urllib.parse.quote(person_id, safe='')}/roles")
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
# OAuth2 client (Banner/Oracle ORDS, behind the sis-gateway.example.com API Gateway):
#   The client_id/secret must be authorized for:
#     GET /v2/sis/persons/personal-information
#     GET /v2/sis/persons/{id}/roles
#   The exact authorization scope/role name depends on your API Gateway -
#   request a client_id+secret from the team that owns Banner/the API Gateway
#   with access to these two specific routes.
#
# The endpoint paths, parameter name and response shapes are examples to adapt
# to your own ETHOS integration. No response field names are assumed in the
# code, so a different shape does not break the tool - it only changes which
# fields come back in the returned JSON.
# ─────────────────────────────────────────────────────────────
