"""HTTP client for the Exchange Online / Security & Compliance admin API.

Base URL : https://{host}/adminapi/beta/{tenant_id}
Scope    : https://{host}/.default

The tenant_id is part of the base URL (not each call), unlike Graph.

`host` defaults to 'outlook.office365.com' (Exchange Online: mailboxes, transport
rules, connectors, message trace...). The Quarantine cmdlets (Get/Release/Delete/
Report-QuarantineMessage) live on a DIFFERENT host and scope —
'ps.compliance.protection.outlook.com' (Security & Compliance PowerShell) — and
additionally require the app's service principal to hold an Exchange role
assignment (New-ManagementRoleAssignment), not just the Exchange.ManageAsApp
permission in the identity provider; without that role assignment, this host
answers 500 "Could not find the organization container" instead of a normal
403/401.
"""

import logging
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)


class ExoClient:
    def __init__(self, token_fn: Callable[[], str], tenant_id: str, host: str = "outlook.office365.com"):
        self.token_fn = token_fn
        self.base = f"https://{host}/adminapi/beta/{tenant_id}"

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base}{path}"

    def _request(self, method: str, path: str, params: Optional[dict] = None,
                 json_body: Optional[dict] = None, _retried: bool = False):
        url = self._url(path)
        headers = {"Authorization": f"Bearer {self.token_fn()}"}
        r = httpx.request(method, url, headers=headers, params=params, json=json_body, timeout=90)
        logger.debug("EXO %s %s -> %s", method, path, r.status_code)

        if r.status_code == 401 and not _retried:
            return self._request(method, path, params=params, json_body=json_body, _retried=True)

        if r.status_code >= 400:
            raise RuntimeError(f"{r.status_code}: {r.text}")

        if r.status_code == 204 or not r.content:
            return None
        return r.json()

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict) -> dict:
        return self._request("POST", path, json_body=body)

    def patch(self, path: str, body: dict) -> dict:
        return self._request("PATCH", path, json_body=body)

    def delete(self, path: str):
        return self._request("DELETE", path)
