"""HTTP client for the public Cortex XDR API (Palo Alto Networks).

Advanced API Key auth: each request carries a fresh nonce (64 chars) and a fresh
timestamp (ms), hashed together with the api_key using SHA-256. This is the same
scheme as the Postman pre-request script commonly used for this API — it has no
relation to OAuth/MSAL or to the Entra tenant used by the other mcp-* servers
(auth.py/graph_client.py/mtp_client.py): Cortex XDR is a Palo Alto Networks
product with its own per-tenant API key, not a per-analyst one.

All endpoints of this API share the same request/response envelope:
  Request:  {"request_data": {...}}
  Response: {"reply": {...}}
"""

import hashlib
import logging
import secrets
import string
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_NONCE_CHARS = string.ascii_letters + string.digits
_API_PATH = "/public_api/v1"


class CortexClient:
    def __init__(self, base_url: str, api_key: str, api_key_id: str):
        self.base_url = base_url.rstrip("/") + _API_PATH
        self.api_key = api_key
        self.api_key_id = api_key_id

    def _headers(self) -> dict:
        nonce = "".join(secrets.choice(_NONCE_CHARS) for _ in range(64))
        timestamp = str(int(time.time() * 1000))
        auth_hash = hashlib.sha256(f"{self.api_key}{nonce}{timestamp}".encode("utf-8")).hexdigest()
        return {
            "x-xdr-timestamp": timestamp,
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(self.api_key_id),
            "Authorization": auth_hash,
            "Content-Type": "application/json",
        }

    def call(self, path: str, request_data: Optional[dict] = None) -> dict:
        """POST to a Cortex XDR endpoint. `path` is relative to /public_api/v1
        (e.g. "/incidents/get_incidents/"). Returns the content of 'reply'."""
        return self.call_raw(path, {"request_data": request_data or {}})

    def call_raw(self, path: str, body: dict) -> dict:
        """Like call(), but the caller builds the full body. Needed for the
        handful of endpoints (e.g. indicators/insert_jsons) where 'request_data'
        is a list instead of a dict, or where there are sibling fields next to
        'request_data' at the same level (e.g. 'validate')."""
        url = f"{self.base_url}{path}"
        r = httpx.post(url, headers=self._headers(), json=body, timeout=90)
        logger.debug("Cortex POST %s -> %s", path, r.status_code)
        if r.status_code >= 400:
            raise RuntimeError(f"{r.status_code}: {r.text}")
        data = r.json()
        return data.get("reply", data)


def load_cortex_credentials() -> tuple[str, str, str]:
    """Reads CORTEX_FQDN, CORTEX_REGION, CORTEX_API_KEY_ID and CORTEX_API_KEY from
    the environment, and builds the base_url with the pattern
    https://api-<fqdn>.xdr.<region>.paloaltonetworks.com
    (e.g. FQDN "mytenant" + region "us" -> https://api-mytenant.xdr.us.paloaltonetworks.com).
    Both values are visible in Configurations > API Keys when creating the key, in
    the example URL the portal shows.

    Unlike the other domains (one app registration per domain, one client secret
    per analyst within it), Cortex XDR uses a single Advanced API Key shared by
    the whole team, with Responder + Viewer roles assigned at the key level. There
    is no AZURE_TENANT_ID or individual secret here.
    """
    import os

    fqdn = os.environ["CORTEX_FQDN"]
    region = os.environ["CORTEX_REGION"]
    base_url = f"https://api-{fqdn}.xdr.{region}.paloaltonetworks.com"
    api_key_id = os.environ["CORTEX_API_KEY_ID"]
    api_key = os.environ["CORTEX_API_KEY"]
    return base_url, api_key_id, api_key
