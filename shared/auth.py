"""
Shared per-app-registration authentication (application permissions).

Each domain (mcp-defender, mcp-identity, mcp-exchange, mcp-intune, mcp-audit)
has its own app registration in the identity provider (its own CLIENT_ID), so a
secret leaked or misused in one domain does not grant access to the others.

Within each app registration, each analyst has their OWN client secret (named
after them), configured locally on their machine via an environment variable.
This does not replace interactive MFA, but it does allow you to:
  - revoke one person's access without rotating everyone else's secret
  - tell, from the secret name in the identity provider's sign-in logs, which
    credential was used
  - keep a per-analyst local audit log (see audit_log.py)
"""

import os
import time

import msal

_token_cache: dict[str, tuple[str, float]] = {}


def get_token(tenant_id: str, client_id: str, client_secret: str,
              scope: str = "https://graph.microsoft.com/.default") -> str:
    """Acquire an application token, cached in memory until 60s before expiry."""
    cache_key = f"{tenant_id}:{client_id}:{scope}"
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > time.time() + 60:
        return cached[0]

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client([scope])
    if "access_token" not in result:
        raise RuntimeError(f"Token error: {result.get('error_description', result)}")

    _token_cache[cache_key] = (result["access_token"], time.time() + result.get("expires_in", 3600))
    return result["access_token"]


def load_domain_credentials(domain_prefix: str) -> tuple[str, str, str]:
    """Reads AZURE_TENANT_ID (shared) + <DOMAIN>_CLIENT_ID / <DOMAIN>_CLIENT_SECRET
    (specific to that domain's app registration, the analyst's individual secret).

    E.g. load_domain_credentials("DEFENDER") reads AZURE_TENANT_ID, DEFENDER_CLIENT_ID,
    DEFENDER_CLIENT_SECRET.
    """
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ[f"{domain_prefix}_CLIENT_ID"]
    client_secret = os.environ[f"{domain_prefix}_CLIENT_SECRET"]
    return tenant_id, client_id, client_secret
