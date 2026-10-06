"""
Generic (non-Entra) OAuth2 client_credentials authentication, for third-party
REST APIs that expose their own token endpoint instead of login.microsoftonline.com
— e.g. Ellucian Banner / Oracle ORDS behind a custom ETHOS Integration gateway
(mcp-banner). Unlike shared/auth.py (MSAL, always against Entra), here the
client_id/secret are sent as a Basic Auth header to the token_url
(RFC 6749 2.3.1 / 4.4), which is the scheme Oracle ORDS uses — no `msal` and no
`tenant_id` involved.
"""

import os
import time

import httpx

_token_cache: dict[str, tuple[str, float]] = {}


def get_client_credentials_token(token_url: str, client_id: str, client_secret: str,
                                  scope: str | None = None) -> str:
    """Acquire an OAuth2 client_credentials token, cached in memory until 60s
    before expiry."""
    cache_key = f"{token_url}:{client_id}:{scope}"
    cached = _token_cache.get(cache_key)
    if cached and cached[1] > time.time() + 60:
        return cached[0]

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope

    r = httpx.post(token_url, data=data, auth=(client_id, client_secret), timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"Token error {r.status_code}: {r.text}")
    result = r.json()
    if "access_token" not in result:
        raise RuntimeError(f"Token error: {result}")

    _token_cache[cache_key] = (result["access_token"], time.time() + result.get("expires_in", 3600))
    return result["access_token"]


def invalidate_client_credentials_token(token_url: str, client_id: str, scope: str | None = None) -> None:
    """Drop the cached token (use on retry-on-401: our cache cannot know the
    provider revoked/expired the token earlier than its stated expires_in)."""
    _token_cache.pop(f"{token_url}:{client_id}:{scope}", None)


def load_banner_credentials() -> tuple[str, str, str]:
    """Reads BANNER_TOKEN_URL / BANNER_CLIENT_ID / BANNER_CLIENT_SECRET."""
    return (
        os.environ["BANNER_TOKEN_URL"],
        os.environ["BANNER_CLIENT_ID"],
        os.environ["BANNER_CLIENT_SECRET"],
    )
