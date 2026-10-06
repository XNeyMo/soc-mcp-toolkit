"""HTTP client for the Microsoft Threat Protection (MTP) and WindowsDefenderATP
(MDE) APIs — both share the same base URL and token scope, so one client serves
both.

Base URL : https://api.security.microsoft.com/api
Scope    : https://api.security.microsoft.com/.default
"""

import logging
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://api.security.microsoft.com/api"


class MtpClient:
    def __init__(self, token_fn: Callable[[], str]):
        self.token_fn = token_fn
        self.base = BASE_URL

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base}{path}"

    def _request(self, method: str, path: str, params: Optional[dict] = None,
                 json_body: Optional[dict] = None, _retried: bool = False):
        url = self._url(path)
        headers = {"Authorization": f"Bearer {self.token_fn()}"}
        r = httpx.request(method, url, headers=headers, params=params, json=json_body, timeout=90)
        logger.debug("MTP %s %s -> %s", method, path, r.status_code)

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
