"""Minimal Microsoft Graph client, shared by all mcp-* servers."""

from typing import Callable, Optional

import httpx

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphClient:
    def __init__(self, token_getter: Callable[[], str]):
        self._token_getter = token_getter

    def _headers(self, extra: Optional[dict] = None) -> dict:
        headers = {"Authorization": f"Bearer {self._token_getter()}"}
        if extra:
            headers.update(extra)
        return headers

    def _raise_for_status(self, r) -> None:
        if r.status_code >= 400:
            raise RuntimeError(f"{r.status_code}: {r.text}")

    def get(self, path: str, params: dict = None, beta: bool = False, eventual: bool = False) -> dict:
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        headers = self._headers({"ConsistencyLevel": "eventual"} if eventual else None)
        r = httpx.get(url, headers=headers, params=params, timeout=90)
        self._raise_for_status(r)
        return r.json()

    def post(self, path: str, body: dict, beta: bool = False) -> dict:
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        r = httpx.post(url, headers=self._headers({"Content-Type": "application/json"}), json=body, timeout=90)
        self._raise_for_status(r)
        return r.json() if r.content else None

    def patch(self, path: str, body: dict, beta: bool = False):
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        r = httpx.patch(url, headers=self._headers({"Content-Type": "application/json"}), json=body, timeout=90)
        self._raise_for_status(r)
        return r.json() if r.content else None

    def delete(self, path: str, beta: bool = False):
        base = GRAPH_BETA if beta else GRAPH_BASE
        url = path if path.startswith("http") else f"{base}{path}"
        r = httpx.delete(url, headers=self._headers(), timeout=90)
        self._raise_for_status(r)
        return r.json() if r.content else None
