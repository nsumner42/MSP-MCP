"""ClouDNS API client: auth parameters on every call, rate limiting, retries.

API facts (from www.cloudns.net/wiki/article/41 and the per-call API articles; not yet checked
against our account):
- Base URL https://api.cloudns.net; calls are /dns/<name>.json, GET or POST with form parameters.
  We POST so the password never lands in a URL.
- Auth on every call: `auth-id` + `auth-password` (main API user: sees every zone). Sub-users
  (`sub-auth-id`) see only delegated zones; we don't use them.
- API users can be limited to allowed IPs; a call from another IP fails with an auth error.
- Errors are HTTP 200 with {"status": "Failed", "statusDescription": "..."}.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import asyncio
import os
import random
from typing import Any

import httpx

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.ratelimit import RateLimiter

DEFAULT_API_URL = "https://api.cloudns.net"


class ClouDNSError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


class ClouDNSClient:
    def __init__(self, api_url: str | None = None):
        self.base = (api_url or os.environ.get("CLOUDNS_API_URL") or DEFAULT_API_URL).rstrip("/")
        # Username = the main API user's auth-id; password = its API password.
        user, self._password = load_machine_credential("ClouDNSApi")
        self._auth = {"auth-id": user.strip()}
        self._limiter = RateLimiter(per_second=5, burst=10)
        self._http = httpx.AsyncClient(timeout=60, headers={"Accept": "application/json"})

    @property
    def auth_kind(self) -> str:
        return next(iter(self._auth))

    async def call(self, name: str, params: dict[str, Any] | None = None) -> Any:
        """POST /dns/<name>.json; returns parsed JSON. Raises on {"status": "Failed"}."""
        path = f"/dns/{name}.json"
        data = {**self._auth, "auth-password": self._password}
        for k, v in (params or {}).items():
            if v is not None:
                data[k] = str(v)
        for attempt in range(1, 5):
            await self._limiter.acquire()
            try:
                r = await self._http.post(f"{self.base}{path}", data=data)
            except httpx.HTTPError as ex:
                if attempt < 4:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise ClouDNSError(f"{path}: {ex}") from None
            if (r.status_code == 429 or r.status_code >= 500) and attempt < 4:
                await asyncio.sleep(3 * attempt + random.uniform(0, 2))
                continue
            if r.status_code >= 400:
                raise ClouDNSError(f"{path}: HTTP {r.status_code}: {r.text.strip()[:300]}")
            try:
                j = r.json()
            except ValueError:
                raise ClouDNSError(f"{path}: not JSON: {r.text.strip()[:300]}") from None
            if isinstance(j, dict) and j.get("status") == "Failed":
                desc = j.get("statusDescription") or str(j)[:300]
                if "auth" in desc.lower() or "password" in desc.lower():
                    desc += (" (check the ClouDNSApi credential, and that this computer's public IP"
                             " is allowed for the API user)")
                elif desc == "Missing domain-name" and data.get("domain-name"):
                    # ClouDNS says this when the zone exists but is not visible to this API user.
                    desc = f"zone {data['domain-name']} not found for this API user"
                raise ClouDNSError(f"{path}: {desc}")
            return j
        raise ClouDNSError(f"{path}: gave up after repeated 429/5xx responses")

    async def aclose(self) -> None:
        await self._http.aclose()
