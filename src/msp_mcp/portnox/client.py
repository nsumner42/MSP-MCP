"""Portnox Cloud REST API client: Bearer token, rate limiting, retries.

API facts (from docs.portnox.com/topics/api and Portnox's own community MCP server,
github.com/portnox/scripts "Portnox Labs/MCP Server", Apache-2.0; the full Swagger reference is
only inside the tenant, Help > API REFERENCE):
- Base URL https://clear.portnox.com:8081/CloudPortalBackEnd (cloud.portnox.com:8081 also works).
- Auth: Authorization: Bearer <token>. Tokens are made per local Portnox admin under Settings >
  Profile Settings > ACCOUNT SETTINGS > CLOUD API TOKENS and carry that admin's rights; admins
  signing in through Entra ID / Google cannot use the API.
- Rate limit: 10 requests per 10 seconds.
- Plain JSON in and out; errors are bare HTTP status codes (400 bad parameter, 401 bad token,
  403 licence/rights, 404 not found).
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

DEFAULT_API_URL = "https://clear.portnox.com:8081/CloudPortalBackEnd"

_HINTS = {
    400: "missing or malformed parameter",
    401: "token not valid or expired (make a new one in Portnox: Settings > Profile Settings > "
         "ACCOUNT SETTINGS > CLOUD API TOKENS, and save it as PortnoxApi)",
    403: "access denied (the token's admin lacks the right, or the licence does not include it)",
    404: "not found",
}


class PortnoxError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


class PortnoxClient:
    def __init__(self, api_url: str | None = None):
        self.base = (api_url or os.environ.get("PORTNOX_API_URL") or DEFAULT_API_URL).rstrip("/")
        # Username = a label (the admin it was made under); password = the API token.
        _, self._token = load_machine_credential("PortnoxApi")
        # Portnox allows 10 requests per 10 seconds.
        self._limiter = RateLimiter(per_second=0.9, burst=5)
        self._http = httpx.AsyncClient(timeout=60, headers={
            "Authorization": f"Bearer {self._token}", "Accept": "application/json"})

    async def call(self, method: str, path: str, json: Any = None) -> Any:
        """One request; returns parsed JSON (None for an empty body). Retries 429/5xx."""
        for attempt in range(1, 5):
            await self._limiter.acquire()
            try:
                r = await self._http.request(method, f"{self.base}{path}", json=json)
            except httpx.HTTPError as ex:
                if attempt < 4:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise PortnoxError(f"{method} {path}: {ex}") from None
            if (r.status_code == 429 or r.status_code >= 500) and attempt < 4:
                await asyncio.sleep(5 * attempt + random.uniform(0, 2))
                continue
            if r.status_code >= 400:
                detail = r.text.strip()[:300]
                hint = _HINTS.get(r.status_code, "")
                raise PortnoxError(f"{method} {path}: HTTP {r.status_code}"
                                   + (f" ({hint})" if hint else "") + (f": {detail}" if detail else ""))
            if not r.content:
                return None
            try:
                return r.json()
            except ValueError:
                return r.text
        raise PortnoxError(f"{method} {path}: gave up after repeated 429/5xx responses")

    async def aclose(self) -> None:
        await self._http.aclose()
