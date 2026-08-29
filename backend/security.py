"""Small, dependency-free controls for protecting the ingestion API."""

from __future__ import annotations

import hmac
import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status


_requests_by_client: dict[str, deque[float]] = defaultdict(deque)


def _enabled(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _configured_keys(name: str) -> set[str]:
    return {value.strip() for value in os.getenv(name, "").split(",") if value.strip()}


def _check_rate_limit(client_id: str) -> None:
    limit = max(1, int(os.getenv("INGEST_RATE_LIMIT_PER_MINUTE", "300")))
    now = time.monotonic()
    events = _requests_by_client[client_id]
    while events and events[0] <= now - 60:
        events.popleft()
    if len(events) >= limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="ingest rate limit exceeded")
    events.append(now)


async def protect_ingest(request: Request) -> None:
    """Apply API-key authentication and a bounded per-client in-memory rate limit.

    Set REQUIRE_INGEST_AUTH=true and INGEST_API_KEYS to a comma-separated list of
    long random secrets in every deployed environment. The Lambda/poller sends one
    of these values in X-API-Key.
    """
    client_id = request.client.host if request.client else "unknown"
    _check_rate_limit(client_id)
    if not _enabled("REQUIRE_INGEST_AUTH"):
        return

    supplied = request.headers.get("X-API-Key", "")
    if not supplied or not any(hmac.compare_digest(supplied, key) for key in _configured_keys("INGEST_API_KEYS")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid ingest API key")


async def protect_admin(request: Request) -> None:
    """Protect development-only maintenance endpoints when they are enabled."""
    if not _enabled("ENABLE_DEV_ENDPOINTS"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="endpoint disabled")
    expected = os.getenv("DEV_ADMIN_API_KEY", "")
    supplied = request.headers.get("X-Admin-Key", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin API key")
