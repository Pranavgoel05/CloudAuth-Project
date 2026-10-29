"""Small in-process rate limiter for the classroom demo.

For production, use a shared store (for example Redis) behind a trusted proxy.
"""
from __future__ import annotations

from collections import defaultdict, deque
from functools import wraps
from threading import Lock
from time import monotonic
from typing import Callable

from fastapi import HTTPException, Request


class _Storage:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= window_seconds:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True


class Limiter:
    """Decorator-compatible rate limiter with a SlowAPI-like `limit` API."""
    def __init__(self) -> None:
        self._storage = _Storage()

    def reset(self) -> None:
        self._storage.reset()

    def limit(self, rule: str):
        amount, period = rule.split("/", 1)
        limit = int(amount)
        window_seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}.get(
            period.rstrip("s"), 60
        )

        def decorate(endpoint: Callable):
            @wraps(endpoint)
            def wrapped(*args, **kwargs):
                request = kwargs.get("request")
                if not isinstance(request, Request):
                    request = next((arg for arg in args if isinstance(arg, Request)), None)
                client_ip = request.client.host if request and request.client else "unknown"
                key = f"{endpoint.__module__}.{endpoint.__name__}:{client_ip}"
                if not self._storage.allow(key, limit, window_seconds):
                    raise HTTPException(status_code=429, detail="Rate limit exceeded; try again later")
                return endpoint(*args, **kwargs)
            return wrapped
        return decorate


limiter = Limiter()
