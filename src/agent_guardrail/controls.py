"""Runtime controls that complement the static policy.

The policy answers "is this agent allowed to call this tool with these
arguments?". These controls answer questions that depend on *runtime* state:

* **Egress allowlist** -- where is a network-capable tool allowed to connect?
  Default-deny on destination host, with explicit allowlisting. This is the
  primary mitigation against data exfiltration by a prompt-injected agent.
* **Rate limiting** -- bound how often an agent can act in a window, so a
  runaway or hijacked loop cannot amplify damage before a human notices.

Both are deliberately simple and in-memory; a production deployment would back
the rate limiter with a shared store and source the allowlist from the same
IaC that provisions the egress proxy.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from urllib.parse import urlparse


class EgressError(Exception):
    pass


class RateLimitError(Exception):
    pass


class EgressAllowlist:
    """Default-deny allowlist of destination hosts for network tools."""

    def __init__(self, allowed_hosts: list[str] | None = None) -> None:
        self._allowed = set(allowed_hosts or [])

    def allow(self, host: str) -> None:
        self._allowed.add(host)

    def check_url(self, url: str) -> None:
        host = urlparse(url).hostname
        if host is None:
            raise EgressError(f"could not parse host from URL: {url!r}")
        if host not in self._allowed:
            raise EgressError(
                f"egress to {host!r} blocked: not in allowlist "
                f"({sorted(self._allowed)})"
            )


class RateLimiter:
    """Sliding-window rate limit, keyed per agent."""

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        if max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        self._max = max_calls
        self._window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, agent_id: str, *, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        events = self._events[agent_id]
        cutoff = now - self._window
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= self._max:
            raise RateLimitError(
                f"agent {agent_id!r} exceeded {self._max} calls "
                f"per {self._window}s"
            )
        events.append(now)
