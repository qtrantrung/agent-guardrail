"""The guardrail gateway: the single choke point an agent's tool calls pass
through.

Flow for every proposed tool call:

1. **Rate limit** the calling agent (cheap, fail-fast).
2. **Evaluate policy** -- default-deny unless an allow rule matches.
3. **Apply egress control** for network tools.
4. **Audit** the decision (allowed *or* denied) into the hash chain.
5. Only then dispatch to the real tool implementation.

The ordering matters: every outcome is audited, including denials, so the log
is a complete record of what the agent *attempted*, not just what it achieved.
A denied call raises ``GuardrailDenied`` rather than returning a value, so a
caller cannot accidentally treat a blocked action as having succeeded.
"""

from __future__ import annotations

from typing import Any, Callable

from .audit import AuditLog
from .controls import EgressAllowlist, EgressError, RateLimiter, RateLimitError
from .engine import PolicyEngine
from .policy import Policy

ToolFn = Callable[..., Any]


class GuardrailDenied(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Gateway:
    def __init__(
        self,
        policy: Policy,
        *,
        egress: EgressAllowlist | None = None,
        rate_limiter: RateLimiter | None = None,
        audit_log: AuditLog | None = None,
        # Tools whose first/`url` argument is a network destination.
        network_tools: set[str] | None = None,
    ) -> None:
        self._engine = PolicyEngine(policy)
        self._egress = egress
        self._rate = rate_limiter
        self.audit = audit_log or AuditLog()
        self._network_tools = network_tools or set()
        self._tools: dict[str, ToolFn] = {}

    def register_tool(self, name: str, fn: ToolFn) -> None:
        self._tools[name] = fn

    def authorize(
        self, agent_id: str, tool: str, args: dict[str, Any]
    ) -> None:
        """Run all guardrails for an action. Raises on any denial.

        Separated from :meth:`call` so the decision can be exercised in tests
        and dry runs without dispatching a real tool.
        """
        if self._rate is not None:
            try:
                self._rate.check(agent_id)
            except RateLimitError as exc:
                self._deny(agent_id, tool, args, str(exc))

        decision = self._engine.evaluate(tool, args, agent_id)
        if not decision.allowed:
            self._deny(agent_id, tool, args, decision.reason)

        if tool in self._network_tools and self._egress is not None:
            url = args.get("url", "")
            try:
                self._egress.check_url(url)
            except EgressError as exc:
                self._deny(agent_id, tool, args, str(exc))

        self.audit.record(
            agent_id=agent_id,
            tool=tool,
            args=args,
            allowed=True,
            reason=decision.reason,
        )

    def call(self, agent_id: str, tool: str, args: dict[str, Any]) -> Any:
        """Authorize and, if permitted, dispatch to the registered tool."""
        self.authorize(agent_id, tool, args)
        if tool not in self._tools:
            raise KeyError(f"no implementation registered for tool {tool!r}")
        return self._tools[tool](**args)

    def _deny(
        self, agent_id: str, tool: str, args: dict[str, Any], reason: str
    ) -> None:
        self.audit.record(
            agent_id=agent_id,
            tool=tool,
            args=args,
            allowed=False,
            reason=reason,
        )
        raise GuardrailDenied(reason)
