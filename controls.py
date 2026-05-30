"""Policy enforcement engine.

Given a :class:`~agent_guardrail.policy.Policy`, decide whether a proposed
agent action is permitted. The engine is pure and side-effect free: it returns
a :class:`Decision` and never executes anything itself. Logging and the actual
tool dispatch live in the gateway, keeping the trust-critical decision logic
small and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .policy import Effect, Policy, Rule


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched_rule: str | None = None

    def __bool__(self) -> bool:
        return self.allowed


class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def evaluate(
        self, tool: str, args: dict[str, Any], agent_id: str
    ) -> Decision:
        """Return the first matching rule's effect, or default-deny.

        Rules are considered in priority order (deny wins ties). The first
        rule that matches the action is decisive; there is no rule blending,
        which keeps the outcome easy to predict and to audit.
        """
        for rule in self._policy.sorted_rules:
            if rule.matches_action(tool, args, agent_id):
                if rule.effect is Effect.ALLOW:
                    return Decision(
                        allowed=True,
                        reason=f"allowed by rule '{rule.id}'",
                        matched_rule=rule.id,
                    )
                return Decision(
                    allowed=False,
                    reason=f"denied by rule '{rule.id}'",
                    matched_rule=rule.id,
                )
        return Decision(
            allowed=False,
            reason="no matching allow rule (default-deny)",
            matched_rule=None,
        )
