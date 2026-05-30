"""agent-guardrail: a small, auditable policy-enforcement layer for AI agents.

Public API:

    from agent_guardrail import Gateway, Policy, GuardrailDenied
    from agent_guardrail import EgressAllowlist, RateLimiter, AuditLog
"""

from .audit import AuditEntry, AuditLog
from .controls import (
    EgressAllowlist,
    EgressError,
    RateLimiter,
    RateLimitError,
)
from .engine import Decision, PolicyEngine
from .gateway import Gateway, GuardrailDenied
from .policy import Condition, Effect, Policy, Rule

__all__ = [
    "Gateway",
    "GuardrailDenied",
    "Policy",
    "Rule",
    "Condition",
    "Effect",
    "PolicyEngine",
    "Decision",
    "EgressAllowlist",
    "EgressError",
    "RateLimiter",
    "RateLimitError",
    "AuditLog",
    "AuditEntry",
]

__version__ = "0.1.0"
