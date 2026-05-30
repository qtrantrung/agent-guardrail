"""Declarative policy model for constraining AI agent tool calls.

A policy is an ordered set of rules evaluated against a proposed *action*
(a tool name plus its arguments and the calling context). Evaluation is
**default-deny**: an action is only permitted if a matching ``allow`` rule
is found and no higher-priority ``deny`` rule matches first.

The model is intentionally small and dependency-free. It is meant to be read
and reasoned about by a security reviewer, not to be a general-purpose policy
language. Where a real deployment would reach for OPA/Rego or Cedar, this
demonstrates the enforcement semantics those engines provide.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Condition:
    """A single constraint on one argument of a tool call.

    Exactly one operator is expected per condition. Conditions are ANDed
    together within a rule: every condition must hold for the rule to match.
    """

    arg: str
    equals: Any = None
    one_of: tuple[Any, ...] | None = None
    matches: str | None = None  # regex, fully anchored
    max: float | None = None
    min: float | None = None

    def holds(self, args: dict[str, Any]) -> bool:
        # A condition on an absent argument never holds. This is deliberate:
        # an injected call that simply omits a constrained argument must not
        # slip past a rule that was written to bound that argument.
        if self.arg not in args:
            return False
        value = args[self.arg]

        if self.equals is not None and value != self.equals:
            return False
        if self.one_of is not None and value not in self.one_of:
            return False
        if self.matches is not None:
            if not isinstance(value, str):
                return False
            if re.fullmatch(self.matches, value) is None:
                return False
        if self.max is not None:
            if not isinstance(value, (int, float)) or value > self.max:
                return False
        if self.min is not None:
            if not isinstance(value, (int, float)) or value < self.min:
                return False
        return True

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Condition":
        one_of = d.get("one_of")
        return cls(
            arg=d["arg"],
            equals=d.get("equals"),
            one_of=tuple(one_of) if one_of is not None else None,
            matches=d.get("matches"),
            max=d.get("max"),
            min=d.get("min"),
        )


@dataclass(frozen=True)
class Rule:
    id: str
    effect: Effect
    # Glob against the tool name, e.g. "fs.read", "http.*", "*".
    tool: str = "*"
    # All conditions must hold for the rule to match the action's arguments.
    conditions: tuple[Condition, ...] = ()
    # Optional: restrict the rule to specific agent identities.
    agents: tuple[str, ...] | None = None
    # Lower number = evaluated earlier. Deny-by-default means a tie goes to deny.
    priority: int = 100
    description: str = ""

    def matches_action(self, tool: str, args: dict[str, Any], agent_id: str) -> bool:
        if self.agents is not None and agent_id not in self.agents:
            return False
        if not fnmatch.fnmatchcase(tool, self.tool):
            return False
        return all(c.holds(args) for c in self.conditions)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Rule":
        agents = d.get("agents")
        return cls(
            id=d["id"],
            effect=Effect(d["effect"]),
            tool=d.get("tool", "*"),
            conditions=tuple(Condition.from_dict(c) for c in d.get("conditions", [])),
            agents=tuple(agents) if agents is not None else None,
            priority=int(d.get("priority", 100)),
            description=d.get("description", ""),
        )


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)

    @property
    def sorted_rules(self) -> list[Rule]:
        # Stable sort: explicit priority first, then deny before allow at the
        # same priority so the safe choice wins ties.
        return sorted(
            self.rules,
            key=lambda r: (r.priority, 0 if r.effect is Effect.DENY else 1),
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        return cls(rules=[Rule.from_dict(r) for r in d.get("rules", [])])

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)
