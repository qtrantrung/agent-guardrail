"""Tamper-evident audit log for agent actions.

Every authorization decision is recorded as an append-only entry. Each entry
embeds the SHA-256 hash of the previous entry, forming a hash chain: altering
or removing any historical record invalidates every hash that follows it, and
:meth:`AuditLog.verify` will detect the break.

This does not protect against an attacker who can rewrite the *entire* log and
recompute the chain (for that you anchor the head hash externally -- e.g.,
periodically write it to append-only cloud storage or a transparency log). It
does give you a cheap, dependency-free integrity check and a clean tamper
signal, which is the point: bounded, auditable operational risk.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: float
    agent_id: str
    tool: str
    args: dict[str, Any]
    allowed: bool
    reason: str
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "args": self.args,
            "allowed": self.allowed,
            "reason": self.reason,
            "prev_hash": self.prev_hash,
        }
        # sort_keys makes the serialization canonical so the hash is stable.
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class AuditLog:
    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def head_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def record(
        self,
        *,
        agent_id: str,
        tool: str,
        args: dict[str, Any],
        allowed: bool,
        reason: str,
        timestamp: float | None = None,
    ) -> AuditEntry:
        prev = self.head_hash
        base = AuditEntry(
            seq=len(self.entries),
            timestamp=time.time() if timestamp is None else timestamp,
            agent_id=agent_id,
            tool=tool,
            args=args,
            allowed=allowed,
            reason=reason,
            prev_hash=prev,
        )
        entry = AuditEntry(**{**asdict(base), "entry_hash": base.compute_hash()})
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        """Return True iff the chain is internally consistent."""
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            if entry.seq != i or entry.prev_hash != prev:
                return False
            if entry.compute_hash() != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(asdict(e), sort_keys=True) for e in self.entries
        )
