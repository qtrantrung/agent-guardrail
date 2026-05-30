import unittest
from dataclasses import replace

from agent_guardrail import (
    AuditLog,
    EgressAllowlist,
    Gateway,
    GuardrailDenied,
    Policy,
    RateLimiter,
)


class TestAuditLog(unittest.TestCase):
    def _populate(self) -> AuditLog:
        log = AuditLog()
        log.record(agent_id="a", tool="fs.read", args={"path": "/x"},
                   allowed=True, reason="ok", timestamp=1.0)
        log.record(agent_id="a", tool="shell.exec", args={"cmd": "rm"},
                   allowed=False, reason="denied", timestamp=2.0)
        return log

    def test_clean_chain_verifies(self):
        self.assertTrue(self._populate().verify())

    def test_records_denials_too(self):
        log = self._populate()
        self.assertEqual(sum(not e.allowed for e in log.entries), 1)

    def test_tampering_with_a_field_breaks_chain(self):
        log = self._populate()
        # Flip a denial into an allow without recomputing hashes.
        log.entries[1] = replace(log.entries[1], allowed=True)
        self.assertFalse(log.verify())

    def test_deleting_an_entry_breaks_chain(self):
        log = self._populate()
        del log.entries[0]
        self.assertFalse(log.verify())

    def test_head_hash_changes_with_appends(self):
        log = AuditLog()
        h0 = log.head_hash
        log.record(agent_id="a", tool="t", args={}, allowed=True,
                   reason="r", timestamp=1.0)
        self.assertNotEqual(h0, log.head_hash)


class TestGateway(unittest.TestCase):
    def _gateway(self) -> Gateway:
        policy = Policy.from_dict(
            {
                "rules": [
                    {"id": "deny-shell", "effect": "deny", "tool": "shell.*", "priority": 10},
                    {"id": "allow-http", "effect": "allow", "tool": "http.get", "priority": 50},
                ]
            }
        )
        gw = Gateway(
            policy,
            egress=EgressAllowlist(["ok.example"]),
            rate_limiter=RateLimiter(max_calls=3, window_seconds=60),
            network_tools={"http.get"},
        )
        gw.register_tool("http.get", lambda url: f"GET {url}")
        return gw

    def test_allowed_call_dispatches_and_audits(self):
        gw = self._gateway()
        out = gw.call("a", "http.get", {"url": "https://ok.example/p"})
        self.assertIn("ok.example", out)
        self.assertTrue(gw.audit.entries[-1].allowed)

    def test_denied_call_raises_and_audits_denial(self):
        gw = self._gateway()
        with self.assertRaises(GuardrailDenied):
            gw.call("a", "shell.exec", {"cmd": "x"})
        self.assertFalse(gw.audit.entries[-1].allowed)

    def test_egress_block_is_enforced_even_when_policy_allows(self):
        gw = self._gateway()
        with self.assertRaises(GuardrailDenied):
            gw.call("a", "http.get", {"url": "https://evil.example/x"})

    def test_rate_limit_blocks_after_budget(self):
        gw = self._gateway()
        for _ in range(3):
            gw.call("a", "http.get", {"url": "https://ok.example/p"})
        with self.assertRaises(GuardrailDenied):
            gw.call("a", "http.get", {"url": "https://ok.example/p"})

    def test_audit_chain_intact_after_mixed_traffic(self):
        gw = self._gateway()
        gw.call("a", "http.get", {"url": "https://ok.example/p"})
        try:
            gw.call("a", "shell.exec", {"cmd": "x"})
        except GuardrailDenied:
            pass
        self.assertTrue(gw.audit.verify())


if __name__ == "__main__":
    unittest.main()
