import unittest

from agent_guardrail import (
    EgressAllowlist,
    EgressError,
    PolicyEngine,
    Policy,
    RateLimiter,
    RateLimitError,
)


def make_policy() -> Policy:
    return Policy.from_dict(
        {
            "rules": [
                {"id": "deny-shell", "effect": "deny", "tool": "shell.*", "priority": 10},
                {
                    "id": "allow-read-kb",
                    "effect": "allow",
                    "tool": "fs.read",
                    "priority": 50,
                    "conditions": [{"arg": "path", "matches": "/srv/kb/.*"}],
                },
                {
                    "id": "allow-ticket",
                    "effect": "allow",
                    "tool": "tickets.create",
                    "agents": ["ops"],
                    "priority": 50,
                    "conditions": [{"arg": "severity", "one_of": ["low", "medium"]}],
                },
            ]
        }
    )


class TestPolicyEngine(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine(make_policy())

    def test_default_deny_for_unknown_tool(self):
        d = self.engine.evaluate("email.send", {"to": "x@y.z"}, "ops")
        self.assertFalse(d.allowed)
        self.assertIsNone(d.matched_rule)

    def test_allow_when_condition_holds(self):
        d = self.engine.evaluate("fs.read", {"path": "/srv/kb/a.md"}, "ops")
        self.assertTrue(d.allowed)
        self.assertEqual(d.matched_rule, "allow-read-kb")

    def test_deny_when_condition_fails(self):
        d = self.engine.evaluate("fs.read", {"path": "/etc/shadow"}, "ops")
        self.assertFalse(d.allowed)

    def test_missing_constrained_arg_is_denied(self):
        # An injected call that omits the constrained arg must not pass.
        d = self.engine.evaluate("fs.read", {}, "ops")
        self.assertFalse(d.allowed)

    def test_explicit_deny_beats_lower_priority(self):
        d = self.engine.evaluate("shell.exec", {"cmd": "rm -rf /"}, "ops")
        self.assertFalse(d.allowed)
        self.assertEqual(d.matched_rule, "deny-shell")

    def test_agent_scoping(self):
        ok = self.engine.evaluate("tickets.create", {"severity": "low"}, "ops")
        self.assertTrue(ok.allowed)
        nope = self.engine.evaluate("tickets.create", {"severity": "low"}, "intruder")
        self.assertFalse(nope.allowed)

    def test_one_of_rejects_out_of_set_value(self):
        d = self.engine.evaluate("tickets.create", {"severity": "critical"}, "ops")
        self.assertFalse(d.allowed)


class TestEgress(unittest.TestCase):
    def test_allows_listed_host(self):
        EgressAllowlist(["api.ok.example"]).check_url("https://api.ok.example/v1")

    def test_blocks_unlisted_host(self):
        with self.assertRaises(EgressError):
            EgressAllowlist(["api.ok.example"]).check_url("https://evil.example/x")

    def test_blocks_unparseable_url(self):
        with self.assertRaises(EgressError):
            EgressAllowlist(["api.ok.example"]).check_url("not a url")


class TestRateLimiter(unittest.TestCase):
    def test_allows_up_to_limit_then_blocks(self):
        rl = RateLimiter(max_calls=2, window_seconds=10)
        rl.check("a", now=0.0)
        rl.check("a", now=1.0)
        with self.assertRaises(RateLimitError):
            rl.check("a", now=2.0)

    def test_window_slides(self):
        rl = RateLimiter(max_calls=1, window_seconds=10)
        rl.check("a", now=0.0)
        with self.assertRaises(RateLimitError):
            rl.check("a", now=5.0)
        rl.check("a", now=11.0)  # first event aged out

    def test_per_agent_isolation(self):
        rl = RateLimiter(max_calls=1, window_seconds=10)
        rl.check("a", now=0.0)
        rl.check("b", now=0.0)  # different agent, own budget


if __name__ == "__main__":
    unittest.main()
