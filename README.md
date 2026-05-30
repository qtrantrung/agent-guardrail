# agent-guardrail

A small, auditable **policy-enforcement layer for AI agent tool calls**.

`ai-agent-guard` sits between an AI agent and the tools it can invoke. Every
proposed tool call passes through a single choke point that applies
least-privilege policy, runtime controls (egress allowlisting, rate limiting),
and writes a tamper-evident audit record - *before* anything executes. The goal
is to turn the open-ended, probabilistic behaviour of an agent into **bounded,
auditable operational risk**.

It is pure Python standard library — no dependencies, no install friction — so
the trust-critical logic is small enough to read in one sitting.

```text
agent  ──proposes──▶  Gateway  ──┬─▶ rate limit (fail fast)
                                 ├─▶ policy engine (default-deny)
                                 ├─▶ egress allowlist (network tools)
                                 ├─▶ audit log (allow AND deny)
                                 └─▶ dispatch to the real tool
```

## Why this exists

When you give an LLM agent real tools — a shell, a filesystem, an HTTP client —
the agent's instructions are no longer fully under your control. A
[prompt injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
delivered through a web page, a document, or another agent can redirect it into
doing something you never intended: reading secrets, deleting data, or
exfiltrating information to an attacker-controlled host.

You cannot make the model immune to being convinced. What you *can* do is make
sure that no matter what the model decides, the **actions it is capable of
taking are bounded by policy you control, and every attempt is recorded**. That
is a classic least-privilege / defence-in-depth posture — applied to the agent
as the untrusted principal.

## Threat model

**Assume the agent is untrusted.** Treat the model's chosen tool calls the way
you would treat input from a partially-compromised client.

| Threat | Mitigation in this library |
|---|---|
| Injected agent calls a dangerous tool (`shell.exec`, etc.) | Default-deny policy; nothing runs without a matching `allow` rule. Explicit `deny` rules win ties. |
| Injected agent broadens a legitimate tool's scope (reads `/etc/shadow` via an allowed `fs.read`) | Per-argument **conditions** (regex / range / set membership) bound *how* a tool may be used, not just *whether*. |
| Data exfiltration to an attacker host | **Egress allowlist**: network tools may only reach explicitly approved destinations. |
| Runaway or hijacked agent loop amplifying damage | Per-agent **rate limiting** over a sliding window. |
| After-the-fact tampering to hide what happened | **Hash-chained audit log**; any edit or deletion breaks `verify()`. Denials are logged too, so you see what was *attempted*. |
| One agent impersonating another's privileges | Rules can be **scoped to specific agent identities**. |

### Out of scope (deliberately)

- **Authenticating the agent identity.** The gateway trusts the `agent_id` it is
  given; bind that to a real workload identity upstream (mTLS, signed tokens).
- **Total-rewrite of the audit log.** A hash chain detects edits *within* a log
  but not an attacker who replaces the whole file and recomputes it. Anchor the
  head hash externally — periodically append it to immutable object storage or a
  transparency log.
- **Semantic judgement of tool *outputs*.** This bounds what an agent may *do*,
  not whether a returned document is itself malicious.

These are noted because honest scoping is part of the design: a guardrail that
overstates its guarantees is worse than one whose limits are written down.

## Install / run

No dependencies. Clone and run the tests:

```bash
git clone https://github.com/qtrantrung/agent-guardrail.git
cd agent-guardrail
PYTHONPATH=src python -m unittest discover -s tests -v   # 23 tests
PYTHONPATH=src python examples/demo.py                   # end-to-end walkthrough
```

## Usage

```python
from agent_guardrail import Gateway, Policy, EgressAllowlist, RateLimiter, GuardrailDenied

gateway = Gateway(
    Policy.from_file("examples/policy.json"),
    egress=EgressAllowlist(["api.vendor.example"]),
    rate_limiter=RateLimiter(max_calls=20, window_seconds=60),
    network_tools={"http.get"},
)
gateway.register_tool("http.get", my_http_get)

try:
    result = gateway.call(agent_id="ops-assistant",
                          tool="http.get",
                          args={"url": "https://api.vendor.example/status"})
except GuardrailDenied as exc:
    # The denial is already in the audit log; handle/return safely.
    log.warning("blocked: %s", exc.reason)
```

Policies are declarative JSON, so they can live in version control and ship
through the same review and IaC pipeline as the rest of your infrastructure:

```json
{
  "rules": [
    { "id": "deny-shell", "effect": "deny", "tool": "shell.*", "priority": 10 },
    { "id": "allow-kb-read", "effect": "allow", "tool": "fs.read", "priority": 50,
      "conditions": [{ "arg": "path", "matches": "/srv/knowledge_base/.*" }] }
  ]
}
```

## Design notes

- **Default-deny, first-match.** Rules are evaluated in priority order; deny
  beats allow on a tie. There is no rule blending, so a decision is always
  traceable to exactly one rule (or to the default).
- **The decision is pure.** `PolicyEngine.evaluate` has no side effects, which
  keeps the trust-critical code easy to test exhaustively. Dispatch and logging
  live in the gateway.
- **Denials are first-class.** They raise rather than return, so a caller cannot
  mistake a blocked action for a successful one, and they are audited like any
  allowed call.
- **Missing constrained arguments fail closed.** A call that simply omits an
  argument a rule was written to bound does not slip through.

## Where this maps to a real deployment

This is a focused reference implementation, not a finished product. In a real
system you would: source the egress allowlist from the same IaC that provisions
the network egress proxy; back the rate limiter with a shared store; replace the
JSON policy with a managed engine (OPA/Rego, Cedar) if your rules grow; and
anchor the audit head hash into append-only storage. The enforcement *semantics*
demonstrated here are what those components would provide.

## Layout

```
src/agent_guardrail/
  policy.py     # declarative rule + condition model, JSON loading
  engine.py     # pure default-deny evaluation -> Decision
  controls.py   # egress allowlist + sliding-window rate limiter
  audit.py      # hash-chained, tamper-evident audit log
  gateway.py    # the choke point: ties it together, dispatches tools
tests/          # 23 unit tests (engine, controls, audit, gateway)
examples/       # policy.json + runnable demo.py
```

## License

MIT
