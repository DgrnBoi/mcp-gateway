# Security Policy

## Reporting a Vulnerability

The MCP Security Gateway is a **security-critical product**: it sits between AI agents and their tool servers, so a bypass in this product is a bypass of your policy enforcement. We take that responsibility seriously, and we ask you to.

**Do NOT report security vulnerabilities by opening a public GitHub issue.** A public report of an authorization bypass, identity spoofing, or quarantine escape is, effectively, a working exploit published to every user before a fix exists.

Instead, report confidentially to the security team at:

> **security@mcp-gateway.dev**

If that address is not yet live at the time of your report, use the placeholder format and the repository maintainers will forward your message. We commit to:

- An acknowledgment of your report within **5 business days**.
- An initial assessment (accepted / needs more information / not a vulnerability) within **10 business days**.
- A fix, mitigation, or disclosure plan communicated to you before any public disclosure.

## Coordinated Vulnerability Disclosure (CVD)

1. **You report.** Send a report describing the vulnerability, the affected version, reproduction steps (attack fixtures in `tests/adversarial/attacks/` format are strongly encouraged), and your suggested remediation if you have one.
2. **We verify.** We will attempt to reproduce the issue in isolation and assess its severity.
3. **We fix and test.** Fixes for accepted vulnerabilities are developed in a private branch, tested against the full adversarial suite, and held to the same CI gates as all other changes (`go vet`, full suite under the race detector, latency benchmark <5ms, coverage ≥80%).
4. **We release.** A patched release is issued with a security advisory. Your handle and disclosure date will be credited in the release notes if you wish to be acknowledged.
5. **You may publish.** Public disclosure is requested to wait until the patched release is generally available. We ask for at most 90 days between acceptance and your publication if a fix is unreasonably delayed; we will never ask you to wait longer than 120 days.

## What We Consider a Vulnerability

- A policy rule that is bypassed, shadowed incorrectly, or mis-evaluated (including precedence and wildcard semantics).
- Identity extraction that can be spoofed (JWT/mTLS/fingerprint collisions).
- Unauthorized access to console resources (RBAC bypass, auditor-view payload leakage, export window bypass).
- Quarantine integrity failures (payload tampering, durable-storage bypass).
- Denial-of-service reachable from unauthenticated data-plane traffic (the 5ms latency budget and resource limits exist precisely for this reason).

## What Is Not a Vulnerability

- Issues requiring the attacker to already have admin access to the host running the gateway.
- Vulnerabilities in the upstream MCP server or the calling agent rather than the gateway itself.
- Missed features (e.g., a feature you believe should be enforced but is not) — please open a feature request instead.

## Supported Versions

Only the latest released major version receives security patches. Upgrade via the release tarballs or the distroless container image.
