# Security Policy

## Reporting a vulnerability

Please report security issues privately through
**GitHub → Security → Report a vulnerability** on this repository.
Do not open a public issue for a vulnerability.

Expect an acknowledgement within 72 hours.

## Scope

TenantTrace is a security testing tool. Two categories matter:

**In scope — vulnerabilities in TenantTrace itself**
- Code execution triggered by analysing untrusted source (the static engine
  must only ever *parse*, never import or execute the code under analysis).
- Credential leakage: tenant tokens appearing in logs, reports, or run
  artifacts that are meant to be shareable.
- Safety-rail bypass: probing a host that is not in `allowed_hosts`, or
  mutating data without `--allow-mutation`.

**Out of scope**
- Vulnerabilities found *by* TenantTrace in your own application. Those are
  yours to fix — that's the point of the tool.
- The deliberately vulnerable fixture app under `fixtures/vulnerable_app/`.
  It is insecure on purpose and must never be deployed anywhere reachable.

## Using this tool responsibly

TenantTrace sends adversarial requests and, with `--allow-mutation`, writes
data. Only point it at systems you own or are explicitly authorised to test.
Non-loopback targets require the `--i-have-authorization` flag; that flag is a
statement you are making, not a permission the tool grants you.
