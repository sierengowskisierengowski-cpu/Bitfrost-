# Security Policy

## Supported Versions

Bifrost is currently in **v0.1.x** early public testing. Security fixes are prioritized on the latest v0.1.x branch.

| Version | Supported |
|---|---|
| v0.1.x | ✅ Yes |
| < v0.1.0 | ❌ No |

## Security Posture (v0.1)

Bifrost is currently recommended for **monitor-only operation** in real environments:

- `learning_mode=true`
- `dry_run=true`
- `autonomous_actions_enabled=false`

Do not enable destructive autonomous response in production-like environments until you validate behavior against your own telemetry and rollback procedures.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately and responsibly.

### Preferred channel

- Open a **private security advisory/report** on GitHub Security (if enabled), or
- Email the maintainer directly (if listed in repository profile/contact)

### Please include

1. Affected component(s) and file path(s)
2. Reproduction steps
3. Expected vs actual behavior
4. Impact assessment (confidentiality/integrity/availability)
5. Suggested fix (if available)
6. Logs, stack traces, or PoC (sanitized)

## Disclosure Process

1. Report received and triaged
2. Impact and exploitability assessed
3. Fix developed and validated
4. Coordinated disclosure and release notes published

Target response times (best effort):

- Initial acknowledgement: within **72 hours**
- Triage update: within **7 days**
- Fix timeline: depends on severity and complexity

## Scope Guidance

In-scope examples:

- Authentication/authorization bypass in local APIs
- Unsafe action execution path or policy bypass
- Queue/ingest handling flaws causing silent telemetry loss
- Input validation bugs that enable command injection
- Data leak paths that bypass anonymization policy

Out-of-scope examples:

- Vulnerabilities only affecting unsupported/modified forks
- Issues requiring physical access without software exploit path
- Theoretical findings with no practical impact path

## Hardening Recommendations

For operators running Bifrost on live systems:

- Run under a dedicated low-privilege service account where possible
- Restrict local ingest interfaces and Unix socket permissions
- Protect secrets via environment variables or secret managers
- Enable filesystem and process protections in service units
- Keep dependencies and host OS patched

## Safe Testing Notice

When testing with real adversarial data (e.g., honeypot sessions), assume payloads may contain prompt injection and hostile strings. Validate output through schema and policy gates before any enforcement path.
