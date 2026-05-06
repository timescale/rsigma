# Security Policy

## Supported Versions

Only the latest release is supported with security updates. We recommend always running the most recent version.

| Version | Supported |
| ------- | --------- |
| latest  | Yes       |
| < latest | No       |

## Reporting a Vulnerability

If you discover a security vulnerability in rsigma, please report it responsibly. **Do not open a public GitHub issue.**

Instead, use [GitHub Security Advisories](https://github.com/timescale/rsigma/security/advisories/new) to report the vulnerability privately. This allows us to assess the issue, develop a fix, and coordinate disclosure before the details become public.

You can expect an initial response within 72 hours. We will work with you to understand the scope and impact, and will credit reporters in the release notes unless anonymity is requested.

## Scope

The following areas are in scope for security reports:

- SQL injection or query manipulation in conversion backends
- Denial of service via crafted Sigma rules or events (unbounded recursion, memory exhaustion, regex catastrophic backtracking)
- Path traversal or arbitrary file access in rule loading
- Authentication or authorization bypass in the daemon HTTP API
- Supply chain issues (compromised dependencies, unsigned artifacts)
- Container escape or privilege escalation in the Docker image

## Security Hardening

rsigma ships with several built-in protections:

- **Input validation**: SQL identifiers are validated against an allowlist pattern before interpolation into queries.
- **Recursion limits**: YAML deep-merge and condition parsing enforce depth and length caps.
- **Event size caps**: The daemon rejects individual event lines exceeding 1 MB.
- **Dependency auditing**: `cargo-deny` and `cargo audit` run in CI on every push. Dependabot monitors for known vulnerabilities weekly.
- **Container image signing**: Docker images are signed with keyless cosign (Sigstore/Fulcio OIDC) and include SBOM and SLSA Build L3 provenance attestations.
- **Binary provenance**: Release binaries are built with SLSA Build L3 provenance via `actions/attest-build-provenance`.

When running the daemon in production, we recommend the following Docker flags:

```bash
docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  ghcr.io/timescale/rsigma:latest daemon ...
```
