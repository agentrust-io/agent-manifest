# Security Policy

## Scope

This policy covers:

- Vulnerabilities in the Agent Manifest Python SDK (`python/`)
- Cryptographic flaws in the Agent Manifest Specification (`spec/`)
- Weaknesses in the hardware attestation integration layer
- Issues with the conformance test suite that would cause non-conformant implementations to pass

Out of scope: general Python dependency vulnerabilities (use `pip-audit` for that), GitHub Actions supply chain issues, and issues with third-party TEE platforms (TPM, SEV-SNP, TDX, OPAQUE).

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/agentrust-io/agent-manifest/security/advisories/new) for all security issues. Do not file a public issue.

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (SDK bugs) or a counter-example proof sketch (spec flaws)
- The spec section or SDK module affected
- Whether you believe it affects implementations already in production

## Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 2 business days |
| Initial assessment | 5 business days |
| Patch or spec errata issued | 30 days for critical, 90 days for moderate |
| Public disclosure | Coordinated with reporter |

## Cryptographic issues

Specification-level cryptographic flaws (e.g., a flaw in the Merkle construction, an issue with the SHAKE-256 output length rule, or a weakness in the hybrid signature protocol) are treated as critical regardless of whether they affect the SDK. We aim to issue a spec errata within 14 days of confirmed cryptographic issues.

## Supported versions

Only the current release branch is supported for security patches. Pre-release versions (`0.1.0a*`) receive patches for critical issues only.
