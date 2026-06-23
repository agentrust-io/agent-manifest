# Tutorials

Step-by-step guides for specific agent-manifest features. Each tutorial is self-contained and includes runnable code.

If you are new to agent-manifest, start with [Getting Started](../getting-started.md) first  -  it covers creating and signing your first manifest in 15 minutes.

---

## Getting started

| Tutorial | What you'll build |
|----------|-------------------|
| [Your first manifest](your-first-manifest.md) | A signed Agent Manifest from scratch with Ed25519 key generation and CLI verification |
| [CI/CD signing](ci-cd-signing.md) | A GitHub Actions workflow that signs your manifest on every release |
| [cMCP session binding](cmcp-session-binding.md) | A cMCP gateway configured to verify and bind a signed manifest at session startup |

## Development

| Tutorial | What you'll build |
|----------|-------------------|
| [Server-side manifest verification](server-side-verification.md) | A FastAPI service that verifies incoming agent manifests and gates requests |
| [A2A delegation chains](delegation-chains.md) | A two-hop delegation chain with scope narrowing and chain verification |
| [HITL approval workflows](hitl-approval-workflows.md) | A manifest with a cryptographically signed human approval record |
| [Revocation and key rotation](revocation-and-key-rotation.md) | A signed revocation record, a live CRL endpoint, and a key rotation procedure |
| [Hardware attestation](hardware-attestation.md) | Hardware-bound attestation on SEV-SNP, TDX, and OPAQUE |

## Operations

| Tutorial | What you'll build |
|----------|-------------------|
| [Deploying the verification endpoint](deploying-the-verification-endpoint.md) | A containerised verifier with health checks, CRL, and Kubernetes deployment |
