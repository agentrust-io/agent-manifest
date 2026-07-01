# Tutorials

Step-by-step guides for specific agent-manifest features. Each tutorial is self-contained and includes runnable code.

If you are new to agent-manifest, start with [Getting Started](https://manifest.agentrust-io.com/getting-started/index.md) first - it covers creating and signing your first manifest in 15 minutes.

______________________________________________________________________

## Getting started

| Tutorial                                                                                          | What you'll build                                                                     |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| [Your first manifest](https://manifest.agentrust-io.com/tutorials/your-first-manifest/index.md)   | A signed Agent Manifest from scratch with Ed25519 key generation and CLI verification |
| [CI/CD signing](https://manifest.agentrust-io.com/tutorials/ci-cd-signing/index.md)               | A GitHub Actions workflow that signs your manifest on every release                   |
| [cMCP session binding](https://manifest.agentrust-io.com/tutorials/cmcp-session-binding/index.md) | A cMCP gateway configured to verify and bind a signed manifest at session startup     |

## Development

| Tutorial                                                                                                           | What you'll build                                                             |
| ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| [Server-side manifest verification](https://manifest.agentrust-io.com/tutorials/server-side-verification/index.md) | A FastAPI service that verifies incoming agent manifests and gates requests   |
| [A2A delegation chains](https://manifest.agentrust-io.com/tutorials/delegation-chains/index.md)                    | A two-hop delegation chain with scope narrowing and chain verification        |
| [HITL approval workflows](https://manifest.agentrust-io.com/tutorials/hitl-approval-workflows/index.md)            | A manifest with a cryptographically signed human approval record              |
| [Revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md)    | A signed revocation record, a live CRL endpoint, and a key rotation procedure |
| [Hardware attestation](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md)                  | Hardware-bound attestation on SEV-SNP, TDX, and OPAQUE                        |

## Operations

| Tutorial                                                                                                                        | What you'll build                                                           |
| ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [Deploying the verification endpoint](https://manifest.agentrust-io.com/tutorials/deploying-the-verification-endpoint/index.md) | A containerised verifier with health checks, CRL, and Kubernetes deployment |
