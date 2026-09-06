# Tutorials

Start by signing a local demo configuration and testing what happens when it changes. Then choose the guide for the boundary you need to enforce.

The [first-manifest example](../getting-started.md) supplies the record, keys, and approved inputs used by several follow-up guides. Those pages say where to append their code. Hardware and cMCP integration guidance identifies additional setup and verification requirements.

---

## Getting started

| Tutorial | What you'll build |
|----------|-------------------|
| [Your first manifest](your-first-manifest.md) | A signed Agent Manifest from scratch with Ed25519 key generation and CLI verification |
| [CI/CD signing](ci-cd-signing.md) | Signing and verification scripts, plus a workflow triggered by manifest changes on `main` |
| [cMCP session binding](cmcp-session-binding.md) | Configuration guidance and the meaning of the gateway's identity evidence |

## Development

| Tutorial | What you'll build |
|----------|-------------------|
| [Server-side manifest verification](server-side-verification.md) | A local request gate tested with accepted, missing, unknown, and mismatched inputs |
| [A2A delegation chains](delegation-chains.md) | A two-hop delegation chain with scope narrowing and chain verification |
| [HITL approval workflows](hitl-approval-workflows.md) | A synthetic approval signed with a software key, with missing and altered approval rejection |
| [Revocation and key rotation](revocation-and-key-rotation.md) | A signed revocation, explicit reader refresh, untrusted-signer rejection, and rotation guidance |
| [Hardware attestation](hardware-attestation.md) | A runnable software binding example, hardware provider selection, and evidence appraisal boundaries |

## Operations

| Tutorial | What you'll build |
|----------|-------------------|
| [Run a verification service](deploying-the-verification-endpoint.md) | A local HTTP verifier with startup-loaded trust and signed revocations, plus container packaging |
