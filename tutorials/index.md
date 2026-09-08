# Tutorials

Start by signing a local demo configuration and testing what happens when it changes. Then choose the guide for the boundary you need to enforce.

The [first-manifest example](https://manifest.agentrust-io.com/getting-started/index.md) supplies the record, keys, and approved inputs used by several follow-up guides. Those pages say where to append their code. Hardware and cMCP integration guidance identifies additional setup and verification requirements.

______________________________________________________________________

## Getting started

| Tutorial                                                                                          | What you'll build                                                                         |
| ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Your first manifest](https://manifest.agentrust-io.com/tutorials/your-first-manifest/index.md)   | A signed Agent Manifest from scratch with Ed25519 key generation and CLI verification     |
| [CI/CD signing](https://manifest.agentrust-io.com/tutorials/ci-cd-signing/index.md)               | Signing and verification scripts, plus a workflow triggered by manifest changes on `main` |
| [cMCP session binding](https://manifest.agentrust-io.com/tutorials/cmcp-session-binding/index.md) | Configuration guidance and the meaning of the gateway's identity evidence                 |

## Development

| Tutorial                                                                                                           | What you'll build                                                                                   |
| ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| [Server-side manifest verification](https://manifest.agentrust-io.com/tutorials/server-side-verification/index.md) | A local request gate tested with accepted, missing, unknown, and mismatched inputs                  |
| [A2A delegation chains](https://manifest.agentrust-io.com/tutorials/delegation-chains/index.md)                    | A two-hop delegation chain with scope narrowing and chain verification                              |
| [HITL approval workflows](https://manifest.agentrust-io.com/tutorials/hitl-approval-workflows/index.md)            | A synthetic approval signed with a software key, with missing and altered approval rejection        |
| [Revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md)    | A signed revocation, explicit reader refresh, untrusted-signer rejection, and rotation guidance     |
| [Hardware attestation](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md)                  | A runnable software binding example, hardware provider selection, and evidence appraisal boundaries |

## Operations

| Tutorial                                                                                                               | What you'll build                                                                                |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [Run a verification service](https://manifest.agentrust-io.com/tutorials/deploying-the-verification-endpoint/index.md) | A local HTTP verifier with startup-loaded trust and signed revocations, plus container packaging |
