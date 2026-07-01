# Python SDK API reference

This reference is generated from the source code. The public API is organised into four modules.

| Module                                                                                | What it covers                                                                          |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [Core models](https://manifest.agentrust-io.com/api-reference/models/index.md)        | `Manifest`, `ArtifactBindings`, and all nested model types                              |
| [Signing](https://manifest.agentrust-io.com/api-reference/signing/index.md)           | Key generation, `Ed25519Signer`, `Ed25519Verifier`                                      |
| [Verification](https://manifest.agentrust-io.com/api-reference/verification/index.md) | `verify_manifest()`, `VerificationContext`, `VerificationResult`, `create_router()`     |
| [Revocation](https://manifest.agentrust-io.com/api-reference/revocation/index.md)     | `sign_revocation()`, `FileCRL`, `create_crl_router()`                                   |
| [Delegation](https://manifest.agentrust-io.com/api-reference/delegation/index.md)     | `DelegationHopSigner`, `verify_delegation_chain()`, `HitlApprovalSigner`                |
| [Attestation](https://manifest.agentrust-io.com/api-reference/attestation/index.md)   | `SEVSNPProvider`, `TDXProvider`, `OPAQUEProvider`, `TPMProvider`, `AttestationProvider` |
| [CLI](https://manifest.agentrust-io.com/api-reference/cli/index.md)                   | `manifest create`, `sign`, `verify`, `revoke`, `keygen`, `attest` commands              |

## Installation

```
# Core (signing, verification, models)
pip install agent-manifest

# With server (FastAPI router, revocation endpoint)
pip install "agent-manifest[server]"

# With post-quantum signatures (ML-DSA-65)
pip install "agent-manifest[pq]"

# Full
pip install "agent-manifest[all]"
```
