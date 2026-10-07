# Python SDK API reference

This section documents every public class and function in the `agent-manifest` Python package. Use it when you are writing code against the SDK and need exact names, arguments and return types; if you are starting out, the [getting started guide](https://manifest.agentrust-io.com/getting-started/index.md) and the [tutorials](https://manifest.agentrust-io.com/tutorials/index.md) explain the same features step by step.

The pages below are generated from the docstrings in the source code, so they match the released package. The public API is organised into these areas.

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
