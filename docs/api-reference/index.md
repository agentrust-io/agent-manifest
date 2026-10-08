# Python SDK API reference

This section documents every public class and function in the `agent-manifest` Python package. Use it when you are writing code against the SDK and need exact names, arguments and return types; if you are starting out, the [getting started guide](../getting-started.md) and the [tutorials](../tutorials/index.md) explain the same features step by step.

The pages below are generated from the docstrings in the source code, so they match the released package. The public API is organised into these areas.

| Module | What it covers |
|--------|---------------|
| [Core models](models.md) | `Manifest`, `ArtifactBindings`, and all nested model types |
| [Signing](signing.md) | Key generation, `Ed25519Signer`, `Ed25519Verifier` |
| [Verification](verification.md) | `verify_manifest()`, `VerificationContext`, `VerificationResult`, `create_router()` |
| [Revocation](revocation.md) | `sign_revocation()`, `FileCRL`, `create_crl_router()` |
| [Delegation](delegation.md) | `DelegationHopSigner`, `verify_delegation_chain()`, `HitlApprovalSigner` |
| [Attestation](attestation.md) | `SEVSNPProvider`, `TDXProvider`, `TPMProvider`, `AttestationProvider` |
| [CLI](cli.md) | `manifest create`, `sign`, `verify`, `revoke`, `keygen`, `attest` commands |

## Installation

```bash
# Core (signing, verification, models)
pip install agent-manifest

# With server (FastAPI router, revocation endpoint)
pip install "agent-manifest[server]"

# With post-quantum signatures (ML-DSA-65)
pip install "agent-manifest[pq]"

# Full
pip install "agent-manifest[all]"
```
