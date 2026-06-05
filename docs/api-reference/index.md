# Python SDK API reference

This reference is generated from the source code. The public API is organised into four modules.

| Module | What it covers |
|--------|---------------|
| [Core models](models.md) | `Manifest`, `ArtifactBindings`, and all nested model types |
| [Signing](signing.md) | Key generation, `Ed25519Signer`, `Ed25519Verifier` |
| [Verification](verification.md) | `verify_manifest()`, `VerificationContext`, `VerificationResult`, `create_router()` |
| [Revocation](revocation.md) | `sign_revocation()`, `FileCRL`, `create_crl_router()` |
| [Delegation](delegation.md) | `DelegationHopSigner`, `verify_delegation_chain()`, `HitlApprovalSigner` |
| [Attestation](attestation.md) | `SEVSNPProvider`, `TDXProvider`, `OPAQUEProvider`, `TPMProvider`, `AttestationProvider` |
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
