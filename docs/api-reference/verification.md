# Verification

The core verification engine and FastAPI router. See [Tutorial: Server-side verification](../tutorials/server-side-verification.md) for usage examples.

## Public API

For gateway and runtime-session binding, call the package-root export rather than
the private `_verify` module:

```python
from agent_manifest import RevocationStore, VerificationContext, verify_manifest
```

`verify_manifest()` is the supported high-level entry point.
`VerificationContext.trusted_keys` maps an issuer `key_id` (the SHA-256 hex of
the public key bytes) to its base64url-encoded Ed25519 public key, the form
returned by `Ed25519KeyPair.public_b64url()`. A consumer that holds raw public
key bytes must base64url-encode them before populating `trusted_keys`. Signers
and verifiers share `agent_manifest.signing_pre_image()` for the exact RFC 8785
canonical byte sequence, including the `hitl_record.approvals` normalization, so
a relying party never reconstructs the pre-image itself.

## Core function

::: agent_manifest._verify.verify_manifest

## Context

::: agent_manifest._verify.VerificationContext

## Results

::: agent_manifest._verify.VerificationResult

::: agent_manifest._verify.OverallResult

::: agent_manifest._verify.FieldsVerified

::: agent_manifest._verify.FieldResult

::: agent_manifest._verify.DelegationResult

::: agent_manifest._verify.HitlResult

::: agent_manifest._verify.MismatchDetail

`EvidencePack` is an optional reference (trace id, signer, hash, and URI) to an
externally retained evidence pack that a verifier can record alongside a result.

::: agent_manifest._verify.EvidencePack

## Revocation

`RevocationStore` is the revocation lookup a verifier consults during
`verify_manifest()`; the default is in-memory, and production deployments back it
with a persistent store. `RevocationRecord` is a single revocation entry: which
manifest was revoked, when, why, and by whom.

::: agent_manifest._verify.RevocationStore

::: agent_manifest._verify.RevocationRecord

## FastAPI router

::: agent_manifest._verify.create_router
