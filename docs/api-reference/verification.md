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

## TRACE envelopes and evidence packs

`EvidencePack` above is only a *reference* to a pack. To appraise the pack
itself, and the per-tool-call TRACE envelopes inside it, use:

```python
from agent_manifest import verify_evidence_pack, verify_trace_envelope
```

A TRACE envelope (spec §6.3.2) is signed by a TEE-sealed key over the RFC 8785
canonical form of every field except `signature`. The envelope carries no
algorithm or key id of its own, so the caller supplies both; `trusted_keys` uses
the same `key_id` → base64url public key mapping as `VerificationContext`. An
evidence pack (spec §5.2.1) instead carries a detached `pack_signature` object
in the form of §3.6, so hybrid signatures work there but not on envelopes.

Read `admissible`, not just `status`. A TRACE reporting
`manifest_verification_result: MISMATCH` or `EXPIRED` can have a perfectly valid
signature — the runtime honestly recorded a bad state — but spec §6.3.2 says it
"MUST NOT be accepted as evidence of a valid tool call for regulatory reporting
purposes". `verify_trace_envelope()` returns `status=VERIFIED` with
`admissible=False` in that case.

Passing `manifest=` additionally enforces the §6.3.2 hash-conflict rule
(SCHEMA F-21): if the envelope's `policy_hash` differs from the manifest's
`artifacts.policy_bundle.hash`, the envelope must declare `MISMATCH`. One that
claims `VALID` over a conflicting hash is a spec violation and fails.

Verification is fail-closed: a missing key, an unknown algorithm, or a build
without the `[pq]` extra yields `UNVERIFIABLE`, never `VERIFIED`.

::: agent_manifest._trace.verify_trace_envelope

::: agent_manifest._trace.verify_evidence_pack

::: agent_manifest._trace.TraceVerificationResult

::: agent_manifest._trace.EvidencePackVerificationResult

::: agent_manifest._trace.TraceStatus

`compute_pack_hash()` returns the spec §5.2.1 `pack_hash` — the SHA-256 of the
pack's canonical bytes excluding `pack_signature`. `trace_signing_pre_image()`
and `evidence_pack_pre_image()` are the shared pre-image functions; producers
and verifiers MUST both use them so the byte sequences match.

::: agent_manifest._trace.compute_pack_hash

::: agent_manifest._trace.trace_signing_pre_image

::: agent_manifest._trace.evidence_pack_pre_image

## Revocation

`RevocationStore` is the revocation lookup a verifier consults during
`verify_manifest()`; the default is in-memory, and production deployments back it
with a persistent store. `RevocationRecord` is a single revocation entry: which
manifest was revoked, when, why, and by whom.

::: agent_manifest._verify.RevocationStore

::: agent_manifest._verify.RevocationRecord

## FastAPI router

::: agent_manifest._verify.create_router
