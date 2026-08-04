# COSE envelope (manifest version 0.2)

The signature envelope for manifest version `0.2`. Version `0.1` manifests keep verifying through the [signing](signing.md) API exactly as before: the envelope follows the manifest `version` field, never a flag.

Normative reference: [`spec/agent-manifest-cose-envelope-v0.2.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-cose-envelope-v0.2.md). Decisions: [ADR-0011](../adr/0011-signature-envelope.md) (why COSE), [ADR-0013](../adr/0013-cbor-library-for-cose.md) (why no COSE library), [ADR-0014](../adr/0014-fully-specified-ed25519-code-point.md) (why `-19`).

## What changes from v0.1

| | v0.1 | v0.2 |
|---|---|---|
| Envelope | Detached signature block over an RFC 8785 pre-image | `COSE_Sign1` (tag 18), or `COSE_Sign` (tag 98) for hybrid |
| Algorithm binding | `signature.algorithm`, outside the signature | `alg` in the protected header, covered by the signature |
| Verification input | Re-serialise, then compare | The payload as received; nothing is re-serialised |
| Receipts, attestation, approvals | Top-level fields with ordering rules | Unprotected header, evaluated after the signature |
| Hardware binds | A hash over a field subset | `sha256` of the payload bytes |

RFC 8785 has not gone away. It remains the producer-side determinism rule and the basis of the hash bound into hardware; what changed is that a verifier no longer has to reproduce it.

## Signing

```python
from agent_manifest import generate_ed25519, sign_manifest_cose

keypair = generate_ed25519()
envelope = sign_manifest_cose(manifest, keypair)   # bytes, tagged CBOR
```

`sign_manifest_cose` selects the structure from the key: a single-algorithm keypair produces `COSE_Sign1`, a `HybridKeyPair` produces one `COSE_Sign` with two signers. Signing refuses a manifest whose `version` is not `0.2`.

::: agent_manifest._cose.sign_manifest_cose

::: agent_manifest._cose.sign_cose_sign1

::: agent_manifest._cose.sign_cose_sign_hybrid

::: agent_manifest._cose.cose_payload

::: agent_manifest._cose.payload_hash

## Attaching what comes after signing

A receipt, a TEE attestation report, and HITL approvals are all produced after the manifest is signed. They attach to the unprotected header, so attaching one never invalidates the signature.

```python
from agent_manifest import attach_receipt, attach_attestation, attach_approvals

envelope = attach_receipt(envelope, receipt_bytes)          # label 394, RFC 9942
envelope = attach_attestation(envelope, attestation_block)
envelope = attach_approvals(envelope, approvals)
```

::: agent_manifest._cose.attach_receipt

::: agent_manifest._cose.attach_attestation

::: agent_manifest._cose.attach_approvals

::: agent_manifest._cose.attach_unprotected

## Verification

```python
from agent_manifest import verify_manifest

result = verify_manifest(envelope, context, revocation_store)   # bytes -> COSE
result = verify_manifest(manifest_dict, context, revocation_store)  # dict -> v0.1
```

`verify_manifest` selects the procedure from what it is given. Everything else, expiry, revocation, artifact bindings, delegation and HITL, is the same engine for both envelopes.

For envelope-level appraisal on its own:

::: agent_manifest._cose.verify_cose_manifest

::: agent_manifest._cose.CoseVerification

::: agent_manifest._cose.CoseSignature

::: agent_manifest._cose.decode_cose_manifest

Nothing in the unprotected header influences whether the signature verifies. It is attacker-malleable by definition, so it is read only after the signature is settled, and a failure in it is reported against that element rather than as a signature failure.

### Failures

| Raised | Meaning | Engine verdict |
|---|---|---|
| `CoseStructureError` | Malformed envelope, bad header, unknown `crit`, unknown algorithm, ambiguous payload | `MISMATCH` |
| `CoseVersionError` | Not a version 0.2 payload | `INCOMPATIBLE_VERSION` |
| `CoseDowngradeError` | `crypto_profile` requires more than `alg` provides | `MISMATCH` |
| `CoseKeyError` | `kid` is not in the trusted keys | `MISMATCH` |
| `InvalidSignature` | The signature did not verify | `MISMATCH` |
| `AlgorithmUnavailableError` | This build cannot perform the algorithm | `UNVERIFIABLE` |

The last one is a capability gap, not a bad manifest, and never falls back to a weaker signature.

## Algorithms

| Algorithm | COSE `alg` | Notes |
|---|---|---|
| Ed25519 | `-19` | What the SDK signs with (RFC 9864) |
| EdDSA | `-8` | Deprecated by RFC 9864; still verified, never emitted |
| ML-DSA-65 | `-49` | RFC 9964; needs `cryptography` >= 47 or the liboqs bindings |

`-8` and `-19` name one algorithm. A `post-quantum` profile is satisfied by neither, and a `COSE_Sign` carrying one entry of each is rejected as a single algorithm signed twice rather than accepted as a hybrid signature.

## Command line

The envelope follows the manifest version on the way out, and the CBOR tag on the way in. No flag selects it.

```bash
manifest sign draft.json --key private.hex -o signed.cose
manifest verify signed.cose --public-key public.hex
```

A `0.2` manifest is written as binary CBOR, so `sign` requires `--output` rather than writing to the terminal.

## HTTP

```
POST /verify/cose
Content-Type: application/agent-manifest+cose

<raw CBOR>
```

The body is the COSE object itself. Only the exact registered media type is accepted: a vendor-tree alias, `application/cbor`, and an absent type are all refused with 415, and the body is never sniffed to decide what it is.

**No key material crosses the wire.** Trust comes from a `VerificationContext` given to `create_router(..., cose_context=...)` when the server is built. Without one the endpoint is fail-closed and returns `UNVERIFIABLE`, never `VALID`.

The body is bounded before it is parsed (1 MiB), with `Content-Length` checked when present and the stream capped regardless. A malformed or unverifiable envelope is a verdict, 200 with a non-`VALID` result, not a transport error. Responses carry `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

Authentication, authorisation and rate limiting are deployment concerns. Mount this router behind them, as [section 5.1](../spec-overview.md) describes.

## Media types

| Media type | Applies to |
|---|---|
| `application/agent-manifest+json` | The manifest document: the canonical JSON payload |
| `application/agent-manifest+cose` | The signed object: `COSE_Sign1` or `COSE_Sign` |

Both are standards-tree, registration pending. A verifier must not accept a vendor-tree alias.
