---
description: Configure and implement the issuer key authorization check from spec §5.3.3, so a trusted key can only sign for the issuers it is authorized for.
---

# Issuer key authorization

This page is for anyone who verifies manifests and configured trusted keys before spec §5.3.3 existed. It explains how to add the second check that §5.3.3 requires: a trusted key may sign only for the issuers (the organizations that sign manifests) it is authorized for. If you use the SDK verifier, this is a configuration change. If you maintain your own verifier, it is a code change, and the last part of this page separates what §5.3.3 requires from how the SDK implements it.

Applies to SDK 0.15.0. Spec reference: [§5.3.3 Issuer Key Authorization](../spec/agent-manifest-v0.2.md#533-issuer-key-authorization).

## Why a trusted key is not enough

Your verifier already holds `trusted_keys`, a mapping from a key ID to a public key. That mapping answers one question: which key made this signature? It does not answer a second one: is that key allowed to sign for the issuer this manifest names?

Without the second check, any key you trust can sign a manifest that claims any issuer. If you trust keys from two organizations, either one can produce manifests in the other's name, and every signature still verifies.

§5.3.3 therefore separates the two checks:

| Check | Configured in | Answers |
|-------|---------------|---------|
| Key identification | `trusted_keys` | Which key made the signature? |
| Issuer authorization | `trusted_key_issuers` | May that key sign for the manifest's `issuer`? |

The key ID is the SHA-256 hash of the raw public key bytes, hex encoded. It identifies a key. It does not authorize one.

The authorization must come from configuration you control. It must never be derived from the manifest itself, and in particular not from `agent_id` or any other identifier the signed subject controls. A manifest cannot vouch for its own signer.

## If you use the SDK verifier

Nothing in `trusted_keys` changes. Add `trusted_key_issuers` next to it, mapping each trusted key ID to the issuer SPIFFE URIs that key may sign for:

```python
from agent_manifest import VerificationContext, verify_manifest

context = VerificationContext(
    # unchanged: key ID -> base64url-encoded public key
    trusted_keys={issuer_key_id: issuer_public_key_b64url},
    # new: key ID -> issuers this key may sign for
    trusted_key_issuers={issuer_key_id: ["spiffe://trust.example/issuer/prod"]},
    # ... your observed artifact hashes, as before
)

result = verify_manifest(manifest_or_cose_bytes, context, revocation_store)
```

`trusted_key_issuers` is an SDK input. It is not a manifest field, and the normative `POST /verify` request body in [§5.1](../spec/agent-manifest-v0.2.md#51-verification-endpoint) does not define it. The SDK's FastAPI router (`create_router()`) accepts it as an SDK-level extension on its own `POST /verify` request body. Treat it there like `trusted_keys`: a value a caller sends you is not your authorization policy.

### Choose a setting

`trusted_key_issuers` has three meaningfully different values:

| Value | Meaning | Effect |
|-------|---------|--------|
| `None` (the default) | Issuer authorization is not configured. | The check is skipped. Existing deployments behave as before. |
| `{}` | Configured, and no key is authorized for any issuer. | Every signed manifest fails the check. Fail-closed. |
| `{key_id: [issuers]}` | Configured with explicit authorizations. | A manifest passes only if its signing key is listed for its `issuer`. |

`None` and `{}` are not the same. An empty mapping is a deliberate policy that authorizes nothing, so you can switch fail-closed behavior on before you have filled in the mapping. No version gate is needed.

`None` is backward-compatible SDK behavior, not a conformant §5.3.3 configuration. It exists so that deployments configured before §5.3.3 keep working, and it does not perform the check §5.3.3 requires. In the SDK, the check runs once `trusted_key_issuers` holds a mapping, even an empty one. §5.3.3 requires the check, not this data structure: the authorization path is deployment policy, and other verifiers may hold it in any form that is external to the manifest.

### Gate on the result, not on `signature_verified`

Let a request through only when `result.result` is `OverallResult.VALID`. When the authorization check runs and fails, the result is `MISMATCH`. Checks that run earlier can end verification first: schema validation, revocation, the validity window, and on v0.2 envelope appraisal. The result is then `REVOKED`, `EXPIRED` or another non-`VALID` value, and the authorization check does not run.

`signature_verified` does not tell you whether authorization passed:

| Envelope | Unauthorized key | `result.result` | `signature_verified` |
|----------|------------------|-----------------|----------------------|
| v0.1 detached signature | the signature is not checked | `MISMATCH` | `false` |
| v0.2 COSE | the signature was already checked | `MISMATCH` | `true` |

Conformance vector `AM-VEC-COSE-009` is exactly the second case: a valid signature from a trusted key that is not authorized for the manifest's issuer.

For v0.2, pass the COSE bytes to `verify_manifest()`. Calling `verify_cose_manifest()` on its own appraises the envelope and checks the signature, but it does not run issuer authorization.

## Read the mismatch details

Each authorization failure appears in `result.mismatch_details` with `field="signature.issuer"`. There are no separate result codes such as `KEY_NOT_AUTHORIZED`; the outcome is a `MISMATCH` like any other.

| Situation | `expected_hash` | `actual_hash` |
|-----------|-----------------|---------------|
| The manifest has no `issuer` | `<manifest issuer authorized for signature key>` | `<missing manifest issuer>` |
| The key has no entry, or an empty list, in `trusted_key_issuers` | `<key_id=… authorized for issuer='…'>` | `<key_id has no issuer authorization>` |
| The key is authorized, but not for this issuer | `<issuer in trusted_key_issuers['…']>` | `<issuer='…'>` |

A key ID that is not in `trusted_keys` at all fails earlier, with `field="signature"` and `<key_id not found in trusted_keys>`. That is a key resolution failure, not an authorization failure, and issuer authorization does not run.

Since SDK 0.13.0, a v0.2 manifest without `issuer` fails schema validation with `MISMATCH` before this check runs. The "no `issuer`" row above still applies to v0.1 manifests.

## If you maintain your own verifier

§5.3.3 requires every conformant verifier to:

- take issuer authorization from a trust path external to the manifest, and never from `agent_id` or another identifier the subject controls
- confirm that the signing key is authorized for the manifest's declared `issuer`
- complete key resolution and issuer authorization before signature verification, in both envelopes
- return no `VALID` result when authorization fails or cannot be determined, and keep those two conditions distinct

How you store the policy and how you report failures is up to your implementation. The blocks below show the current SDK implementation, `_signature_key_issuer_mismatch()` in `python/src/agent_manifest/_verify.py`, as a reference. Where it differs from the spec text, follow the spec text; the note after the blocks names both differences.

??? info "SDK reference: the authorization check"

    ```python
    def _signature_key_issuer_mismatch(
        manifest: dict[str, Any],
        key_id: str,
        trusted_key_issuers: Optional[dict[str, list[str]]],
    ) -> Optional[MismatchDetail]:
        if trusted_key_issuers is None:
            return None

        issuer = manifest.get("issuer")
        if not isinstance(issuer, str) or not issuer:
            return MismatchDetail(
                field="signature.issuer",
                expected_hash="<manifest issuer authorized for signature key>",
                actual_hash="<missing manifest issuer>",
            )

        allowed_issuers = trusted_key_issuers.get(key_id)
        if not allowed_issuers:
            return MismatchDetail(
                field="signature.issuer",
                expected_hash=f"<key_id={key_id} authorized for issuer={issuer!r}>",
                actual_hash="<key_id has no issuer authorization>",
            )

        if issuer not in allowed_issuers:
            return MismatchDetail(
                field="signature.issuer",
                expected_hash=f"<issuer in trusted_key_issuers[{key_id!r}]>",
                actual_hash=f"<issuer={issuer!r}>",
            )

        return None
    ```

    The only manifest inputs are the signing `key_id` and `manifest["issuer"]`. The authorization itself comes entirely from `trusted_key_issuers`. The check distinguishes `None` (skip) from an empty mapping (authorize nothing) with an explicit `is None` test; a truthiness test would merge the two.

??? info "SDK reference: where the check runs in each envelope"

    **v0.1 detached signature.** Authorization gates cryptographic verification. The verifier resolves the key through `trusted_keys`, runs the authorization check, and verifies the signature only if authorization passes:

    ```text
    resolve key_id in trusted_keys ── not found ──> MISMATCH on "signature"
            │
            v
    authorization check ── fails ──> MISMATCH on "signature.issuer",
            │                        signature not verified
            v
    verify signature
    ```

    **v0.2 COSE envelope.** The signature was verified during envelope appraisal, before the manifest engine runs, and `signature_verified` takes that value. The authorization check then runs for every signature in the envelope, so in a multi-signature envelope each signer must be authorized for the manifest's `issuer`. Any failure is added to the mismatch details alongside the other checks.

    When `trusted_key_issuers` is configured, the outcome is the same in both envelopes: no `VALID` result without authorization. Only the position of the check differs, which is why `signature_verified` differs (see the table above).

!!! note "Known divergence pending resolution: SDK and §5.3.3 text"
    The SDK differs from the literal text of §5.3.3 in two places. This page describes the SDK as it behaves today. Whether the spec text or the implementation changes is still open.

    - **Order on v0.2.** §5.3.3 requires issuer authorization before signature verification. On the v0.2 COSE path the SDK verifies the envelope signature during appraisal and runs issuer authorization afterwards. With `trusted_key_issuers` configured, an unauthorized key still never reaches `VALID`.
    - **`None`.** §5.3.3 forbids `VALID` when authorization cannot be completed. With `trusted_key_issuers=None` the SDK skips the check so that deployments configured before §5.3.3 keep working.

    For new conformant verifiers, this means:

    1. Follow the §5.3.3 order: issuer authorization before signature verification, in both envelopes. The SDK's v0.2 COSE order is not a model to copy.
    2. Treat `trusted_key_issuers=None` as backward-compatible SDK behavior, not as a conformant §5.3.3 configuration. A verifier without an authorization policy withholds `VALID`.

## Test your configuration

The conformance vectors cover each case:

| Vector | Case | Expected |
|--------|------|----------|
| `AM-VEC-022` | Trusted key authorized for a different issuer | `MISMATCH` |
| `AM-VEC-023` | Key authorized for the subject (`agent_id`), not the issuer | `MISMATCH` |
| `AM-VEC-024` | Empty `trusted_key_issuers` mapping | `MISMATCH` |
| `AM-VEC-COSE-009` | v0.2: trusted key, valid signature, wrong issuer | `MISMATCH`, `signature_verified: true` |

Vectors are in `python/tests/vectors/`; their README describes how to run them against your own verifier.

## Related

- [Key rotation](key-rotation.md): when `trusted_key_issuers` is configured, add a new key there together with `trusted_keys`, or manifests signed with the new key fail authorization.
- [Server-side verification](../tutorials/server-side-verification.md): where the verifier's trusted inputs come from.
