# Agent Manifest COSE Envelope (manifest version 0.2)

| | |
|---|---|
| **Status** | Draft, normative for manifest `version` `0.2` |
| **Date** | 2026-07-27 |
| **Decision** | ADR-0011 |
| **Tracking** | Issue #243, phase 1 of 5 |
| **Replaces** | v0.1 specification section 3.6 (for version 0.2 manifests only) |

This document specifies the signature envelope for manifest version 0.2. It exists as a standalone document because the rest of the v0.2 specification has not been written yet; it will be folded into that specification as section 3.6 and this file will then be superseded. Until then it is the normative reference for the envelope.

Manifest version 0.1 is unaffected. A verifier MUST select the envelope by the manifest `version` field and MUST NOT apply this document to a version 0.1 manifest. Version 0.1 manifests continue to verify exactly as v0.1 section 3.6 specifies, for as long as the retention window requires.

## 1. Why COSE

ADR-0011 records the reasoning and it is not repeated here. The three properties this envelope exists to obtain:

1. **The signed bytes travel with the signature.** COSE signs a payload as-is. A verifier never re-serializes anything to check a signature, which removes canonicalize-before-verify as an attack surface. RFC 8785 remains the producer-side determinism rule (ADR-0001) and the basis of the manifest hash bound into hardware, but it stops being an input to verification.
2. **The algorithm is covered by the signature.** `alg` lives in the protected header. The downgrade a verifier had to defend against by cross-check in v0.1 (0.6.0 and 0.6.1 of the SDK) cannot be expressed here.
3. **Post-signing additions have a defined home.** COSE's unprotected header is exactly the place for data that attaches after signing. Three separate v0.1 mechanisms collapse into that one idea, as section 4 sets out.

## 2. Object structure

A signed Agent Manifest is one of:

- **`COSE_Sign1`** (CBOR tag 18) when there is a single signature. This is the default and covers the `standard` and `post-quantum` profiles with a single algorithm.
- **`COSE_Sign`** (CBOR tag 98) with exactly two signers when the issuer signs with both Ed25519 and ML-DSA-65 during the post-quantum transition.

A verifier MUST accept both tags. A verifier MUST reject an untagged COSE structure: the tag is what tells a relying party which verification procedure applies, and inferring it from the array shape is the kind of guess this envelope exists to eliminate.

### 2.1 Hybrid signatures

Hybrid is carried as a single `COSE_Sign` over one payload with two `COSE_Signature` entries, one per algorithm. It is not two `COSE_Sign1` objects.

Each signature entry carries its own `alg` in its own protected header (`-19` for Ed25519, `-49` for ML-DSA-65) and its own `kid`. Both entries cover the identical payload bytes, which the structure guarantees rather than an application rule.

A verifier operating under a policy that requires post-quantum protection MUST verify both entries and MUST reject the manifest if either fails. A verifier that cannot perform ML-DSA-65 MUST return `UNVERIFIABLE` and MUST NOT fall back to the Ed25519 entry alone, which would be a downgrade (v0.1 section 4.2, carried forward).

## 3. Protected header

The protected header is covered by the signature. For `COSE_Sign1` these parameters appear in the object's protected header; for `COSE_Sign` `typ` and `content type` appear in the body protected header, while `alg` and `kid` appear in each signature's protected header.

| Parameter | Label | Value | Presence |
|---|---|---|---|
| `alg` | 1 | `-19` (Ed25519) or `-49` (ML-DSA-65) | REQUIRED |
| `kid` | 4 | Key identifier, byte string. The SHA-256 of the public key bytes, as in v0.1 | REQUIRED |
| `content type` | 3 | `application/agent-manifest+json` | REQUIRED |
| `typ` | 16 | `application/agent-manifest+cose` | REQUIRED |

`alg` values are the IANA-registered COSE code points: Ed25519 from [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html), and ML-DSA-65 from RFC 9964, which also registers the AKP key type (COSE key type `7`). No provisional or draft code points are used.

A producer MUST sign with `-19` and MUST NOT sign with `-8`. A verifier MUST accept `-8` on an existing manifest and MUST treat it as Ed25519 (ADR-0014). RFC 9864 (Standards Track, October 2025) deprecated the polymorphic `EdDSA` identifier `-8`, which named a family and left the curve to be inferred from the key, and registered fully-specified identifiers in its place. Inferring an algorithm from a key is the same class of ambiguity that ADR-0011 gives as a reason to move off the v0.1 envelope, so this profile takes the fully-specified identifier. `-8` remains verifiable because manifests are audit records with a retention window that outlives the identifier they were signed under.

`-8` and `-19` name one algorithm, not two. Anything reasoning about *which* algorithm signed - the `crypto_profile` check of section 6, and the two-signer rule of section 2.1 - MUST compare algorithms rather than code points, so that a `COSE_Sign` carrying one entry of each is rejected as a single algorithm signed twice rather than accepted as a hybrid signature.

`typ` (RFC 9596) declares the type of the complete COSE object; `content type` declares the type of the payload. They are deliberately different values: the object is CBOR, the payload is JSON. A verifier MUST reject an object whose `typ` is absent or is any value other than `application/agent-manifest+cose`, which prevents a manifest signature from being reinterpreted as a signature over some other kind of document.

A verifier MUST reject a protected header containing a `crit` parameter naming anything it does not understand. A verifier MUST NOT accept `alg` from an unprotected header under any circumstances.

## 4. Payload, and what attaches after signing

The payload is the RFC 8785 canonical JSON serialization of the manifest document, as a byte string, carried inline. Detached payloads are not used: a manifest is a few kilobytes and is not secret, so detaching would trade a self-contained artifact for a fetch that can fail or be substituted. (SCITT permits detached payloads for large or sensitive statements; this profile does not need that latitude.)

The payload contains every manifest field that is settled at signing time. It does NOT contain `signature`, which no longer exists as a manifest field: the COSE structure *is* the signature.

Three v0.1 mechanisms disappear, replaced by the unprotected header:

| v0.1 mechanism | v0.2 |
|---|---|
| The fixed `signed_fields` list (v0.1 section 3.6) and its coverage table | Deleted. The payload is what is signed. There is no list to keep in sync and no field that is silently outside the signature. |
| `hitl_record.approvals` normalized to `[]` in the pre-image so approvals could attach later | Deleted. The HITL *requirement* stays in the signed payload; approvals attach in the unprotected header. |
| `transparency_log_entry` as an unsigned top-level field with a five-step ordering rule | Deleted. The receipt attaches in the unprotected header per SCITT. |

### 4.1 Unprotected header parameters

| Parameter | Label | Contents | Presence |
|---|---|---|---|
| `receipts` | 394 | SCITT receipts (RFC 9942), an array. Registering a signed manifest with a Transparency Service yields a receipt; a manifest carrying one is a Transparent Statement in SCITT terms | REQUIRED for production (v0.1 section 3.6 rule carried forward) |
| `agent-manifest-attestation` | (string label, pending IANA) | The hardware attestation block, which is produced after signing and is therefore not covered by the issuer signature. Same semantics as the v0.1 `attestation` field | REQUIRED for Level 1 and above |
| `agent-manifest-approvals` | (string label, pending IANA) | HITL approval records, each independently authenticated by its own `approval_signature` per v0.1 section 3.5 | REQUIRED when the signed payload's `hitl_record.required` is true |

`receipts` uses the label RFC 9943 assigns. The two Agent Manifest parameters use string labels until integer labels are requested from IANA in the v1.0 work; COSE permits string labels, so this is valid rather than a placeholder that must be swapped before shipping.

Nothing in the unprotected header is covered by the issuer signature, which is precisely why these three things live there. Each carries its own integrity story: a receipt is signed by the Transparency Service, an attestation report by the TEE, and an approval by its approver.

## 5. What hardware attestation binds

`sha256` of the **payload bytes**: the canonical JSON of the manifest document, exactly the bytes carried in the COSE payload.

This is a simplification of v0.1, where the attestation bound a hash of the manifest with `attestation`, `signature`, and `transparency_log_entry` excluded, and every future top-level field had to be classified. Here the payload is by construction the settled part of the manifest, so there is nothing to exclude and nothing to keep in sync.

The binding is carried in the platform's caller-supplied field as v0.1 section 3.3.1 already specifies per platform (`HOST_DATA` for SEV-SNP boot binding, `REPORT_DATA` and `REPORTDATA` for the runtime freshness proofs of section 3.3.2). Those sections are unchanged.

## 6. Verification procedure

A verifier MUST perform these steps in order and MUST fail closed at the first failure.

1. Parse the CBOR. Reject anything that is not a tagged `COSE_Sign1` (18) or `COSE_Sign` (98).
2. Read the protected header. Reject an absent or unexpected `typ`; reject an unknown `crit` entry; reject an absent `alg`.
3. Extract the payload and parse it as JSON. Reject a `version` this verifier does not support, returning `INCOMPATIBLE_VERSION` (v0.1 section 2.4 semantics carried forward). Route a `0.1` payload to the v0.1 envelope rules; this document applies to `0.2`.
4. Check the signed `crypto_profile` in the payload against the `alg` in the protected header. Reject a signature weaker than the declared profile requires: a `post-quantum` profile with only Ed25519 (`-19`, or `-8` on an existing manifest) is a downgrade. A signature stronger than the profile requires is permitted. This is the v0.1 section 4.2 rule, retained because the profile is a claim about posture that the algorithm alone does not express.
5. Verify the signature over the COSE `Sig_structure`. For `COSE_Sign`, verify every signature entry the governing policy requires.
6. Return `UNVERIFIABLE`, not `MISMATCH`, if the algorithm is registered but this verifier cannot perform it. The verifier has established nothing about a manifest that may be entirely valid (v0.1 section 4.2, as amended).
7. Only then evaluate the unprotected header: receipt inclusion proof, attestation report, approvals. A failure in any of these is reported against that element, not as a signature failure.

Step 7 being last is normative. An unprotected header is attacker-malleable by definition, so nothing in it may influence whether the signature verifies.

## 7. Media types

Two registrations are needed. Both use the `agent-manifest` name in the standards tree, filed as part of the v1.0 standardization path (v0.1 section 10.3).

| Media type | Applies to |
|---|---|
| `application/agent-manifest+json` | The manifest document: the canonical JSON payload, and the natural type for a manifest at rest or over HTTP before signing |
| `application/agent-manifest+cose` | The signed object: a `COSE_Sign1` or `COSE_Sign` carrying a manifest payload |

Until registration completes, implementations MUST use these exact strings and documentation MUST state that registration is pending. A verifier MUST NOT accept a vendor-tree alias: two valid `typ` values for one object type is the ambiguity `typ` exists to remove.

## 8. Example (CBOR diagnostic notation)

A Level 0 manifest signed with Ed25519, before registration with a Transparency Service:

```
18(                                   / COSE_Sign1 /
  [
    h'a4012703...',                   / protected: {1: -8, 4: h'...', 3: "application/agent-manifest+json",
                                        16: "application/agent-manifest+cose"} /
    {},                               / unprotected: empty until a receipt attaches /
    h'7b224063...',                   / payload: RFC 8785 canonical JSON of the manifest /
    h'd28c1f5e...'                    / signature /
  ]
)
```

The same manifest after registration and hardware attestation, showing only the unprotected header:

```
    {
      394: [h'd284...'],              / receipts (RFC 9942) /
      "agent-manifest-attestation": { / TEE report, signed by the platform /
        "platform": "amd-sev-snp",
        "manifest_hash_in_report": "sha256:...",
        "report_uri": "..."
      }
    },
```

## 9. Open items for phase 2

These are implementation decisions, not envelope decisions, and are listed so phase 2 does not rediscover them. The first two are now settled in [ADR-0013](../docs/adr/0013-cbor-library-for-cose.md):

- ~~Which CBOR and COSE library the Python SDK takes.~~ **Decided:** `cbor2` only, with the COSE structures built in the SDK. No COSE library is taken, so the crypto surface stays `cryptography` plus optional `pyoqs`.
- ~~Whether the SDK emits `COSE_Sign1` with a zero-length unprotected header map or omits it before registration.~~ **Decided:** always a zero-length map. Only one of the two is a valid `COSE_Sign1` — omitting the element yields a three-element array, which RFC 9052 section 4.2 does not define. Pinned byte-for-byte in `AM-VEC-COSE-001` (`unprotected_hex` is `a0`).
- `AM-VEC-*` conformance vectors for negative cases only this envelope can express: a tampered protected header, an `alg` substituted between the protected and unprotected headers, a `typ` mismatch, and an unprotected header injected before signature verification.
- Whether the `agent-manifest-attestation` and `agent-manifest-approvals` string labels are worth converting to IANA integer labels before v1.0, which is a wire-size argument only.

## 10. References

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) - COSE structures and algorithms, including the now-deprecated polymorphic `EdDSA` (`-8`)
- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) - Fully-specified algorithms for JOSE and COSE, Standards Track, October 2025. Deprecates `EdDSA` (`-8`); registers Ed25519 = `-19` and Ed448 = `-53`. See ADR-0014
- [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html) - COSE `typ` header parameter (label 16), Standards Track, June 2024
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) - ML-DSA for JOSE and COSE, Standards Track, May 2026. ML-DSA-65 = `alg` `-49`, AKP key type `7`
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) - SCITT architecture. Signed Statements are COSE_Sign1; `receipts` is unprotected header label 394
- [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942.html) - COSE Receipts
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) - JSON Canonicalization Scheme, the payload serialization
- ADR-0001 (RFC 8785), ADR-0005 as amended (profiles and algorithms), ADR-0011 (this decision)
- v0.1 specification sections 2.4, 3.3, 3.5, 3.6, 4.2, 10.3, 10.5
