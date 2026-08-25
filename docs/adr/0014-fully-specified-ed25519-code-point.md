# ADR-0014: Sign with the fully-specified Ed25519 code point (-19), keep verifying -8

**Status**: Accepted
**Date**: 2026-08-05
**Spec section**: [COSE envelope v0.2](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-cose-envelope-v0.2.md), section 3
**Amends**: [ADR-0011](0011-signature-envelope.md), which named `-8`
**Tracking**: Issue #243, phase 2

## Context

ADR-0011 recorded the COSE code points as settled: `EdDSA` `-8`, `ML-DSA-65` `-49`, AKP key type `7`. The ML-DSA half is correct and was confirmed against the IANA COSE Algorithms registry (`-48`/`-49`/`-50` for ML-DSA-44/65/87). The Ed25519 half was already out of date when it was written.

[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) (Standards Track, October 2025) **deprecates the polymorphic `EdDSA` identifier `-8`** and registers fully-specified ones in its place: `Ed25519` = `-19` and `Ed448` = `-53`, both marked Recommended. The IANA registry now carries `-8` with a Deprecated status.

This surfaced during phase 2 while confirming the ML-DSA code point against IANA rather than against memory. It was not caught in phase 1, where `-8` was carried forward from RFC 9053 without re-checking the registry.

## Decision

**A producer signs with `-19`. A verifier accepts both `-19` and `-8`, and treats them as the same algorithm.**

`-8` stays verifiable indefinitely rather than for a deprecation window. Manifests are audit records with regulated retention beyond their 90-day life (ADR-0011's own reasoning for keeping v0.1 verification), and a signature cannot be re-issued under a new identifier without re-signing, which would defeat the point of an audit record.

**Anything that reasons about which algorithm signed compares algorithms, not code points.** Two consequences, both normative in the envelope specification: a `post-quantum` `crypto_profile` is not satisfied by `-19` or `-8`; and a `COSE_Sign` carrying one entry of each is rejected as a single algorithm signed twice, not accepted as a hybrid signature.

## Rationale

The strongest argument is that ADR-0011 already made it. Its case against the v0.1 envelope is that an algorithm identifier must be authenticated and unambiguous - that a verifier should never have to infer what was signed. `-8` is exactly that inference: it names the EdDSA *family* and leaves the curve to be read off the key. RFC 9864 exists to remove that indirection, and the reasoning it gives is the reasoning ADR-0011 gives. Keeping `-8` while citing DSSE on algorithm binding would be inconsistent.

The second argument is alignment, which is the entire point of moving to COSE. SCITT, C2PA and the RATS work track the COSE registries. A profile that mandates a deprecated identifier is a profile that has to be revised the first time a reviewer opens the registry.

Verification tolerance is separate from signing choice and costs nothing. A verifier that accepts `-8` cannot be attacked through it: both identifiers resolve to the same verification with the same key type, and `alg` is inside the protected header the signature covers, so neither can be swapped for the other after signing. What tolerance buys is that a verifier shipped before this decision keeps working, and no coordinated cutover is needed.

## Alternatives considered

**Option A: sign `-19`, verify both (chosen).**

**Option B: stay on `-8` and document the choice.** Defensible on ubiquity - every COSE implementation supports `-8`, and `pycose` verified this project's envelopes using it. Rejected because the specification is a proposed standard heading for a standards body, and "we knowingly mandate a deprecated identifier" is a weaker position than the one-line change that avoids it. The cost of moving is lowest now, before conformance vectors are published in phase 3 and before any v0.2 manifest is issued.

**Option C: sign `-19` and reject `-8`.** Cleanest in the abstract, wrong for this object type: it would make previously valid audit records unverifiable, which is the one thing the retention argument in ADR-0011 rules out.

**Option D: accept both on signing, chosen per configuration.** Rejected. Two ways to emit one thing is how implementations drift apart, and it would put the encoding of a signed field under a runtime flag - the same objection ADR-0011 raises to selecting an envelope by flag rather than by version.

## Consequences

- The wire format changes: the protected header of an Ed25519 manifest now carries `-19`. `AM-VEC-COSE-001` is regenerated accordingly. This is the moment to do it, since no v0.2 manifest has been issued and phase 3 has not published its vectors.
- **No COSE library can verify a `-19` manifest today, and that is the real cost of this decision.** The interop check that validates this project's `Sig_structure` against an implementation it did not write (ADR-0013) fails on `-19` with `Unknown COSE attribute`, exactly as it fails on `-49`. The check now runs against `-8` fixtures built by the same builders, which keeps an outside opinion on the *structure* while the identifier waits for the ecosystem. It is worth being blunt that this cuts against ADR-0011's stated goal of adopting "a specification other people implement": for a period, nobody else's tooling reads either of this profile's algorithm identifiers. The judgement is that shipping a deprecated identifier into a standards-track profile is the worse of the two, and that library support follows the RFC rather than the other way round. Revisit if that turns out to be wrong.
- ADR-0011's "code points are settled" line is superseded for Ed25519 only. Its ML-DSA-65 and AKP key type values stand, both confirmed against IANA.
- Ed448 (`-53`) is registered by RFC 9864 but is not part of this profile. The standard profile is Ed25519 (ADR-0002); adding a second classical curve is a separate decision with no demand behind it.
- Verifiers built against the specification before this ADR accept `-19` already if they were built from the SDK, which shipped the tolerance ahead of this decision precisely so that this change would not need a flag day.

## References

- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) - Fully-Specified Algorithms for JOSE and COSE. Deprecates `EdDSA` `-8`; registers Ed25519 `-19`, Ed448 `-53`.
- [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) - the original `EdDSA` `-8` registration.
- [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml) - the authority for both, checked rather than recalled.
- ADR-0002 (Ed25519 as the standard profile), ADR-0011 (the COSE envelope), ADR-0013 (the CBOR dependency).
