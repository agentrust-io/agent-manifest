# ADR-0011: The manifest is a signed document, not a JWT/JOSE profile

**Status**: Proposed
**Date**: 2026-07-26
**Spec section**: Section 2.3 (Canonical Serialization), Section 3.6 (Manifest Signature)

## Context

A recurring question in standards conversations is: *why is this not just a JWT extension?* The question deserves a structural answer, and answering it exposed a decision this project has never actually made.

### What we sign today

The spec describes the signed manifest as "JWS" in two places (Section 2.2 lifecycle table, and the `pack_signature` note in Section 5). That description is wrong, and this ADR's companion change removes it. The implementation has never used JOSE:

- The SDK's only cryptographic dependency is `cryptography`. No JOSE library is present.
- `signing_pre_image()` returns the RFC 8785 canonical bytes of a fixed subset of top-level fields (`SIGNED_FIELDS`), with `hitl_record.approvals` normalized to `[]`.
- The result is a raw Ed25519 (or ML-DSA-65, or both) signature carried in a bespoke detached JSON `signature` object.

So the envelope is neither JOSE nor COSE. It is a third thing: canonical JSON plus a detached signature object, specified only by us. That is the weakest of the available positions for a project whose stated goal is a canonical standard, and it is the real subject of this ADR.

### What the envelope has to carry

The manifest is not shaped like a bearer token:

- Ten artifact bindings, not a claim set about a caller.
- Multiple independent signers. The issuer signs the manifest; each HITL approver signs their own approval; each delegation hop is signed by its principal; hardware attestation is appended after signing and is deliberately outside the issuer signature.
- A 90-day default lifetime, versus the minutes-to-hours life of an access token.
- A transparency log inclusion proof attached *after* signing (Section 3.6 ordering rules).

### The strongest form of the counter-argument

EAT, [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) (Standards Track, April 2025), is a real IETF attestation-token format in the JWT/CWT family. It supports nested tokens for composite multi-subsystem devices (Section 4.2.18.3) and Detached EAT Bundles for claims carried outside the token (Section 5). An honest reading is that an IETF-blessed *token* can, in principle, express multi-artifact and detached attestation. Any rebuttal that rests on "JWT cannot do this" is wrong and will be dismantled by anyone who knows EAT.

### What comparable standards actually chose

The pattern is not "tokens versus documents" in the abstract. It splits cleanly by object type:

| Standard | Object | Envelope |
|---|---|---|
| EAT (RFC 9711) | Attestation token about a caller | JWT / CWT profile |
| SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html), June 2026) | Supply-chain signed statement plus transparency receipt | COSE_Sign1, mandated |
| in-toto / SLSA | Multi-subject build attestation | DSSE, which explicitly rejected JWS |
| C2PA | Multi-assertion content provenance | JUMBF container, `COSE_Sign1_Tagged` claim signature |

SCITT is the closest analog to what Agent Manifest is: it requires that "Signed Statements produced by Issuers must be COSE_Sign1 messages," treats the payload as content-agnostic (including detached payloads), and carries COSE Receipts as proofs in the unprotected header. That is our model, down to the Rekor-style log entry in Section 3.6.

The DSSE authors documented why they declined to profile JWS: it "has a history of vulnerable implementations due to the complexity and lack of specificity in the RFC"; implementations fail to check that the algorithm matches the public key type or to validate the certificate chain root; and canonicalization is "an unnecessarily large attack surface." Their Pre-Authentication Encoding exists to bind `payloadType` and `payload` unambiguously so that signer and verifier cannot disagree about what was signed.

### We have already shipped one of those bugs

This is not a theoretical concern for us. Section 3.6 excludes the entire `signature` block from the signing pre-image, so `signature.algorithm` was unauthenticated, and the verifier never compared it against the signed `crypto_profile`. Until 0.6.0, a manifest declaring the post-quantum profile verified `VALID` on a classical-only Ed25519 signature. We fixed it with an explicit cross-check. COSE_Sign1 places `alg` in the *protected* header, where it is covered by the signature; the entire class of bug is structurally absent rather than patched after the fact.

## Decision

Two parts. The first is settled; the second is what this ADR asks for a decision on.

**1. Agent Manifest is a signed document, not a bearer token, and it composes with the token layer rather than competing with it.** EAT is the right answer for "who is calling, right now, and what is their attestation evidence." An EAT (or any platform attestation token) is a valid *input* to a manifest's attestation block. The manifest itself is the durable, multi-signer, hardware-bound record of what the agent *was*. We will not profile JWS as the manifest envelope.

**2. The envelope encoding is open, with a recommendation.** Migrate to **COSE_Sign1** (Option A below), aligning with SCITT and inheriting its documented safety properties, rather than continuing to specify a bespoke canonical-JSON envelope. This is a breaking change and needs explicit sign-off before it is written into the spec; until that happens the status of this ADR stays *Proposed* and Section 3.6 is unchanged.

## Rationale

Deciding by precedent rather than by capability is what makes the position defensible. The question is not whether a JWS or JWT profile *could* carry ten artifact bindings, because EAT shows something in that family can. The question is what every directly comparable multi-artifact, multi-signer, transparency-logged provenance standard chose when it faced this exact decision, and the answer is unanimous: a COSE or DSSE document envelope, never a JWS profile.

Our current envelope is worse than either branch of that fork. It has the two properties DSSE names as reasons to avoid JWS (canonicalization before verification, and no authenticated payload-type or algorithm binding) while also lacking what JOSE and COSE both have: a specification other people implement, independent test suites, and a body of review. Being idiosyncratic is affordable for an internal format and expensive for a proposed standard.

The counter-consideration is real: the canonical-JSON envelope is shipped, hardware-validated on SEV-SNP and TDX, and consumed by cmcp and ca2a through the published package. None of that is throwaway work, and Option B is a legitimate choice if the cost of churn outweighs the standards-path benefit. What is not legitimate is leaving the question unanswered, because a reviewer will find the mismatch between "SCITT-style transparency log" and "envelope of our own invention" and read the silence as an oversight.

## Alternatives considered

**Option A: COSE_Sign1 (recommended).** Aligns with SCITT, C2PA, and the direction of RATS. `alg` moves into the protected header and is covered by the signature. Receipts attach in the unprotected header, matching what we already do with `transparency_log_entry`. Cost: a CBOR dependency, a second signing and verification path, new conformance vectors, and a spec version bump. Consumers on 0.x break unless we support both envelopes through a deprecation window.

**Option B: keep the canonical-JSON envelope and close the DSSE-cited gaps normatively.** Specify in Section 3.6 that the algorithm identifier is bound (either inside the pre-image or by a mandatory cross-check against `crypto_profile`, which 0.6.0 now implements), that an authenticated payload-type indicator is part of the pre-image, and that verifiers must reject unknown or absent algorithm identifiers rather than defaulting. Cheapest path, keeps every current consumer working, and is defensible as long as it is written down. Cost: SCITT profiling later becomes a second migration, and we carry the burden of arguing for a bespoke format in every standards conversation.

**Option C: DSSE.** Solves payload-type binding and avoids canonicalization, and is proven by in-toto and SLSA. But it is not what SCITT mandates, so it does not buy the alignment that is the whole point of moving.

**Option D: profile JWS/JOSE properly.** What the question actually asks for. Rejected on precedent, not capability: no comparable provenance standard took this route, and DSSE documented specific implementation hazards. It would also make Agent Manifest look like an access-token extension, which is exactly the category error the project exists to correct.

**Option E: status quo, undocumented.** Rejected. The current state is a bespoke envelope described in the spec by the wrong name.

## Consequences

- Section 2.2 and Section 5 no longer describe the manifest signature as "JWS." That correction lands with this ADR regardless of which option is chosen.
- If Option A is chosen: a spec version bump, a dual-envelope support window with a stated end, COSE variants of the `AM-VEC-*` conformance vectors, and coordination with cmcp and ca2a, which consume the verifier through the published package. The TypeScript SDK should then be written against the new envelope rather than ported to the old one and migrated twice.
- If Option B is chosen: the hardening rules become normative text in Section 3.6, with negative conformance vectors for each (unbound algorithm, absent algorithm, payload-type substitution). `AM-VEC-020` is the first of these.
- Either way, the answer to the standards question becomes: EAT and JWT for the attestation-token input, a signed document for the manifest, and no competition between the two layers.

## References

- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) - The Entity Attestation Token (EAT), Standards Track, April 2025. Nested tokens: Section 4.2.18.3. Detached EAT Bundles: Section 5.
- [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html) - An Architecture for Trustworthy and Transparent Digital Supply Chains (SCITT), Standards Track, June 2026.
- [DSSE background](https://github.com/secure-systems-lab/dsse/blob/master/background.md) - reasons against a JWS profile, and the Pre-Authentication Encoding rationale.
- [C2PA Specification](https://spec.c2pa.org/) - JUMBF container with `COSE_Sign1_Tagged` claim signatures.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) - JSON Canonicalization Scheme, the basis of the current pre-image. See ADR-0001.
- ADR-0001 (RFC 8785 canonical JSON), ADR-0005 (ML-DSA-65 and hybrid signatures), spec Section 3.6.
