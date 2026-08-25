# ADR-0013: Take a CBOR library, not a COSE library

**Status**: Accepted
**Date**: 2026-08-04
**Spec section**: [COSE envelope v0.2](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-cose-envelope-v0.2.md), section 9 (open items 1 and 2)
**Tracking**: Issue #243, phase 2 of 5

## Context

[ADR-0011](0011-signature-envelope.md) moved the manifest signature envelope to COSE_Sign1 and noted that phase 2 "takes a CBOR/COSE library, which is the first non-`cryptography` crypto dependency the SDK has taken and should be reviewed as such." The envelope specification left the choice open deliberately, as the first of four implementation decisions for this phase.

Two decisions are settled here: which dependency the SDK takes, and how the SDK encodes an envelope that has no receipt attached yet.

The SDK's dependency posture is the reason this is an ADR rather than a line in a commit message. Today the runtime closure is `pydantic` and `cryptography`, the latter also providing ML-DSA-65 behind the optional `[pq]` extra. Everything cryptographic goes through one audited implementation, which is a claim the project makes to adopters and should not give up quietly.

## Decision

**The SDK depends on `cbor2` for serialization and builds the COSE structures itself**, in [`python/src/agent_manifest/_cose.py`](https://github.com/agentrust-io/agent-manifest/blob/main/python/src/agent_manifest/_cose.py). No COSE library is taken. Signing and verification stay on `cryptography` (Ed25519 and ML-DSA-65), exactly as the v0.1 path does.

**The unprotected header is always emitted as a zero-length map.** It is never omitted. A `COSE_Sign1` is a four-element array (RFC 9052 section 4.2), so omitting the element does not produce a shorter valid `COSE_Sign1` — it produces something that is not one. The envelope spec listed this as an open question about two valid encodings; there is only one, and pinning it lets conformance vectors compare byte-for-byte.

Encoding is deterministic throughout: protected headers and the outer structure are encoded with `canonical=True`. On verification, the protected header is read from the byte string as received and is never re-encoded, so a verifier's own encoder can never disagree with the signer's about what was signed.

## Rationale

The COSE object this profile emits is a four-element array and a `Sig_structure` that is itself a four- or five-element array (RFC 9052 section 4.4). That is the entire construction. Against that, a COSE library would have to earn a place inside the trust boundary, and the two candidates do not:

| | `pycose` 1.1.0 | `cwt` 3.3.0 | `cbor2` + this repo |
|---|---|---|---|
| ML-DSA-65 (`alg` -49, RFC 9964) | absent | absent | supported |
| Additional crypto in the closure | `ecdsa`, `certvalidator` (which pulls `oscrypto`, `asn1crypto`) | `pyhpke` | none |
| Constrains `cbor2` | no | pins `>=5.4.2,<6.0.0` | no |
| Who builds the signed bytes | the library | the library | this project |

Both libraries were inspected at the versions a resolver picks today: neither ships the RFC 9964 code points, and neither mentions ML-DSA in any form. So the post-quantum profile — half of what this envelope exists to carry — would need extending in a dependency either way, and `-49` support would arrive on someone else's release schedule.

The dependency argument is the decisive one. `pycose` brings a second and third asymmetric-crypto implementation into a package that has kept to one, and `oscrypto` in particular is a liability against modern OpenSSL. `cwt` is the cleaner of the two, but it pins `cbor2` below 6.0, which is a version ceiling on the SDK's serialization for the benefit of code we would use a fraction of.

`cbor2` is the right size of dependency: serialization only, no crypto, no declared runtime dependencies of its own, and already an indirect dependency of every alternative considered. Taking it directly is strictly less than taking it through a COSE library. The review that ADR-0011 asked for is below.

The remaining argument for a COSE library is that hand-rolling crypto plumbing is how implementations acquire bugs. It has real force, and it is answered by scope: what this repository builds is CBOR array construction, not a signature scheme. Every actual cryptographic operation is a call into `cryptography` (or the liboqs bindings, where a deployment still carries them). Meanwhile the specific defects ADR-0011 cites in JOSE implementations — accepting `alg` from an unauthenticated place, failing to bind the algorithm to the key type, re-serializing before verifying — are precisely the checks a general-purpose library leaves to its caller anyway. Writing them here makes them reviewable in one file with the spec section numbers next to them.

## Dependency review

ADR-0011 asked for this dependency to be reviewed on maintenance, audit history, and wheel availability across the supported Python matrix. Recorded here as findings rather than impressions.

**Maintenance.** MIT, authored and maintained by Alex Grönholm ([agronholm/cbor2](https://github.com/agronholm/cbor2)), 48 releases, currently 6.1.4. `Requires-Python: >=3.10`, and the wheels carry classifiers through 3.15, so the project tracks new interpreters ahead of them shipping rather than behind. It declares **no runtime dependencies at all**, which is the property that matters most here: taking it adds one node to the closure, not a subtree.

**Audit history.** `pip-audit` 2.10.1 reports no known advisory against any `cbor2` version in the SDK's environment. This is the advisory-database check, not a code audit; nobody has read the extension source on this project's behalf, and the point below about what that extension now is makes that worth saying plainly.

**Wheel availability.** Verified by resolving, not by assumption — nine targets, 3.11/3.12/3.13 × manylinux x86-64 / macOS arm64 / Windows x86-64, all satisfied. One detail the resolution surfaced: under the `>=5.6,<7` pin, macOS and Windows get 6.1.4 while `manylinux_2_17` gets **5.9.0**, because the 6.x wheels target a newer glibc baseline. The SDK therefore has to work on both major versions, so it is tested against both ends of the range.

**What the extension is, and the risk that carries.** This is the finding that would have been missed by assuming. cbor2 **5.x** ships a C extension *plus* a pure-Python fallback (`_decoder.py`, `_encoder.py`, `_types.py`). cbor2 **6.x** ships a **Rust** extension and **no fallback at all** — the wheel contains `__init__.py`, `tool.py`, and the compiled module. On a platform with no published wheel, 6.x cannot be installed without a Rust toolchain, where 5.x would simply run slower in pure Python.

That is a real change in the SDK's build surface and an argument for the `<7` ceiling being a deliberate ceiling rather than routine caution. It does not change the decision: the alternative libraries depend on `cbor2` too and would inherit the same property while adding their own, so this is a cost of CBOR in Python, not a cost of this choice.

**A behavioural difference between the two majors.** 5.x decodes the contents of a CBOR tag into `list` and `dict`; 6.x decodes them into `tuple` and an immutable mapping. Any implementation reading a COSE object through `cbor2` has to accept both, so `_cose.py` accepts either shape and normalizes the unprotected header once, and the test suite is run against 5.6.0 and 6.1.4.

## Interoperability check

Building the COSE structures in-repo raises a fair question: if the SDK verifies its own output, a mistake in the `Sig_structure` would be reproduced on both sides and pass. So the published vector was handed to a COSE library with no relationship to this project.

`pycose` 1.1.0 parses `AM-VEC-COSE-001`, reads `alg` as `EdDSA`, resolves `kid` and the content type, preserves the `typ` it does not recognise, sees the zero-length unprotected map, and **verifies the signature**. It rejects both a flipped signature byte and a modified payload. The same check covers `COSE_Sign`: pycose reads the body protected header, the per-signature protected header, and verifies the signature over the multi-signer `Sig_structure`. Both are run by [`python/tests/interop/verify_with_pycose.py`](https://github.com/agentrust-io/agent-manifest/blob/main/python/tests/interop/verify_with_pycose.py).

The limit of this check is worth recording precisely. It covers Ed25519 only, because **no COSE library implements ML-DSA-65 yet** — handed a real hybrid envelope, pycose stops at `Unknown COSE attribute with value: -49`. The `COSE_Sign` fixture therefore carries a single Ed25519 signer built through the same `_sig_structure_sign` the hybrid path uses, which isolates everything about the structure that is not algorithm-specific. What remains without an outside opinion is the `-49` code point itself, and that was confirmed against the IANA COSE Algorithms registry (`-48`/`-49`/`-50` for ML-DSA-44/65/87), not against memory.

It runs outside the pytest suite, in its own environment, for a reason that reinforces the decision above: **pycose cannot decode any COSE message when cbor2 6.x is installed — including messages it encoded itself.** Making it a normal test would mean pinning the SDK's serialization to accommodate a test-only dependency. That the interop check has to be quarantined from the library it validates against is the clearest possible argument for not having taken that library as a dependency.

## Alternatives considered

**Option A: `pycose`.** The obvious choice by name. Rejected on the dependency closure (`ecdsa`, `certvalidator`, `oscrypto`) and on the absence of ML-DSA-65, which would require carrying a fork or a monkeypatch for the post-quantum profile.

**Option B: `cwt`.** Maintained, and narrower in dependencies than `pycose`. Rejected because it also lacks ML-DSA-65, pins `cbor2<6`, and is built around CWT claim sets rather than a document envelope, so most of what it provides is unused.

**Option C: `cbor2` plus in-repo COSE (chosen).**

**Option D: no new dependency at all — hand-encode CBOR.** Rejected. CBOR decoding of untrusted input is exactly the kind of parser this project should not be writing, and it is the part `cbor2` is good at.

## Consequences

- The SDK's runtime dependencies become `pydantic`, `cryptography`, `cbor2`. The crypto surface is unchanged: no new signature implementation enters the closure.
- The pin is `>=5.6,<7`, and both ends are exercised by CI-visible tests. Widening it to 7.x needs a fresh look at the two majors' decode types, not just a green suite on whichever version happens to resolve.
- When a COSE library does ship RFC 9964 code points, revisiting this is cheap. The envelope is behind `_cose.py`, and the wire format is pinned by conformance vectors rather than by an implementation, so a swap would be a refactor rather than a migration.
- The SDK owns its `Sig_structure` construction and must keep it correct against RFC 9052 section 4.4. The phase 3 vectors are what hold that: an implementation in another language, using a COSE library, must produce identical bytes.
- Two of the four open items in section 9 of the envelope specification are now closed. The other two — the negative conformance vectors, and whether the two string labels become IANA integer labels before v1.0 — remain open and belong to phase 3 and the v1.0 work respectively.

## References

- [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html) — COSE structures. Section 4.2 (COSE_Sign1 array), section 4.4 (`Sig_structure`).
- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) — ML-DSA for JOSE and COSE. ML-DSA-65 = `alg` -49.
- [ADR-0011](0011-signature-envelope.md) — the decision to move to COSE_Sign1.
- [COSE envelope specification v0.2](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-cose-envelope-v0.2.md) — section 9, open items for phase 2.
