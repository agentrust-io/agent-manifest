"""Generate the language-neutral Agent Manifest conformance vectors.

The vectors in this directory are a portable contract for the verification
engine (spec Section 5). They are designed so *any* implementation, in any
language, can load a manifest + verification context and assert the same
``VerificationResult`` that the Python reference SDK produces.

Design rules that keep the vectors stable and portable:

* **Fixed signing key.** All signed vectors use one Ed25519 key derived from
  the seed ``00 01 02 ... 1f``. The public key (and key_id) is written to
  ``keys.json`` so other languages can verify signatures without re-running
  this script. Ed25519 is deterministic (RFC 8032), so signatures are
  reproducible byte-for-byte.
* **Time-stable expectations.** Expiry/TTL/HITL windows use absolute dates far
  in the past or far in the future, so a vector's expected result does not
  change with wall-clock time for roughly the next century.
* **Self-contained context.** Each vector carries the full
  ``VerificationContext`` under ``context`` (1:1 with the SDK model), plus
  optional ``revoke: true`` to seed the revocation store before verifying.

Run from the repo's ``python/`` directory:

    python -m tests.vectors.generate

This rewrites the ``AM-VEC-*.json``, ``index.json`` and ``keys.json`` files.
The generated files are committed; regenerate only when the engine's normative
behaviour changes, and review the diff.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2

from agent_manifest._canonicalize import canonicalize
from agent_manifest._cose import (
    ALG_ED25519,
    COSE_SIGN1_TAG,
    HDR_ALG,
    HDR_CONTENT_TYPE,
    HDR_KID,
    HDR_TYP,
    MEDIA_TYPE_MANIFEST_COSE,
    MEDIA_TYPE_MANIFEST_JSON,
    _sig_structure_sign1,
    payload_hash,
    sign_cose_sign1,
)
from agent_manifest._delegation import DelegationHopSigner
from agent_manifest._signing import (
    Ed25519Signer,
    ed25519_from_private_bytes,
    signing_pre_image,
)

HERE = Path(__file__).parent

# Fixed key: seed bytes 00 01 02 ... 1f. Deterministic, never use in production.
SEED = bytes(range(32))
KP = ed25519_from_private_bytes(SEED)

# The public key and key_id are published verbatim. They are public, non-secret
# values, so they are declared here as plain constants rather than derived from
# the keypair at write time — this keeps the (private-key-bearing) KP object out
# of every value that gets serialized to disk. The assertion below guarantees
# the constants stay in lockstep with the fixed seed.
KEY_ID = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
PUBLIC_KEY_B64URL = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
assert (KP.key_id, KP.public_b64url()) == (KEY_ID, PUBLIC_KEY_B64URL), (
    "fixed signing key drifted from the published public key/key_id constants"
)
TRUSTED_KEYS = {KEY_ID: PUBLIC_KEY_B64URL}

# Stable absolute timestamps (never "now").
ISSUED_AT = "2025-01-01T00:00:00Z"
FAR_FUTURE = "2099-12-31T23:59:59Z"
FAR_PAST = "2000-01-01T00:00:00Z"
# ~100 years in seconds: a HITL/memory approval that stays valid for the life
# of these vectors without ever being "approved in the future".
CENTURY_SECONDS = 100 * 365 * 24 * 3600

SP_HASH = "sha256:" + "a" * 64
PB_HASH = "sha256:" + "b" * 64
TRACE_ROOT = "sha256:" + "c" * 64
MEM_HASH = "sha256:" + "d" * 64
RAG_ROOT = "sha256:" + "e" * 64

MANIFEST_ID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
ISSUER = "spiffe://trust.example/signing-authority"


def _sign(manifest: dict[str, Any]) -> dict[str, Any]:
    sig = Ed25519Signer(KP).sign(manifest)
    # signed_at is not part of the signed pre-image; pin it for a stable diff.
    sig["signed_at"] = ISSUED_AT
    manifest["signature"] = sig
    return manifest


def base_manifest(**overrides: Any) -> dict[str, Any]:
    m: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": ISSUED_AT,
        "expires_at": FAR_FUTURE,
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SP_HASH},
            "policy_bundle": {"hash": PB_HASH},
            "model_identity": {
                "model_hash": None,
                "version": "claude-3",
                "deployment_type": "api",
            },
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    m.update(overrides)
    return _sign(m)


def base_context(**overrides: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "system_prompt_hash": SP_HASH,
        "policy_bundle_hash": PB_HASH,
        "model_version": "claude-3",
        "trusted_keys": dict(TRUSTED_KEYS),
    }
    ctx.update(overrides)
    return ctx


def cose_manifest(**overrides: Any) -> dict[str, Any]:
    """A version 0.2 manifest: no signature field, because the COSE object is
    the signature (envelope spec section 4)."""
    m: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.2",
        "issued_at": ISSUED_AT,
        "expires_at": FAR_FUTURE,
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SP_HASH},
            "policy_bundle": {"hash": PB_HASH},
            "model_identity": {
                "model_hash": None,
                "version": "claude-3",
                "deployment_type": "api",
            },
        },
    }
    m.update(overrides)
    return m


def cose_encoding_vector() -> dict[str, Any]:
    """Pin the COSE_Sign1 encoding byte-for-byte (issue #243 phase 2, ADR-0013).

    The open item this closes is whether an envelope with no receipt attached
    yet carries a zero-length unprotected header map or omits it. It carries
    one - ``a0`` below - and an implementation in another language has to
    produce these exact bytes, not merely something self-consistent.

    Reproducible because the key is the fixed seed and Ed25519 is
    deterministic (RFC 8032). The post-quantum and hybrid envelopes cannot be
    pinned this way: ML-DSA-65 signing is hedged, so the signature bytes
    differ per run and only the structure is stable.
    """
    manifest = cose_manifest()
    envelope = sign_cose_sign1(manifest, KP)
    protected, unprotected, payload, signature = cbor2.loads(envelope).value
    assert unprotected == {}, "the unprotected header must be a zero-length map"

    return {
        "id": "AM-VEC-COSE-001",
        "description": (
            "COSE_Sign1 encoding is pinned byte-for-byte: CBOR tag 18, a "
            "four-element array, and a zero-length unprotected header map "
            "before any receipt is attached."
        ),
        "spec_refs": ["cose-envelope-v0.2 2", "cose-envelope-v0.2 3"],
        "envelope_hex": envelope.hex(),
        "context": base_context(),
        "expected": {
            "result": "VALID",
            "signature_verified": True,
            "cose": {
                "tag": 18,
                "protected_hex": protected.hex(),
                "unprotected_hex": cbor2.dumps(dict(unprotected)).hex(),
                "payload_hex": payload.hex(),
                "signature_hex": signature.hex(),
                "manifest_hash": payload_hash(payload),
            },
        },
    }


def _detached_signature_is_valid(manifest: dict[str, Any]) -> bool:
    """The ``signature_valid`` counterpart for a v0.1 detached signature block.

    Same meaning as :func:`_signature_is_valid`, over the pre-image the v0.1
    envelope signs rather than an RFC 9052 Sig_structure. Only AM-VEC-COSE-014
    needs it, because it is the one COSE-series vector whose subject is a
    manifest document.
    """
    block = manifest.get("signature")
    if not block:
        return False
    try:
        raw = base64.urlsafe_b64decode(block["signature_value"] + "====")
        KP.public_key.verify(raw, signing_pre_image(manifest))
    except Exception:
        return False
    return True


def _signature_is_valid(envelope: bytes) -> bool:
    """Does the Ed25519 signature in *envelope* verify over its Sig_structure?

    Recorded on every negative vector as ``signature_valid``. It is the
    difference between a vector that tests the rule it names and one that a
    verifier passes by rejecting a broken signature and never reaching that
    rule. Computed from the finished bytes rather than passed in, so it cannot
    drift from what the vector actually contains.
    """
    try:
        decoded = cbor2.loads(envelope)
        body = decoded.value if isinstance(decoded, cbor2.CBORTag) else decoded
        protected, _unprotected, payload, signature = body
        if payload is None:
            return False
        KP.public_key.verify(signature, _sig_structure_sign1(protected, payload))
    except Exception:
        return False
    return True


def _cose_negative(
    vid: str,
    description: str,
    spec_refs: list[str],
    envelope: bytes,
    expected_result: str,
    *,
    signature_verified: bool = False,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A COSE vector whose envelope a conforming verifier must not accept.

    Negatives carry `envelope_hex` and an expected result, and deliberately
    not an `expected.cose` block: the bytes are malformed by construction, so
    pinning their decomposition would assert that a verifier can parse
    something it is being told to reject.

    The schema states *that* a manifest is rejected, not *why*. A verifier
    that rejects one of these for the wrong reason still passes. ``signature_valid``
    narrows that: where it is true, a rejection cannot have come from signature
    verification, so the named rule is the only thing left to reject on.
    """
    return {
        "id": vid,
        "description": description,
        "spec_refs": spec_refs,
        "envelope_hex": envelope.hex(),
        "signature_valid": _signature_is_valid(envelope),
        "context": base_context() if context is None else context,
        "expected": {
            "result": expected_result,
            "signature_verified": signature_verified,
        },
    }


def _sign_payload(payload: bytes) -> bytes:
    """A well-formed COSE_Sign1 carrying *payload* verbatim.

    Used by the vectors whose defect is in the payload. Signing over the
    malformed bytes rather than swapping them into an already-signed envelope
    is what keeps the payload rule the only thing wrong with the object: a
    verifier that checked the signature and stopped would accept it.
    """
    protected = cbor2.dumps(
        {
            HDR_ALG: ALG_ED25519,
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_KID: hashlib.sha256(KP.public_bytes).digest(),
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )
    signature = KP.private_key.sign(_sig_structure_sign1(protected, payload))
    return _retag(COSE_SIGN1_TAG, [protected, {}, payload, signature])


def _signed_cose_parts() -> tuple[bytes, bytes, dict[Any, Any], bytes, bytes]:
    """A valid envelope and its four decoded elements, for mutation."""
    envelope = sign_cose_sign1(cose_manifest(), KP)
    protected, unprotected, payload, signature = cbor2.loads(envelope).value
    return envelope, protected, dict(unprotected), payload, signature


def _retag(tag: int, body: list[Any]) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(tag, body), canonical=True)


def cose_negative_vectors() -> list[dict[str, Any]]:
    """The negative cases a conforming verifier must reject.

    002 to 005 are named in section 9 of the envelope specification. 006 to 008
    are places a CBOR implementation genuinely differs, so they catch
    cross-language divergence rather than restating v0.1 behaviour. 009 to 013
    are the cases carried over from the phase 2 security follow-up on issue
    #243: the authorization boundary, the two JSON parser divergences, version
    routing, and the depth bound.

    Every one of 009 to 013 signs over the payload under test rather than
    swapping bytes into an already-signed envelope, so each carries a valid
    signature and the rule it names is the only reason to reject it.
    """
    vectors: list[dict[str, Any]] = []
    _, protected, _, payload, signature = _signed_cose_parts()

    # 002: the protected header is covered by the signature, so editing it
    # invalidates the signature even when the edit is semantically harmless.
    # This is the case re-serialising a header to inspect it would break.
    tampered_header = dict(cbor2.loads(protected))
    tampered_header[7] = "injected"
    vectors.append(_cose_negative(
        "AM-VEC-COSE-002",
        "A tampered protected header invalidates the signature.",
        ["cose-envelope-v0.2 3", "cose-envelope-v0.2 6"],
        _retag(18, [cbor2.dumps(tampered_header, canonical=True), {}, payload, signature]),
        "MISMATCH",
    ))

    # 003: alg placed in the unprotected header, which is not covered by the
    # signature. A verifier that reads alg from the malleable half can be told
    # which algorithm to use by anyone who can modify the object in transit.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-003",
        "alg present in the unprotected header is rejected, never read.",
        ["cose-envelope-v0.2 3", "cose-envelope-v0.2 6"],
        _retag(18, [protected, {1: -49}, payload, signature]),
        "MISMATCH",
    ))

    # 004: a vendor-tree alias for typ. Section 7 forbids accepting one:
    # two valid type values for one object type is the ambiguity typ removes.
    #
    # The signature is computed over the aliased header rather than copied from
    # a differently-signed object, so the signature is valid and the typ value
    # is the only defect. Editing typ in an already-signed header would have
    # broken the signature too, and a verifier that checked the signature and
    # never implemented the typ rule would have passed the vector for the wrong
    # reason.
    aliased_header = dict(cbor2.loads(protected))
    aliased_header[16] = "application/vnd.agent-manifest+cose"
    aliased_protected = cbor2.dumps(aliased_header, canonical=True)
    aliased_signature = KP.private_key.sign(
        _sig_structure_sign1(aliased_protected, payload)
    )
    vectors.append(_cose_negative(
        "AM-VEC-COSE-004",
        (
            "A vendor-tree typ alias is rejected. The signature over this "
            "envelope is valid, so typ is the only defect."
        ),
        ["cose-envelope-v0.2 3", "cose-envelope-v0.2 7"],
        _retag(18, [aliased_protected, {}, payload, aliased_signature]),
        "MISMATCH",
    ))

    # 005: the positive half of the same rule. An unprotected header injected
    # after signing MUST NOT change the verdict, because nothing in it is
    # covered and step 7 is evaluated last. A verifier that merged the two
    # halves, or took kid from the malleable one, would fail this.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-005",
        (
            "An unprotected header injected after signing does not change the "
            "verdict: kid is read from the protected header only."
        ),
        ["cose-envelope-v0.2 4.1", "cose-envelope-v0.2 6"],
        _retag(18, [protected, {4: b"\x00" * 32}, payload, signature]),
        "VALID",
        signature_verified=True,
    ))

    # 006: untagged. The tag is what tells a relying party which procedure
    # applies; inferring it from the array shape is the guess this envelope
    # exists to remove.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-006",
        "An untagged COSE structure is rejected rather than inferred.",
        ["cose-envelope-v0.2 2", "cose-envelope-v0.2 6"],
        cbor2.dumps([protected, {}, payload, signature], canonical=True),
        "MISMATCH",
    ))

    # 007: trailing bytes. CBOR decoders commonly stop at the end of the first
    # object and ignore the rest, which would let one octet string carry a
    # second manifest behind the first.
    valid = sign_cose_sign1(cose_manifest(), KP)
    vectors.append(_cose_negative(
        "AM-VEC-COSE-007",
        "Trailing bytes after the COSE object are rejected.",
        ["cose-envelope-v0.2 6"],
        valid + b"\x00",
        "MISMATCH",
    ))

    # 008: detached payload. Permitted by SCITT, not by this profile, and a
    # verifier that accepts nil here would verify a signature over bytes it
    # never saw.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-008",
        "A detached (nil) payload is rejected; this profile is inline only.",
        ["cose-envelope-v0.2 4", "cose-envelope-v0.2 6"],
        _retag(18, [protected, {}, None, signature]),
        "MISMATCH",
    ))

    # 009: the signing key is trusted, but not for this issuer. The envelope is
    # byte-identical to AM-VEC-COSE-001, which is the point: only the context
    # differs, so nothing about the object can explain the rejection. A
    # verifier that stops at "the signature verifies under a trusted key"
    # returns VALID here and has no authorization boundary at all.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-009",
        (
            "A trusted key not authorized for the manifest's issuer is "
            "rejected. The envelope is byte-identical to AM-VEC-COSE-001 and "
            "the signature verifies; only the issuer binding differs."
        ),
        ["5.3", "cose-envelope-v0.2 6"],
        sign_cose_sign1(cose_manifest(), KP),
        "MISMATCH",
        signature_verified=True,
        context=base_context(
            trusted_key_issuers={KEY_ID: ["spiffe://trust.example/other-authority"]}
        ),
    ))

    # 010: a duplicate member name. RFC 8259 section 4 states that the
    # behaviour of an implementation given these is unpredictable, and RFC 8785
    # forbids them outright. The second issuer is an attacker-chosen value, so
    # a last-wins parser and a first-wins parser attribute the same signed
    # bytes to two different authorities, and both consider the signature
    # valid. Rejecting is the only answer that cannot differ between them.
    canonical = canonicalize(cose_manifest())
    first_issuer = canonical.index(b'"issuer":')
    after_issuer = canonical.index(b",", first_issuer)
    duplicated = (
        canonical[:after_issuer]
        + b',"issuer":"spiffe://trust.example/attacker"'
        + canonical[after_issuer:]
    )
    vectors.append(_cose_negative(
        "AM-VEC-COSE-010",
        (
            "A payload with a duplicate member name is rejected rather than "
            "resolved. The signature over these bytes is valid: the two "
            "issuer values are the only defect."
        ),
        ["cose-envelope-v0.2 4", "cose-envelope-v0.2 6"],
        _sign_payload(duplicated),
        "MISMATCH",
    ))

    # 011: NaN. Not JSON (RFC 8259 section 6 admits no non-finite values), but
    # several parsers accept it as an extension, Python's own among them unless
    # told otherwise. It is placed in `attestation`, which is a free-form
    # object, so the manifest is schema-valid everywhere else and the literal
    # is the only thing wrong with it.
    placeholder = canonicalize(cose_manifest(attestation={"placeholder": 0}))
    non_finite = placeholder.replace(
        b'{"placeholder":0}', b'{"nonce_skew_seconds":NaN}'
    )
    assert b"NaN" in non_finite, "the non-finite literal was not spliced in"
    vectors.append(_cose_negative(
        "AM-VEC-COSE-011",
        (
            "A payload containing the non-JSON literal NaN is rejected, not "
            "accepted as a parser extension. The signature over these bytes "
            "is valid."
        ),
        ["cose-envelope-v0.2 4", "cose-envelope-v0.2 6"],
        _sign_payload(non_finite),
        "MISMATCH",
    ))

    # 012: a 0.1 payload in a 0.2 envelope. Section 6 step 3 routes on the
    # payload's own version, so this must come back INCOMPATIBLE_VERSION rather
    # than being verified under 0.2 rules because the envelope looks like one.
    # Distinct from the other negatives in expected result, deliberately: an
    # unsupported version is a capability statement, not a malformed object.
    vectors.append(_cose_negative(
        "AM-VEC-COSE-012",
        (
            "A payload declaring version 0.1 inside a 0.2 COSE envelope "
            "returns INCOMPATIBLE_VERSION. The envelope is well formed and "
            "the signature over it is valid."
        ),
        ["cose-envelope-v0.2 6", "2.4"],
        _sign_payload(canonicalize(cose_manifest(version="0.1"))),
        "INCOMPATIBLE_VERSION",
    ))

    # 013: nesting past the accepted depth. A manifest is untrusted input, so
    # this has to produce a verdict rather than exhaust the stack - a verifier
    # that recurses without a bound crashes on it instead of returning
    # anything. Nested inside `attestation` for the same reason as 011: the
    # rest of the document is valid, so depth is the only defect.
    deeply_nested = placeholder.replace(
        b'{"placeholder":0}',
        ('{"a":' * 80 + "1" + "}" * 80).encode(),
    )
    vectors.append(_cose_negative(
        "AM-VEC-COSE-013",
        (
            "A payload nested past the accepted depth is rejected with a "
            "verdict, not a stack exhaustion. The signature over these bytes "
            "is valid."
        ),
        ["cose-envelope-v0.2 4", "cose-envelope-v0.2 6"],
        _sign_payload(deeply_nested),
        "MISMATCH",
    ))

    # 014: the other half of the version gate. #274 made it bidirectional, so a
    # 0.2 manifest must not fall back to the v0.1 detached signature block any
    # more than a 0.1 payload may be verified under 0.2 rules (012). A one-way
    # gate is not a gate: an attacker who cannot produce a valid COSE envelope
    # would simply present the manifest in the envelope that is still accepted.
    #
    # It is the one vector in the COSE series carrying `manifest` rather than
    # `envelope_hex`, because the rule under test is precisely that this
    # document must not be accepted outside a COSE envelope. The signature over
    # it is valid and the version is one the verifier supports, so the envelope
    # pairing is the only defect: the same document at version 0.1 is
    # AM-VEC-001, which verifies VALID.
    #
    # MISMATCH rather than INCOMPATIBLE_VERSION, deliberately. The verifier
    # supports 0.2; what it will not do is verify 0.2 here. Reporting an
    # unsupported version would state something untrue about its capabilities.
    fallback = base_manifest(version="0.2")
    vectors.append({
        "id": "AM-VEC-COSE-014",
        "description": (
            "A version 0.2 manifest presented with a v0.1 detached signature "
            "block is rejected. The signature is valid and the version is "
            "supported; the envelope is the defect."
        ),
        "spec_refs": ["cose-envelope-v0.2 6", "2.4"],
        "manifest": fallback,
        # Carried for the same reason as on every other negative, over the
        # pre-image this envelope signs rather than a Sig_structure. Without it
        # a verifier could pass the vector by rejecting the signature and never
        # reaching the version rule.
        "signature_valid": _detached_signature_is_valid(fallback),
        "context": base_context(),
        "expected": {
            "result": "MISMATCH",
            "signature_verified": False,
        },
    })

    # 015: the other literal finding 2 on #243 names. NaN and Infinity are one
    # class of defect but not one code path in every parser, so a verifier
    # could special-case NaN, pass 011, and still accept this. -Infinity
    # travels the same path as Infinity in every parser checked, so it is
    # covered by this vector rather than given a third.
    infinite = placeholder.replace(
        b'{"placeholder":0}', b'{"nonce_skew_seconds":Infinity}'
    )
    assert b"Infinity" in infinite, "the non-finite literal was not spliced in"
    vectors.append(_cose_negative(
        "AM-VEC-COSE-015",
        (
            "A payload containing the non-JSON literal Infinity is rejected. "
            "Companion to AM-VEC-COSE-011: a verifier that special-cases NaN "
            "passes that one and fails this. The signature over these bytes "
            "is valid."
        ),
        ["cose-envelope-v0.2 4", "cose-envelope-v0.2 6"],
        _sign_payload(infinite),
        "MISMATCH",
    ))

    return vectors


def _vector(
    vid: str,
    description: str,
    spec_refs: list[str],
    manifest: dict[str, Any],
    context: dict[str, Any],
    expected: dict[str, Any],
    *,
    revoke: bool = False,
) -> dict[str, Any]:
    v: dict[str, Any] = {
        "id": vid,
        "description": description,
        "spec_refs": spec_refs,
        "manifest": manifest,
        "context": context,
        "expected": expected,
    }
    if revoke:
        v["revoke"] = True
    return v


def build() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    # 001 - happy path
    vectors.append(_vector(
        "AM-VEC-001", "All bound artifacts match a signed, in-date manifest.",
        ["5.3"], base_manifest(), base_context(),
        {"result": "VALID", "signature_verified": True,
         "fields_verified": {"system_prompt": "MATCH", "policy_bundle": "MATCH",
                             "model_identity": "MATCH", "rag_corpus": "NOT_BOUND"}},
    ))

    # 002 - artifact hash mismatch
    vectors.append(_vector(
        "AM-VEC-002", "Runtime system_prompt hash differs from the bound hash.",
        ["5.3"], base_manifest(),
        base_context(system_prompt_hash="sha256:" + "9" * 64),
        {"result": "MISMATCH", "signature_verified": True,
         "fields_verified": {"system_prompt": "MISMATCH"}},
    ))

    # 003 - expired
    vectors.append(_vector(
        "AM-VEC-003", "Manifest expires_at is in the past.",
        ["5.3"], base_manifest(expires_at=FAR_PAST), base_context(),
        {"result": "EXPIRED"},
    ))

    # 004 - revoked (takes precedence over everything else)
    vectors.append(_vector(
        "AM-VEC-004", "Manifest id is present in the revocation store.",
        ["4.4", "5.3"], base_manifest(), base_context(),
        {"result": "REVOKED"}, revoke=True,
    ))

    # 005 - no signature block at all
    m = base_manifest()
    del m["signature"]
    vectors.append(_vector(
        "AM-VEC-005", "Unsigned manifest must never be VALID (fail-closed).",
        ["5.3"], m, base_context(),
        {"result": "SIGNATURE_MISSING", "signature_verified": False},
    ))

    # 006 - signed but verifier holds no trusted keys
    vectors.append(_vector(
        "AM-VEC-006", "Signed manifest with no trusted keys is UNVERIFIABLE.",
        ["5.3"], base_manifest(), base_context(trusted_keys={}),
        {"result": "UNVERIFIABLE", "signature_verified": False},
    ))

    # 007 - unsupported version
    vectors.append(_vector(
        "AM-VEC-007", "Unsupported manifest version is rejected before verifying.",
        # 0.2 is the COSE envelope and is supported; 0.3 does not exist, which
        # is what makes it the right stand-in for "a version from the future".
        ["2.4"], base_manifest(version="0.3"), base_context(),
        {"result": "INCOMPATIBLE_VERSION"},
    ))

    # 008 - tampered after signing (signature no longer covers the bytes)
    m = base_manifest()
    m["agent_id"] = "spiffe://evil.example/agent/impostor"
    vectors.append(_vector(
        "AM-VEC-008", "agent_id altered after signing invalidates the signature.",
        ["5.3"], m, base_context(),
        {"result": "MISMATCH", "signature_verified": False},
    ))

    # 009 - HITL required + valid approval, enforced
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": ISSUED_AT,
            "approved_scope": {"approval_duration_seconds": CENTURY_SECONDS},
        }],
    })
    vectors.append(_vector(
        "AM-VEC-009", "Required HITL with an unexpired approval passes under enforce_hitl.",
        ["3.2.10", "5.3"], m, base_context(enforce_hitl=True),
        {"result": "VALID", "fields_verified": {"hitl_record": "APPROVED"}},
    ))

    # 010 - HITL enforced but record absent
    vectors.append(_vector(
        "AM-VEC-010", "enforce_hitl with no hitl_record fails closed.",
        ["3.2.10", "5.3"], base_manifest(hitl_record=None),
        base_context(enforce_hitl=True),
        {"result": "MISMATCH", "fields_verified": {"hitl_record": "MISSING"}},
    ))

    # 011 - HITL approval expired
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": FAR_PAST,
            "approved_scope": {"approval_duration_seconds": 3600},
        }],
    })
    vectors.append(_vector(
        "AM-VEC-011", "Expired HITL approval is surfaced regardless of enforcement.",
        ["3.2.10"], m, base_context(),
        {"result": "MISMATCH", "fields_verified": {"hitl_record": "EXPIRED"}},
    ))

    # 012 - delegation chain present, no keys to verify it
    m = base_manifest(delegation_chain=[{
        "hop": 0,
        "principal_type": "human",
        "principal_id": "did:web:example",
        "delegated_at": ISSUED_AT,
        "scope_grant": {"max_delegation_depth": 3, "ttl_seconds": 3600},
        "delegation_signature": "sig",
    }])
    vectors.append(_vector(
        "AM-VEC-012", "Delegation chain with no public keys is UNVERIFIABLE.",
        ["3.4.1", "5.2"], m, base_context(),
        {"result": "UNVERIFIABLE", "fields_verified": {"delegation_chain": "UNVERIFIABLE"}},
    ))

    # 013 - memory baseline TTL expired
    m = base_manifest()
    m["artifacts"]["memory_baseline"] = {
        "snapshot_hash": MEM_HASH,
        "approved_at": FAR_PAST,
        "ttl_seconds": 3600,  # schema minimum; far-past approval means it is long expired
    }
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-013", "Memory baseline past its TTL is reported EXPIRED.",
        ["3.2.6"], m, base_context(memory_snapshot_hash=MEM_HASH),
        {"result": "VALID", "fields_verified": {"memory_baseline": "EXPIRED"}},
    ))

    # 014 - decision trace matches
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": TRACE_ROOT}
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-014", "Decision-trace audit chain root matches the runtime root.",
        ["3.2.7"], m, base_context(audit_chain_root=TRACE_ROOT),
        {"result": "VALID", "fields_verified": {"decision_trace": "MATCH"}},
    ))

    # 015 - RAG corpus poisoning scan flagged
    m = base_manifest()
    m["artifacts"]["rag_corpus"] = {
        "merkle_root": RAG_ROOT,
        "poisoning_scan": {"result": "flagged"},
    }
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-015", "RAG corpus with a flagged poisoning scan fails verification.",
        ["3.2.5.1"], m, base_context(rag_corpus_merkle_root=RAG_ROOT),
        {"result": "MISMATCH"},
    ))

    # 016 - bound artifact with no runtime hash, under strict verification
    m = base_manifest()
    m["artifacts"]["tool_manifest"] = {"catalog_hash": "sha256:" + "f" * 64}
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-016", "Bound tool_manifest with no runtime hash is INCOMPLETE in strict mode.",
        ["5.3"], m, base_context(strict_artifact_verification=True),
        {"result": "INCOMPLETE", "fields_verified": {"tool_manifest": "NOT_BOUND"}},
    ))

    # 017 - attestation enforced but no attestation block present
    vectors.append(_vector(
        "AM-VEC-017", "enforce_attestation with no attestation block is ATTESTATION_UNAVAILABLE.",
        ["3.3"], base_manifest(), base_context(enforce_attestation=True),
        {"result": "ATTESTATION_UNAVAILABLE", "attestation_verified": False},
    ))

    # 018 - attestation block whose reported hash matches the manifest hash
    m = base_manifest()
    subset = {k: v for k, v in m.items() if k not in ("attestation", "transparency_log_entry")}
    attest_hash = "sha256:" + hashlib.sha256(canonicalize(subset)).hexdigest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": attest_hash}
    vectors.append(_vector(
        "AM-VEC-018", "Attestation report hash matching the canonical manifest hash verifies.",
        ["3.3"], m, base_context(),
        {"result": "VALID", "attestation_verified": True},
    ))

    # 018b - the stale-attestation case from issue #265. The manifest is
    # attested, then memory_baseline.snapshot_hash is renewed and the document
    # re-signed, and the original attestation block is carried forward. This is
    # exactly what the withdrawn artifact-only refresh path described. The
    # pre-image covers the signature block, so re-signing alone would have been
    # enough to break the binding; the retained report binds the previous
    # document either way, and spec 3.3 requires MISMATCH regardless of
    # enforce_attestation.
    m = base_manifest(artifacts={
        "system_prompt": {"hash": SP_HASH},
        "policy_bundle": {"hash": PB_HASH},
        "model_identity": {
            "model_hash": None,
            "version": "claude-3",
            "deployment_type": "api",
        },
        "memory_baseline": {"snapshot_hash": "sha256:" + "a1" * 32},
    })
    subset = {k: v for k, v in m.items() if k not in ("attestation", "transparency_log_entry")}
    stale_hash = "sha256:" + hashlib.sha256(canonicalize(subset)).hexdigest()
    refreshed = base_manifest(artifacts={
        "system_prompt": {"hash": SP_HASH},
        "policy_bundle": {"hash": PB_HASH},
        "model_identity": {
            "model_hash": None,
            "version": "claude-3",
            "deployment_type": "api",
        },
        "memory_baseline": {"snapshot_hash": "sha256:" + "b2" * 32},
    })
    refreshed["attestation"] = {"platform": "tpm", "manifest_hash_in_report": stale_hash}
    vectors.append(_vector(
        "AM-VEC-021",
        "Attestation carried forward onto a re-signed manifest binds the previous document.",
        ["2.2", "3.3"], refreshed, base_context(),
        {"result": "MISMATCH", "attestation_verified": False},
    ))

    # 019 - a fully signed, verifiable single-hop delegation chain.
    # The chain root principal must equal the manifest signing identity (issuer),
    # so a valid chain cannot be grafted onto an unrelated manifest.
    hop_signer = DelegationHopSigner(KP)
    scope_grant = {"max_delegation_depth": 3, "ttl_seconds": 3600}
    hop = {
        "hop": 0,
        "principal_type": "system",
        "principal_id": ISSUER,
        "delegated_at": ISSUED_AT,
        "scope_grant": scope_grant,
    }
    hop["delegation_signature"] = hop_signer.sign_hop(
        hop=0, principal_id=ISSUER, principal_type="system",
        delegated_at=ISSUED_AT, scope_grant=scope_grant, manifest_id=MANIFEST_ID,
    )
    m = base_manifest(delegation_chain=[hop])
    vectors.append(_vector(
        "AM-VEC-019", "Signed single-hop delegation chain bound to the manifest issuer verifies.",
        ["3.4.1", "5.2"], m,
        base_context(delegation_public_keys={ISSUER: PUBLIC_KEY_B64URL}),
        {"result": "VALID", "fields_verified": {"delegation_chain": "VALID"}},
    ))

    # 020 - post-quantum profile presented with a classical-only signature.
    # The Ed25519 signature here is genuine and covers a pre-image that includes
    # crypto_profile="post-quantum", so the only defect is the mismatch between
    # the signed profile and the unsigned signature.algorithm identifier. Spec
    # 4.2 requires a verifier to reject rather than silently fall back.
    vectors.append(_vector(
        "AM-VEC-020",
        "Post-quantum crypto_profile with an Ed25519 signature is a downgrade.",
        ["4.2", "3.6"], base_manifest(crypto_profile="post-quantum"), base_context(),
        {"result": "MISMATCH", "signature_verified": False},
    ))

    # 022 - a trusted key not authorized for the manifest's issuer (issue #325).
    # The v0.1 counterpart of AM-VEC-COSE-009: the manifest, signature and
    # signing key are byte-identical to AM-VEC-001, and only the context differs
    # by naming a different authority in trusted_key_issuers. A verifier that
    # stops at "the signature verifies under a trusted key" returns VALID here
    # and has no key-to-issuer authorization boundary at all.
    #
    # signature_verified is false, not true as on AM-VEC-COSE-009: the v0.1
    # path evaluates the issuer binding before it verifies the detached
    # signature (spec 5.3), so on a mismatch it never reaches verification and
    # the flag stays false. The COSE path appraises the envelope signature
    # first, so its analog records true.
    vectors.append(_vector(
        "AM-VEC-022",
        "A trusted key not authorized for the manifest's issuer is rejected.",
        ["5.3"], base_manifest(),
        base_context(
            trusted_key_issuers={KEY_ID: ["spiffe://trust.example/other-authority"]}
        ),
        {"result": "MISMATCH", "signature_verified": False},
    ))

    # 023 - the subject presented as the authority. trusted_key_issuers names
    # the manifest's own agent_id ("spiffe://trust.example/agent/kyc/prod")
    # rather than its issuer, so the key is authorized for the subject it signs
    # for and not for the issuer that signed. Companion to AM-VEC-022: a
    # verifier that compared the key's authorization against agent_id instead of
    # issuer would accept this one, so the two together pin that the binding is
    # to the issuer specifically.
    vectors.append(_vector(
        "AM-VEC-023",
        "A key authorized for the subject (agent_id) but not the issuer is rejected.",
        ["5.3"], base_manifest(),
        base_context(
            trusted_key_issuers={KEY_ID: ["spiffe://trust.example/agent/kyc/prod"]}
        ),
        {"result": "MISMATCH", "signature_verified": False},
    ))

    # --- version 0.2, COSE envelope (ADR-0011, issue #243) -----------------
    vectors.append(cose_encoding_vector())
    vectors.extend(cose_negative_vectors())

    return vectors


def main() -> None:
    vectors = build()

    # Only the PUBLIC key is published — verifiers need nothing else. The signing
    # key is the fixed SEED (bytes 00..1f) hardcoded in this script, so the suite
    # stays reproducible without ever writing private key material to disk.
    keys = {
        "algorithm": "Ed25519",
        "note": "Test-only deterministic key (signing seed = bytes 00..1f, see generate.py). Never use in production.",
        "key_id": KEY_ID,
        "public_key_b64url": PUBLIC_KEY_B64URL,
    }
    (HERE / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")

    index = {
        "suite": "agent-manifest-verification",
        # The suite is written against the 0.2 spec, which defines both
        # envelopes. It said 0.1 while nearly half the vectors target the v0.2
        # COSE envelope, which is the first thing a consumer reads.
        "spec_version": "0.2",
        "description": "Language-neutral verification conformance vectors. "
                       "Each vector: a manifest or a COSE envelope, a "
                       "VerificationContext, and the expected "
                       "VerificationResult.",
        # A vector carries either `manifest` (a version 0.1 document with a
        # detached signature block) or `envelope_hex` (a version 0.2 COSE
        # object). The envelope follows the manifest version, so a consumer
        # selects the procedure by which key is present.
        "envelopes": {
            "manifest": "v0.1 detached signature over an RFC 8785 pre-image",
            "envelope_hex": "v0.2 COSE_Sign1 / COSE_Sign, CBOR",
        },
        "signing_key": "keys.json",
        "vectors": [
            {"id": v["id"], "file": f"{v['id']}.json", "description": v["description"]}
            for v in vectors
        ],
    }
    (HERE / "index.json").write_text(json.dumps(index, indent=2) + "\n")

    for v in vectors:
        out = copy.deepcopy(v)
        (HERE / f"{v['id']}.json").write_text(json.dumps(out, indent=2) + "\n")

    print(f"Wrote {len(vectors)} vectors + index.json + keys.json to {HERE}")


if __name__ == "__main__":
    main()
