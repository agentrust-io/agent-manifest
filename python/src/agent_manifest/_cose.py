"""COSE_Sign1 / COSE_Sign signature envelope for manifest version 0.2.

Normative reference: ``spec/agent-manifest-cose-envelope-v0.2.md`` (ADR-0011).
This module implements manifest version ``0.2`` only. Version ``0.1`` manifests
keep verifying through :mod:`agent_manifest._signing` exactly as they do today;
the envelope is selected by the manifest ``version`` field, never by a flag.

What changes relative to v0.1:

  - The signed bytes travel with the signature. A verifier never re-serializes
    a manifest to check a signature; it verifies over the payload as received.
    RFC 8785 stays the *producer-side* determinism rule and the basis of the
    hash bound into hardware, but it is not an input to verification.
  - ``alg`` sits in the protected header, covered by the signature. The
    downgrade v0.1 defends against with a cross-check (SDK 0.6.0) cannot be
    expressed here.
  - Data that attaches after signing - transparency receipts, the TEE
    attestation report, HITL approvals - lives in the unprotected header.
    The v0.1 ``signed_fields`` list, the ``hitl_record.approvals``
    normalization rule, and the ``transparency_log_entry`` ordering rule all
    disappear with it.

Dependency note (ADR-0013): the only new dependency is ``cbor2``, a
serialization library. The COSE structures are built here rather than taken
from a COSE library so that every byte that goes into a signature is
constructed in code this project reviews, and so that the SDK's crypto surface
stays ``cryptography`` plus the optional liboqs bindings.
"""
from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, Union

import cbor2
from cryptography.exceptions import InvalidSignature

from . import _signing
from ._canonicalize import canonicalize
from ._signing import (
    Ed25519KeyPair,
    Ed25519Verifier,
    HybridKeyPair,
    MlDsa65KeyPair,
    _b64url_decode,
)

__all__ = [
    "COSE_MANIFEST_VERSION",
    "COSE_SIGN1_TAG",
    "COSE_SIGN_TAG",
    "ALG_EDDSA",
    "ALG_ED25519",
    "ALG_ML_DSA_65",
    "ED25519_ALGORITHMS",
    "HDR_ALG",
    "HDR_CRIT",
    "HDR_CONTENT_TYPE",
    "HDR_KID",
    "HDR_TYP",
    "HDR_RECEIPTS",
    "LABEL_ATTESTATION",
    "LABEL_APPROVALS",
    "MEDIA_TYPE_MANIFEST_COSE",
    "MEDIA_TYPE_MANIFEST_JSON",
    "CoseError",
    "CoseStructureError",
    "CoseVersionError",
    "CoseDowngradeError",
    "CoseKeyError",
    "CoseSignature",
    "CoseVerification",
    "cose_payload",
    "payload_hash",
    "sign_manifest_cose",
    "sign_cose_sign1",
    "sign_cose_sign_hybrid",
    "attach_unprotected",
    "attach_receipt",
    "attach_attestation",
    "attach_approvals",
    "decode_cose_manifest",
    "read_payload_manifest",
    "verify_cose_manifest",
]

# --- CBOR tags (RFC 9052 section 2) -----------------------------------------
COSE_SIGN1_TAG = 18
COSE_SIGN_TAG = 98

# --- Header parameter labels ------------------------------------------------
HDR_ALG = 1
HDR_CRIT = 2
HDR_CONTENT_TYPE = 3
HDR_KID = 4
HDR_TYP = 16  # RFC 9596
HDR_RECEIPTS = 394  # RFC 9943 / RFC 9942

# String labels pending IANA integer assignment (envelope spec section 4.1).
LABEL_ATTESTATION = "agent-manifest-attestation"
LABEL_APPROVALS = "agent-manifest-approvals"

# --- Algorithm code points --------------------------------------------------
# `EdDSA` (-8) is polymorphic: it says "some EdDSA curve" and leaves the choice
# to the key. RFC 9864 (Standards Track, October 2025) deprecated it and
# registered fully-specified identifiers, of which Ed25519 is -19.
#
# This module SIGNS with -19 (ADR-0014) and VERIFIES both. -8 stays verifiable
# indefinitely rather than for a deprecation window: manifests are audit
# records with regulated retention, and a signature cannot be re-issued under
# a new identifier without re-signing.
ALG_EDDSA = -8  # RFC 9053; deprecated by RFC 9864, still verified
ALG_ED25519 = -19  # RFC 9864, fully specified; what this SDK signs with
ALG_ML_DSA_65 = -49  # RFC 9964
ALG_NAMES: dict[int, str] = {
    ALG_EDDSA: "EdDSA",
    ALG_ED25519: "Ed25519",
    ALG_ML_DSA_65: "ML-DSA-65",
}

# Both identifiers name the same signature algorithm over the same key type.
ED25519_ALGORITHMS: frozenset[int] = frozenset({ALG_EDDSA, ALG_ED25519})

# --- Media types (envelope spec section 7, registration pending) ------------
MEDIA_TYPE_MANIFEST_JSON = "application/agent-manifest+json"
MEDIA_TYPE_MANIFEST_COSE = "application/agent-manifest+cose"

COSE_MANIFEST_VERSION = "0.2"

# Ed25519 signatures are fixed-length; reject before handing bytes to OpenSSL
# (SIGN-001, carried forward from the v0.1 path).
_ED25519_SIGNATURE_LEN = 64

# v0.1 top-level fields with no place in a v0.2 payload. ``signature`` no
# longer exists as a manifest field - the COSE structure is the signature.
# ``attestation`` and ``transparency_log_entry`` attach after signing and now
# live in the unprotected header.
_NON_PAYLOAD_FIELDS = ("signature", "attestation", "transparency_log_entry")

# Which algorithms satisfy a declared crypto_profile (envelope spec section 6
# step 4, carrying forward v0.1 section 4.2). One-directional by design:
# stronger than declared is permitted, weaker is a downgrade.
PROFILE_REQUIRED_ALGORITHMS: dict[str, frozenset[int]] = {
    "post-quantum": frozenset({ALG_ML_DSA_65}),
}


class CoseError(ValueError):
    """Base class for every COSE envelope rejection."""


class CoseStructureError(CoseError):
    """The object is not a well-formed COSE manifest envelope.

    Covers an untagged or wrongly tagged structure, a malformed header, a
    missing or unexpected ``typ``/``content type``, an unknown ``crit``
    entry, and a payload that is not the JSON of a manifest.
    """


class CoseVersionError(CoseError):
    """The payload declares a manifest version this envelope does not govern.

    A ``0.1`` payload is routed to the v0.1 envelope rules rather than
    reinterpreted here; any other unsupported version maps to
    ``INCOMPATIBLE_VERSION``.
    """


class CoseDowngradeError(CoseError):
    """The signed ``crypto_profile`` requires more than ``alg`` provides."""


class CoseKeyError(CoseError):
    """A signature names a ``kid`` that is not in the caller's trusted keys."""


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def cose_payload(manifest_dict: dict[str, Any]) -> bytes:
    """Return the payload bytes for *manifest_dict*: RFC 8785 canonical JSON.

    The payload is the manifest document as it stands at signing time. Fields
    that attach afterwards are dropped rather than carried: ``signature`` (the
    COSE structure replaces it), ``attestation`` and ``transparency_log_entry``
    (unprotected header), and ``hitl_record.approvals`` (unprotected header).
    The HITL *requirement* stays in the signed payload; the approvals do not.

    Unlike v0.1's ``signing_pre_image()`` there is no field allowlist. Whatever
    is in the manifest is signed, so no field can sit silently outside the
    signature and there is no list to keep in sync with the schema.
    """
    payload: dict[str, Any] = {
        k: v for k, v in manifest_dict.items() if k not in _NON_PAYLOAD_FIELDS
    }
    hitl = payload.get("hitl_record")
    if isinstance(hitl, dict) and "approvals" in hitl:
        payload["hitl_record"] = {k: v for k, v in hitl.items() if k != "approvals"}
    return canonicalize(payload)


def payload_hash(payload: bytes) -> str:
    """Return ``sha256:<hex>`` over the payload bytes.

    This is what hardware attestation binds (envelope spec section 5): the
    exact bytes carried in the COSE payload, with nothing excluded and nothing
    to keep in sync. Callers hold it in the platform's caller-supplied field
    (``HOST_DATA``, ``REPORT_DATA``, ``REPORTDATA``) per v0.1 section 3.3.
    """
    return "sha256:" + hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _kid(public_key_bytes: bytes) -> bytes:
    """COSE ``kid``: SHA-256 of the raw public key bytes, as a byte string.

    The same digest v0.1 carries as a hex string in ``signature.key_id``, so a
    key registered for v0.1 keeps its identity across the migration.
    """
    return hashlib.sha256(public_key_bytes).digest()


def _require_v02(manifest_dict: dict[str, Any]) -> None:
    version = manifest_dict.get("version")
    if version != COSE_MANIFEST_VERSION:
        raise CoseVersionError(
            f"The COSE envelope is normative for manifest version "
            f"{COSE_MANIFEST_VERSION!r}, but this manifest declares "
            f"{version!r}. Sign a 0.1 manifest with the v0.1 envelope."
        )


def _sig_structure_sign1(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4 ``Sig_structure`` for COSE_Sign1."""
    return cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)


def _sig_structure_sign(
    body_protected: bytes, sign_protected: bytes, payload: bytes
) -> bytes:
    """RFC 9052 section 4.4 ``Sig_structure`` for one COSE_Sign signer."""
    return cbor2.dumps(
        ["Signature", body_protected, sign_protected, b"", payload], canonical=True
    )


def _ml_dsa_sign(private_key_bytes: bytes, data: bytes) -> bytes:
    """Sign through the SDK's ML-DSA-65 backend (cryptography, or liboqs)."""
    _signing._require_ml_dsa()
    return _signing._ml_dsa_sign_raw(private_key_bytes, data)


def _ml_dsa_verify(public_key_bytes: bytes, data: bytes, signature: bytes) -> None:
    _signing._require_ml_dsa()
    if not _signing._ml_dsa_verify_raw(public_key_bytes, data, signature):
        raise InvalidSignature("ML-DSA-65 signature verification failed")


def _ed25519_verify(public_key_bytes: bytes, data: bytes, signature: bytes) -> None:
    # Ed25519Verifier applies the CRYPTO-005 small-order (torsion point)
    # rejection at load time; go through it rather than around it.
    verifier = Ed25519Verifier(public_key_bytes)
    if len(signature) != _ED25519_SIGNATURE_LEN:
        raise InvalidSignature(
            f"Ed25519 signature must be {_ED25519_SIGNATURE_LEN} bytes, "
            f"got {len(signature)}"
        )
    verifier._pub.verify(signature, data)


def sign_cose_sign1(
    manifest_dict: dict[str, Any],
    keypair: Union[Ed25519KeyPair, MlDsa65KeyPair],
) -> bytes:
    """Sign *manifest_dict* as a tagged ``COSE_Sign1`` and return CBOR bytes.

    The unprotected header is emitted as a zero-length map. It is never
    omitted: a three-element array is not a ``COSE_Sign1`` (RFC 9052 section
    4.2), and pinning one encoding is what lets conformance vectors compare
    byte-for-byte (ADR-0013).
    """
    _require_v02(manifest_dict)
    payload = cose_payload(manifest_dict)

    if isinstance(keypair, Ed25519KeyPair):
        alg = ALG_ED25519
        public_bytes = keypair.public_bytes
    else:
        alg = ALG_ML_DSA_65
        public_bytes = keypair.public_key_bytes
        # Fail before building an envelope this build cannot finish signing.
        _signing._require_ml_dsa()

    protected = cbor2.dumps(
        {
            HDR_ALG: alg,
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_KID: _kid(public_bytes),
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )
    to_be_signed = _sig_structure_sign1(protected, payload)
    if isinstance(keypair, Ed25519KeyPair):
        signature = keypair.private_key.sign(to_be_signed)
    else:
        signature = _ml_dsa_sign(keypair.private_key_bytes, to_be_signed)

    return cbor2.dumps(
        cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, signature]),
        canonical=True,
    )


def sign_cose_sign_hybrid(
    manifest_dict: dict[str, Any], keypair: HybridKeyPair
) -> bytes:
    """Sign *manifest_dict* as a tagged ``COSE_Sign`` with two signers.

    Hybrid is one ``COSE_Sign`` over one payload, not two ``COSE_Sign1``
    objects (envelope spec section 2.1): both entries covering identical
    payload bytes is then a property of the structure rather than an
    application rule a verifier has to be told to enforce.

    ``typ`` and ``content type`` sit in the body protected header; ``alg`` and
    ``kid`` sit in each signature's own protected header. Entries are emitted
    Ed25519 first, ML-DSA-65 second.
    """
    _require_v02(manifest_dict)
    _signing._require_ml_dsa()
    payload = cose_payload(manifest_dict)

    body_protected = cbor2.dumps(
        {
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )

    ed_protected = cbor2.dumps(
        {HDR_ALG: ALG_ED25519, HDR_KID: _kid(keypair.ed25519.public_bytes)},
        canonical=True,
    )
    ed_signature = keypair.ed25519.private_key.sign(
        _sig_structure_sign(body_protected, ed_protected, payload)
    )

    pq_protected = cbor2.dumps(
        {HDR_ALG: ALG_ML_DSA_65, HDR_KID: _kid(keypair.ml_dsa65.public_key_bytes)},
        canonical=True,
    )
    pq_signature = _ml_dsa_sign(
        keypair.ml_dsa65.private_key_bytes,
        _sig_structure_sign(body_protected, pq_protected, payload),
    )

    return cbor2.dumps(
        cbor2.CBORTag(
            COSE_SIGN_TAG,
            [
                body_protected,
                {},
                payload,
                [
                    [ed_protected, {}, ed_signature],
                    [pq_protected, {}, pq_signature],
                ],
            ],
        ),
        canonical=True,
    )


def sign_manifest_cose(
    manifest_dict: dict[str, Any],
    keypair: Union[Ed25519KeyPair, MlDsa65KeyPair, HybridKeyPair],
) -> bytes:
    """Sign *manifest_dict* with whichever envelope *keypair* calls for."""
    if isinstance(keypair, HybridKeyPair):
        return sign_cose_sign_hybrid(manifest_dict, keypair)
    return sign_cose_sign1(manifest_dict, keypair)


# ---------------------------------------------------------------------------
# Post-signing attachment (unprotected header)
# ---------------------------------------------------------------------------


def attach_unprotected(cose_bytes: bytes, label: Union[int, str], value: Any) -> bytes:
    """Return *cose_bytes* with ``unprotected[label] = value``.

    The protected header, payload, and signature byte strings are carried
    through untouched, so attaching never invalidates a signature - which is
    the whole reason these three things live in the unprotected header.
    """
    tag, body = _decode_tagged(cose_bytes)
    unprotected = dict(body[1])
    unprotected[label] = value
    body = list(body)
    body[1] = unprotected
    return cbor2.dumps(cbor2.CBORTag(tag, body), canonical=True)


def attach_receipt(cose_bytes: bytes, receipt: bytes) -> bytes:
    """Append a SCITT receipt (RFC 9942) to the ``receipts`` array (label 394)."""
    tag, body = _decode_tagged(cose_bytes)
    receipts = list(body[1].get(HDR_RECEIPTS) or [])
    receipts.append(receipt)
    return attach_unprotected(cose_bytes, HDR_RECEIPTS, receipts)


def attach_attestation(cose_bytes: bytes, attestation: dict[str, Any]) -> bytes:
    """Attach the hardware attestation block produced after signing."""
    return attach_unprotected(cose_bytes, LABEL_ATTESTATION, attestation)


def attach_approvals(cose_bytes: bytes, approvals: list[dict[str, Any]]) -> bytes:
    """Attach HITL approval records, each authenticated by its own signature."""
    return attach_unprotected(cose_bytes, LABEL_APPROVALS, approvals)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoseSignature:
    """One signature entry: its algorithm, its key, and whether it verified."""

    algorithm: int
    key_id: str  # hex digest, the v0.1 key_id spelling of the COSE kid
    verified: bool

    @property
    def algorithm_name(self) -> str:
        return ALG_NAMES.get(self.algorithm, f"COSE alg {self.algorithm}")


@dataclass(frozen=True)
class CoseVerification:
    """The outcome of appraising a COSE manifest envelope.

    ``verified`` reports the signature only. Everything in ``unprotected`` is
    attacker-malleable and is deliberately not appraised here: the caller
    evaluates receipts, attestation, and approvals after the signature has
    been settled (envelope spec section 6 step 7, which is normative about
    the ordering).
    """

    manifest: dict[str, Any]
    payload: bytes
    manifest_hash: str
    tag: int
    signatures: tuple[CoseSignature, ...]
    unprotected: dict[Any, Any]

    @property
    def verified(self) -> bool:
        """True when every signature entry verified against a trusted key."""
        return bool(self.signatures) and all(s.verified for s in self.signatures)

    @property
    def algorithms(self) -> tuple[int, ...]:
        return tuple(s.algorithm for s in self.signatures)

    @property
    def receipts(self) -> list[Any]:
        value = self.unprotected.get(HDR_RECEIPTS) or []
        return list(value) if isinstance(value, (list, tuple)) else []

    @property
    def attestation(self) -> Optional[dict[str, Any]]:
        value = self.unprotected.get(LABEL_ATTESTATION)
        return value if isinstance(value, dict) else None

    @property
    def approvals(self) -> Optional[list[Any]]:
        value = self.unprotected.get(LABEL_APPROVALS)
        return list(value) if isinstance(value, (list, tuple)) else None


def _algorithm_family(alg: int) -> str:
    """The signature algorithm behind a code point.

    ``-8`` and ``-19`` are two identifiers for Ed25519 (RFC 9864 replaced the
    polymorphic one with the fully-specified one), so anything reasoning about
    *which algorithm signed* has to collapse them.
    """
    return "ed25519" if alg in ED25519_ALGORITHMS else ALG_NAMES.get(alg, str(alg))


def _plain(value: Any) -> Any:
    """Convert a CBOR-decoded value into plain dicts and lists.

    cbor2 6.x returns immutable mappings and tuples for anything inside a tag;
    5.x returns lists and dicts. Callers downstream (the verification engine,
    Pydantic models) expect ordinary containers, so the unprotected header is
    normalized once here rather than defensively at every use.
    """
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _decode_tagged(cose_bytes: bytes) -> tuple[int, list[Any]]:
    """Decode exactly one tagged COSE object and return ``(tag, body)``.

    Step 1 of the verification procedure. An untagged structure is rejected:
    the tag is what tells a relying party which procedure applies, and
    inferring it from the array shape is the guess this envelope exists to
    eliminate. Trailing bytes are rejected too, so one octet string cannot
    carry a second manifest behind the first.
    """
    if not isinstance(cose_bytes, (bytes, bytearray)):
        raise CoseStructureError(
            f"COSE object must be bytes, got {type(cose_bytes).__name__}"
        )
    stream = io.BytesIO(bytes(cose_bytes))
    try:
        decoded = cbor2.CBORDecoder(stream).decode()
    except RecursionError as exc:  # deeply nested CBOR (DOS-006)
        raise CoseStructureError(f"COSE object is too deeply nested: {exc}") from exc
    except Exception as exc:  # cbor2 raises several unrelated types
        raise CoseStructureError(f"COSE object is not valid CBOR: {exc}") from exc
    if stream.read(1):
        raise CoseStructureError("trailing bytes after the COSE object")

    if not isinstance(decoded, cbor2.CBORTag):
        raise CoseStructureError(
            "untagged COSE structure: expected CBOR tag 18 (COSE_Sign1) or "
            "98 (COSE_Sign)"
        )
    if decoded.tag not in (COSE_SIGN1_TAG, COSE_SIGN_TAG):
        raise CoseStructureError(
            f"unexpected CBOR tag {decoded.tag}: expected 18 (COSE_Sign1) or "
            f"98 (COSE_Sign)"
        )
    # cbor2 6.x decodes the contents of a tag into tuples and immutable
    # mappings; 5.x decodes them into lists and dicts. Both are supported
    # versions (ADR-0013), so accept either shape.
    body = decoded.value
    if not isinstance(body, (list, tuple)) or len(body) != 4:
        raise CoseStructureError(
            f"COSE body must be a four-element array, got "
            f"{len(body) if isinstance(body, (list, tuple)) else type(body).__name__}"
        )
    if not isinstance(body[0], bytes):
        raise CoseStructureError("protected header must be a byte string")
    # cbor2 hands back an immutable mapping for a map inside a tag.
    if not isinstance(body[1], Mapping):
        raise CoseStructureError("unprotected header must be a map")
    if not isinstance(body[2], bytes):
        raise CoseStructureError("payload must be a byte string, inline not detached")
    return decoded.tag, list(body)


def _decode_protected(protected: bytes, *, what: str) -> dict[Any, Any]:
    if protected == b"":
        # A zero-length protected header is legal CBOR in COSE generally, but
        # this profile requires parameters in it, so it is always a rejection.
        raise CoseStructureError(f"{what} protected header is empty")
    try:
        header = cbor2.loads(protected)
    except Exception as exc:
        raise CoseStructureError(
            f"{what} protected header is not valid CBOR: {exc}"
        ) from exc
    if not isinstance(header, Mapping):
        raise CoseStructureError(f"{what} protected header must be a map")
    return dict(header)


def _check_crit(header: Mapping[Any, Any], *, what: str) -> None:
    crit = header.get(HDR_CRIT)
    if crit is None:
        return
    if not isinstance(crit, (list, tuple)) or not crit:
        raise CoseStructureError(f"{what} crit must be a non-empty array")
    # Nothing in this profile is understood as critical, so any entry is
    # by definition an entry this verifier does not understand.
    raise CoseStructureError(
        f"{what} protected header marks {list(crit)!r} critical, which this "
        f"verifier does not understand"
    )


def _check_unprotected_has_no_alg(unprotected: Mapping[Any, Any]) -> None:
    if HDR_ALG in unprotected:
        raise CoseStructureError(
            "alg present in the unprotected header, which a verifier MUST NOT "
            "accept under any circumstances"
        )


def _check_body_type(header: Mapping[Any, Any]) -> None:
    typ = header.get(HDR_TYP)
    if typ is None:
        raise CoseStructureError(
            "typ (label 16) is absent from the protected header; without it a "
            "manifest signature could be reinterpreted as a signature over "
            "another kind of document"
        )
    if typ != MEDIA_TYPE_MANIFEST_COSE:
        raise CoseStructureError(
            f"typ is {typ!r}, expected {MEDIA_TYPE_MANIFEST_COSE!r}; a "
            f"vendor-tree alias MUST NOT be accepted"
        )
    content_type = header.get(HDR_CONTENT_TYPE)
    if content_type != MEDIA_TYPE_MANIFEST_JSON:
        raise CoseStructureError(
            f"content type is {content_type!r}, expected "
            f"{MEDIA_TYPE_MANIFEST_JSON!r}"
        )


def _read_alg_and_kid(header: Mapping[Any, Any], *, what: str) -> tuple[int, bytes]:
    alg = header.get(HDR_ALG)
    if alg is None:
        raise CoseStructureError(f"{what} protected header has no alg")
    if not isinstance(alg, int) or isinstance(alg, bool):
        raise CoseStructureError(f"{what} alg must be an integer code point, got {alg!r}")
    kid = header.get(HDR_KID)
    if not isinstance(kid, bytes):
        raise CoseStructureError(f"{what} protected header has no kid byte string")
    return alg, kid


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build the object, refusing any member name that appears twice.

    RFC 8785 canonical JSON cannot contain duplicate names, so a payload that
    does is malformed. It also matters more here than malformedness usually
    does: JSON parsers disagree about which value wins, so a payload with a
    repeated ``issuer`` or ``expires_at`` could be read differently by two
    verifiers that both consider the signature valid. The envelope exists to
    make everyone agree on what was signed; this is the parse-level half of
    that guarantee.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise CoseStructureError(
                f"payload contains a duplicate member name {key!r}, which "
                f"RFC 8785 does not permit and parsers resolve differently"
            )
        seen[key] = value
    return seen


def _reject_non_json_constant(token: str) -> Any:
    """Refuse NaN and Infinity, which Python accepts and RFC 8785 forbids."""
    raise CoseStructureError(
        f"payload contains {token}, which is not permitted by RFC 8785"
    )


#: Maximum nesting depth accepted in a COSE payload (DOS-006).
#:
#: A manifest is a shallow document: the deepest path this specification defines
#: is roughly ``artifacts.tool_manifest.tools[].approved_scope``, well under ten.
#: Sixty-four leaves generous headroom for a future revision while staying far
#: below any interpreter's recursion limit.
_MAX_PAYLOAD_NESTING = 64


def _payload_nesting_depth(text: str) -> int:
    """Maximum ``{``/``[`` nesting depth in *text*, ignoring string contents.

    Scanned rather than measured after parsing, because the point is to refuse
    the work before doing it: a depth check that runs after ``json.loads`` has
    already paid for the structure it was supposed to prevent.

    String-aware, so a brace inside a member value cannot inflate the count and
    make a legitimate manifest look like an attack. Backslash escapes are skipped
    so ``"\\\\"`` does not swallow the closing quote.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "}]":
            depth -= 1
    return deepest


def _parse_payload(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CoseStructureError(f"payload is not valid JSON: {exc}") from exc

    # Before json.loads, not after. Relying on RecursionError alone made this
    # guard platform-dependent: CPython on Linux parses thousands of levels
    # without raising, so on that platform there was no bound at all, while
    # Windows tripped its own recursion limit and appeared to be protected. An
    # explicit bound behaves identically everywhere.
    depth = _payload_nesting_depth(text)
    if depth > _MAX_PAYLOAD_NESTING:
        raise CoseStructureError(
            f"payload is nested {depth} levels deep, above the "
            f"{_MAX_PAYLOAD_NESTING}-level limit"
        )

    try:
        manifest = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise CoseStructureError(f"payload is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        # A manifest is untrusted input, so nesting must produce a verdict
        # rather than unwind the caller's stack (DOS-006).
        raise CoseStructureError(f"payload is too deeply nested: {exc}") from exc
    if not isinstance(manifest, dict):
        raise CoseStructureError(
            f"payload must be a JSON object, got {type(manifest).__name__}"
        )
    return manifest


def _check_version(manifest: Mapping[str, Any]) -> None:
    version = manifest.get("version")
    if version == "0.1":
        raise CoseVersionError(
            "payload declares manifest version 0.1, which is governed by the "
            "v0.1 envelope (spec section 3.6), not by this document"
        )
    if version != COSE_MANIFEST_VERSION:
        raise CoseVersionError(
            f"unsupported manifest version {version!r}; this verifier "
            f"implements {COSE_MANIFEST_VERSION!r}"
        )


def _check_profile(manifest: Mapping[str, Any], algorithms: tuple[int, ...]) -> None:
    """Step 4: the signed ``crypto_profile`` against the protected ``alg``.

    ``alg`` is covered by the signature here, so this is no longer defending
    against a rewritten identifier the way the v0.1 cross-check is. It still
    runs, because ``crypto_profile`` is a claim about posture that the
    algorithm alone does not express: a post-quantum profile carrying only
    ``-8`` is a downgrade whatever the signature says.
    """
    declared = manifest.get("crypto_profile", "standard")
    required = PROFILE_REQUIRED_ALGORITHMS.get(declared)
    if required is None:
        return
    if not required.intersection(algorithms):
        present = ", ".join(ALG_NAMES.get(a, str(a)) for a in algorithms)
        expected = ", ".join(sorted(ALG_NAMES.get(a, str(a)) for a in required))
        raise CoseDowngradeError(
            f"crypto_profile={declared!r} requires {expected}, but the "
            f"envelope carries {present or 'no algorithm'}"
        )


def _verify_one(
    alg: int,
    kid: bytes,
    to_be_signed: bytes,
    signature: bytes,
    trusted_keys: Mapping[str, str],
) -> CoseSignature:
    key_id = kid.hex()
    entry = CoseSignature(algorithm=alg, key_id=key_id, verified=False)
    if alg not in ALG_NAMES:
        raise CoseStructureError(
            f"unknown alg code point {alg}; this profile registers "
            f"{ALG_EDDSA} (EdDSA) and {ALG_ML_DSA_65} (ML-DSA-65)"
        )
    if not isinstance(signature, bytes):
        raise CoseStructureError("signature must be a byte string")
    if not trusted_keys:
        # No keys to appraise against. Steps 1-4 have passed; the caller reports
        # UNVERIFIABLE rather than VALID, and never MISMATCH.
        return entry

    public_b64 = trusted_keys.get(key_id)
    if public_b64 is None:
        raise CoseKeyError(f"kid={key_id} is not in trusted_keys")
    public_bytes = _b64url_decode(public_b64)

    # AlgorithmUnavailableError propagates: a build with no ML-DSA backend has
    # established nothing about an ML-DSA-65 signature, which is UNVERIFIABLE
    # (step 6), and MUST NOT fall back to a classical entry.
    if alg in ED25519_ALGORITHMS:
        _ed25519_verify(public_bytes, to_be_signed, signature)
    else:
        _ml_dsa_verify(public_bytes, to_be_signed, signature)
    return CoseSignature(algorithm=alg, key_id=key_id, verified=True)


def decode_cose_manifest(cose_bytes: bytes) -> CoseVerification:
    """Parse and structurally validate *cose_bytes* without verifying signatures.

    Runs steps 1-4 of the verification procedure. Every signature entry comes
    back ``verified=False``. Use it to read a manifest whose keys this party
    does not hold; never to decide that a manifest is authentic.
    """
    return _appraise(cose_bytes, trusted_keys={})


def verify_cose_manifest(
    cose_bytes: bytes, trusted_keys: Mapping[str, str]
) -> CoseVerification:
    """Verify a COSE manifest envelope. Fails closed at the first failure.

    *trusted_keys* maps a hex ``kid`` to a base64url public key, the same
    mapping ``VerificationContext.trusted_keys`` carries for v0.1. For a
    hybrid ``COSE_Sign`` each signer's own key must be present: the entries
    carry component key ids, not v0.1's combined hybrid key id.

    An empty *trusted_keys* is not an error. Structural checks still run and
    the result reports ``verified=False``, which the engine renders as
    ``UNVERIFIABLE``.

    Raises:
        CoseStructureError: Malformed envelope, bad header, unknown crit,
            unknown algorithm, or a payload that is not manifest JSON.
        CoseVersionError: The payload is not a version 0.2 manifest.
        CoseDowngradeError: ``crypto_profile`` requires more than ``alg`` gives.
        CoseKeyError: A ``kid`` is absent from *trusted_keys*.
        cryptography.exceptions.InvalidSignature: A signature did not verify.
        AlgorithmUnavailableError: This build cannot perform the algorithm.
    """
    return _appraise(cose_bytes, trusted_keys=trusted_keys)


def _appraise(
    cose_bytes: bytes, *, trusted_keys: Mapping[str, str]
) -> CoseVerification:
    # Step 1: parse, and reject anything that is not a tagged COSE_Sign1/Sign.
    tag, body = _decode_tagged(cose_bytes)
    body_protected_bytes, unprotected, payload, fourth = body

    # Step 2: the protected header. Read from the byte string as received -
    # the signature covers those exact bytes, so nothing is ever re-encoded.
    body_header = _decode_protected(body_protected_bytes, what="body")
    _check_crit(body_header, what="body")
    _check_unprotected_has_no_alg(unprotected)
    _check_body_type(body_header)

    # Step 3: the payload, and the version gate.
    manifest = _parse_payload(payload)
    _check_version(manifest)

    # Collect the signature entries before step 4, which needs every alg.
    entries: list[tuple[int, bytes, bytes, bytes]] = []  # alg, kid, tbs, sig
    if tag == COSE_SIGN1_TAG:
        if not isinstance(fourth, bytes):
            raise CoseStructureError("COSE_Sign1 signature must be a byte string")
        alg, kid = _read_alg_and_kid(body_header, what="body")
        entries.append(
            (alg, kid, _sig_structure_sign1(body_protected_bytes, payload), fourth)
        )
    else:
        if not isinstance(fourth, (list, tuple)) or not fourth:
            raise CoseStructureError("COSE_Sign carries no signature entries")
        seen_algorithms: set[str] = set()
        for index, raw in enumerate(fourth):
            if not isinstance(raw, (list, tuple)) or len(raw) != 3:
                raise CoseStructureError(
                    f"COSE_Signature {index} must be a three-element array"
                )
            sign_protected_bytes, sign_unprotected, signature = raw
            if not isinstance(sign_protected_bytes, bytes):
                raise CoseStructureError(
                    f"COSE_Signature {index} protected header must be a byte string"
                )
            if not isinstance(sign_unprotected, Mapping):
                raise CoseStructureError(
                    f"COSE_Signature {index} unprotected header must be a map"
                )
            if not isinstance(signature, bytes):
                raise CoseStructureError(
                    f"COSE_Signature {index} signature must be a byte string"
                )
            what = f"COSE_Signature {index}"
            sign_header = _decode_protected(sign_protected_bytes, what=what)
            _check_crit(sign_header, what=what)
            _check_unprotected_has_no_alg(sign_unprotected)
            alg, kid = _read_alg_and_kid(sign_header, what=what)
            family = _algorithm_family(alg)
            if family in seen_algorithms:
                # Two entries for one algorithm cannot make a hybrid signature
                # stronger, and would let a policy check be satisfied twice by
                # the same key. Compared by family, so a -8 entry alongside a
                # -19 entry is caught: both are Ed25519 over the same key type,
                # and two spellings of one algorithm are not two signers.
                raise CoseStructureError(
                    f"COSE_Sign carries more than one "
                    f"{ALG_NAMES.get(alg, alg)} signature entry"
                )
            seen_algorithms.add(family)
            entries.append(
                (
                    alg,
                    kid,
                    _sig_structure_sign(
                        body_protected_bytes, sign_protected_bytes, payload
                    ),
                    signature,
                )
            )

    algorithms = tuple(alg for alg, _, _, _ in entries)

    # Step 4: profile against algorithm, before any signature is checked.
    _check_profile(manifest, algorithms)

    # Step 5: verify every entry. For COSE_Sign that means all of them - a
    # verifier under a post-quantum policy must not accept the classical
    # entry alone, and this profile only ever emits entries that are required.
    signatures = tuple(
        _verify_one(alg, kid, to_be_signed, signature, trusted_keys)
        for alg, kid, to_be_signed, signature in entries
    )

    # Step 7 is the caller's: nothing in the unprotected header has been
    # appraised, and nothing in it influenced whether the signature verified.
    return CoseVerification(
        manifest=manifest,
        payload=payload,
        manifest_hash=payload_hash(payload),
        tag=tag,
        signatures=signatures,
        unprotected=_plain(unprotected),
    )


def read_payload_manifest(cose_bytes: bytes) -> dict[str, Any]:
    """Return the payload's manifest JSON, checking nothing but its shape.

    Deliberately skips the header, version, profile, and signature checks so
    that a rejected envelope can still be labelled with its ``manifest_id``.
    Never use it to decide anything about a manifest.
    """
    _, body = _decode_tagged(cose_bytes)
    return _parse_payload(body[2])
