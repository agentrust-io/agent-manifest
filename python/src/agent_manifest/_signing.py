"""Ed25519 and ML-DSA-65 signing and verification for Agent Manifest SDK.

Standard profile (Levels 0-2): Ed25519 (RFC 8032)
Post-quantum profile (Level 3): ML-DSA-65 (NIST FIPS 204)
Hybrid mode: both algorithms required, both must verify independently

Signing pre-image: RFC 8785 canonical JSON of the manifest's signed_fields.
Key identifiers: sha256 hex-digest of the raw public key bytes.
Signatures: base64url-encoded (no padding).

Ed25519 implementation notes (CRYPTO-007):
  The cryptography library (PyCA/OpenSSL) enforces:
    - Cofactorless equation: [S]B == R + [k]A
    - Non-canonical point encodings are rejected
    - Small-order / torsion-component keys are rejected at load time
  These properties are inherited from OpenSSL's EVP_PKEY Ed25519 validation.

ML-DSA-65 backends, in preference order:
  1. ``cryptography`` >= 47, which implements ML-DSA through OpenSSL. This is
     already a required dependency, so the post-quantum profile needs no
     separate install:  pip install "agent-manifest[pq]"
  2. The liboqs Python bindings, if importable as ``oqs``. Supported for
     deployments already carrying them; no longer required, and not installed
     by any extra.

The two differ only in private key encoding - cryptography works in the
32-byte seed, liboqs in the expanded secret key. Public keys are the same
1952-byte encoding in both, so key ids, COSE ``kid`` values, and signatures
are interoperable regardless of which backend produced them.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ._canonicalize import canonicalize

_ML_DSA_ALGO = "ML-DSA-65"

# ML-DSA-65 comes from cryptography where available, and from the Open Quantum
# Safe bindings otherwise.
#
# cryptography is preferred because it is already a required dependency, it is
# the implementation the rest of this module uses, and it needs no separate
# install. It gained ML-DSA in 47.0.0; the module can still raise
# UnsupportedAlgorithm at call time when the linked OpenSSL is too old, which
# is a capability gap and surfaces as AlgorithmUnavailableError.
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _CRYPTOGRAPHY_MLDSA_AVAILABLE = True
except ImportError:  # cryptography < 47
    _mldsa = None  # type: ignore[assignment]
    _CRYPTOGRAPHY_MLDSA_AVAILABLE = False

# The liboqs binding is optional and kept for deployments already using it.
# The capability check is deliberately not "the import succeeded": the module
# name `oqs` on PyPI belongs to an unrelated project, and importing it must
# not be read as post-quantum support (see also the `pq` extra, which no
# longer names a liboqs package because none is published under `pyoqs`).
def _has_liboqs_api(module: Any) -> bool:
    """Identify liboqs by its API rather than by the module name it occupies."""
    return hasattr(module, "Signature")


try:
    import oqs as _oqs

    _OQS_AVAILABLE = _has_liboqs_api(_oqs)
except ImportError:
    _oqs = None
    _OQS_AVAILABLE = False

# FIPS 204 ML-DSA-65 sizes. The seed is the portable private key form (the
# `[0] seed` choice of the AKP private key, RFC 9964); liboqs works in
# expanded secret keys instead, which is why key material identifies its own
# backend below.
_ML_DSA_65_SEED_LEN = 32
_ML_DSA_65_PUBLIC_LEN = 1952

# PKCS#8 wrapper for a 32-byte ML-DSA-65 seed:
#   SEQUENCE { INTEGER 0, AlgorithmIdentifier(2.16.840.1.101.3.4.3.18),
#              OCTET STRING { [0] seed } }
# cryptography exposes no raw-seed loader, so a seed is wrapped before loading.
# test_ml_dsa_seed_wrapper_matches_cryptography pins this against what
# cryptography itself emits, so an encoding change cannot pass silently.
_ML_DSA_65_PKCS8_SEED_PREFIX = bytes.fromhex(
    "3034020100300b060960864801650304031204228020"
)


class AlgorithmUnavailableError(RuntimeError):
    """This build cannot perform the requested algorithm.

    Distinct from a verification failure: the manifest may be perfectly
    valid, this verifier simply lacks the capability to appraise it. The
    verification engine translates this into ``UNVERIFIABLE`` rather than
    ``MISMATCH`` so a capability gap is never reported as a bad manifest.

    Subclasses ``RuntimeError``, which is what ``_require_oqs()`` raised
    before this type existed, so existing callers keep working.
    """


# Signed fields per the spec Section 3.6 normative signing coverage table
# (PR #160). Excludes attestation, signature, and transparency_log_entry,
# which are appended post-signing. This list is fixed and normative - it
# MUST NOT be varied by implementations.
SIGNED_FIELDS: tuple[str, ...] = (
    "@context",
    "@type",
    "manifest_id",
    "previous_manifest_id",
    "agent_id",
    # Spec 6.4.2. Same compatibility argument as `intent` below: absent
    # fields are omitted from the pre-image, so every existing signature
    # still verifies. It has to be signed, because an instance identity a
    # signature does not cover is one the operator can retarget after the
    # fact, and the OCSF join is exactly what depends on it.
    "agent_instance_id",
    "version",
    "min_verifier_version",
    "issued_at",
    "expires_at",
    "issuer",
    "crypto_profile",
    "profile",
    "unbound_artifacts",
    "source_bundle",
    "artifacts",
    "delegation_chain",
    "hitl_record",
    "prior_transparency_log_entry",
    "log_retention",
    "data_scope",
    "operational_lifecycle",
    # Spec 3.9. Adding a field here is normally a compatibility break, and is
    # not one in this case: signing_pre_image omits fields absent from the
    # manifest, so a manifest with no `intent` produces byte-identical
    # pre-image to before and its signature still verifies. The field has to
    # be in this tuple rather than outside it, because an intent the signature
    # does not cover is an intent anyone downstream can rewrite.
    "intent",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# NOTE: intentionally NOT anchored with `$` -- Python's `$` matches at
# end-of-string OR just before a single trailing '\n', which would let
# "<valid-b64url>\n" slip past this alphabet check even though '\n' isn't
# in the URL-safe alphabet, and base64.urlsafe_b64decode() would then
# silently drop that '\n' and decode it identically to the un-suffixed
# value -- defeating the CRYPTO-006 guard below. fullmatch() (no anchors)
# does not have this hole.
_B64URL_RE = re.compile(r"[A-Za-z0-9\-_]*")



def _signed_at_now() -> str:
    """ISO 8601 UTC timestamp for the signature block's signed_at (spec 3.6)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _b64url_decode(s: str) -> bytes:
    # CRYPTO-006: reject standard base64 (+/) - only URL-safe chars allowed
    if not isinstance(s, str) or not _B64URL_RE.fullmatch(s):
        raise ValueError(
            "Invalid base64url: contains non-URL-safe characters (use - and _ not + and /)"
        )
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))


def _key_id(public_key_bytes: bytes) -> str:
    """sha256 hex of raw public key bytes."""
    return hashlib.sha256(public_key_bytes).hexdigest()


def intent_hash(manifest_dict: dict[str, Any]) -> str | None:
    """Return ``sha256:<hex>`` over the manifest's declared intent, or None.

    Derived rather than stored (spec 3.9). A runtime that wants to bind the
    intent into a per-call receipt references this digest instead of copying the
    statement, and because it is computed from the manifest on demand there is
    no second representation that can be made to disagree with the first.

    Computed over the RFC 8785 canonical form of the whole ``intent`` object, so
    a field added to it in a later revision is covered without changing this
    function. Returns None when the manifest declares no intent, which is a
    distinct answer from a digest over an empty statement.
    """
    intent = manifest_dict.get("intent")
    if intent is None:
        return None
    return "sha256:" + hashlib.sha256(canonicalize(intent)).hexdigest()


def signing_pre_image(manifest_dict: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes that are signed.

    Extracts only the SIGNED_FIELDS subset from *manifest_dict* and
    canonicalizes the result. Fields absent from the manifest are omitted
    (null-exclusion already applied by canonicalize's exclude_none default).

    Normalization rule (spec Section 3.6, ADR-0006 as amended): the value of
    ``hitl_record.approvals`` is normalized to ``[]`` before canonicalization.
    The HITL requirement itself stays tamper-evident under the issuer
    signature while approvals attach post-issuance without re-signing; each
    approval is authenticated separately by its own ``approval_signature``.

    This function is the single source of truth for the pre-image - both
    signers and verifiers MUST call this function to guarantee identical
    byte sequences.
    """
    subset = {k: manifest_dict[k] for k in SIGNED_FIELDS if k in manifest_dict}
    hitl_record = subset.get("hitl_record")
    if isinstance(hitl_record, dict):
        normalized = dict(hitl_record)
        normalized["approvals"] = []
        subset["hitl_record"] = normalized
    return canonicalize(subset)


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------

# CRYPTO-005: all 8 low-order (torsion) points of the Ed25519 curve - cofactor 8.
# A key equal to any of these allows signature forgery; reject at load time.
_SMALL_ORDER_POINTS: frozenset[bytes] = frozenset({
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
})


@dataclass(frozen=True)
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def __repr__(self) -> str:
        return f"Ed25519KeyPair(key_id={self.key_id!r}, private_key=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        return _key_id(self.public_bytes)

    def public_b64url(self) -> str:
        return _b64url_encode(self.public_bytes)

    def private_b64url(self) -> str:
        raw = self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return _b64url_encode(raw)


def generate_ed25519() -> Ed25519KeyPair:
    """Generate a fresh Ed25519 key pair."""
    priv = Ed25519PrivateKey.generate()
    return Ed25519KeyPair(private_key=priv, public_key=priv.public_key())


def ed25519_from_private_bytes(raw: bytes) -> Ed25519KeyPair:
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return Ed25519KeyPair(private_key=priv, public_key=priv.public_key())


class Ed25519Signer:
    """Signs manifest dicts with Ed25519 (RFC 8032, deterministic).

    For production use on high-value keys, prefer a HSM implementation
    of hedged signing (draft-irtf-cfrg-det-sigs-with-noise) to protect
    against fault attacks on the deterministic nonce derivation.
    """

    def __init__(self, keypair: Ed25519KeyPair) -> None:
        self._kp = keypair

    def sign(self, manifest_dict: dict[str, Any]) -> dict[str, Any]:
        """Return a signature block dict suitable for ManifestSignature."""
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = self._kp.private_key.sign(pre_image)
        return {
            "algorithm": "Ed25519",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "signed_at": _signed_at_now(),
            "signature_value": _b64url_encode(sig_bytes),
            "signed_fields": list(SIGNED_FIELDS),
        }


class Ed25519Verifier:
    """Verifies Ed25519 signatures using OpenSSL's cofactorless equation."""

    def __init__(self, public_key_bytes: bytes) -> None:
        # CRYPTO-005: reject all 8 torsion (small-order) subgroup elements.
        # cryptography >=44 moved this check to verify() time - enforce it here.
        if len(public_key_bytes) != 32 or public_key_bytes in _SMALL_ORDER_POINTS:
            raise ValueError(
                "Invalid Ed25519 public key: key is a small-order subgroup element "
                "(torsion point) and MUST be rejected."
            )
        self._pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        self._key_id = _key_id(public_key_bytes)

    @classmethod
    def from_b64url(cls, s: str) -> "Ed25519Verifier":
        return cls(_b64url_decode(s))

    def verify_bytes(self, pre_image: bytes, signature_value: str) -> None:
        """Verify *signature_value* over already-canonicalized *pre_image* bytes.

        The manifest pre-image is fixed and normative, so manifest callers use
        :meth:`verify`. TRACE envelopes (spec 6.3.2) and evidence packs (spec
        5.2.1) cover a different field set and supply their canonical bytes
        directly through this method.

        Raises:
            cryptography.exceptions.InvalidSignature: Verification failed or wrong length.
            ValueError: Signature string contains non-URL-safe base64 characters.
        """
        sig_bytes = _b64url_decode(signature_value)
        # SIGN-001: reject before passing to OpenSSL - avoids undefined-length inputs
        if len(sig_bytes) != 64:
            raise InvalidSignature(
                f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}"
            )
        self._pub.verify(sig_bytes, pre_image)  # raises InvalidSignature on failure

    def verify(self, manifest_dict: dict[str, Any], signature_value: str) -> None:
        """Verify *signature_value* over *manifest_dict*'s signed fields.

        Raises:
            cryptography.exceptions.InvalidSignature: Verification failed or wrong length.
            ValueError: Signature string contains non-URL-safe base64 characters.
        """
        self.verify_bytes(signing_pre_image(manifest_dict), signature_value)


# ---------------------------------------------------------------------------
# ML-DSA-65
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MlDsa65KeyPair:
    private_key_bytes: bytes
    public_key_bytes: bytes

    def __repr__(self) -> str:
        return f"MlDsa65KeyPair(key_id={self.key_id!r}, private_key_bytes=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def key_id(self) -> str:
        return _key_id(self.public_key_bytes)

    def public_b64url(self) -> str:
        return _b64url_encode(self.public_key_bytes)


def ml_dsa65_available() -> bool:
    """True when this build can perform ML-DSA-65 through either backend."""
    return _CRYPTOGRAPHY_MLDSA_AVAILABLE or _OQS_AVAILABLE


def _require_ml_dsa() -> None:
    """Raise unless some ML-DSA-65 backend is present.

    A capability gap, never a verification failure: callers translate this
    into ``UNVERIFIABLE`` so a build that cannot appraise a signature never
    reports the manifest as bad (spec 4.2, ADR-0005 as amended).
    """
    if not ml_dsa65_available():
        raise AlgorithmUnavailableError(
            "ML-DSA-65 is unavailable in this build. It needs cryptography "
            ">= 47 (install with: pip install \"agent-manifest[pq]\") or the "
            "liboqs Python bindings importable as `oqs`."
        )


# Kept because it is the name this module raised under before the backend
# became pluggable, and callers outside this file used it.
_require_oqs = _require_ml_dsa


def _mldsa_key_from_seed(seed: bytes) -> Any:
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    return load_der_private_key(
        _ML_DSA_65_PKCS8_SEED_PREFIX + seed, password=None
    )


def _ml_dsa_sign_raw(private_key_bytes: bytes, data: bytes) -> bytes:
    """Sign *data*, choosing the backend that understands the key material.

    A 32-byte value is a seed and belongs to cryptography; anything else is a
    liboqs expanded secret key. Dispatching on the key rather than on a
    configured preference means a keypair generated under either backend keeps
    working when the other one is also installed.
    """
    is_seed = len(private_key_bytes) == _ML_DSA_65_SEED_LEN
    if is_seed and _CRYPTOGRAPHY_MLDSA_AVAILABLE:
        try:
            signature: bytes = _mldsa_key_from_seed(private_key_bytes).sign(data)
        except UnsupportedAlgorithm as exc:  # OpenSSL too old
            raise AlgorithmUnavailableError(
                f"ML-DSA-65 is not available from this OpenSSL build: {exc}"
            ) from exc
        return signature
    if not is_seed and _OQS_AVAILABLE:
        with _oqs.Signature(_ML_DSA_ALGO, private_key_bytes) as sig:
            oqs_signature: bytes = sig.sign(data)
        return oqs_signature
    _require_ml_dsa()
    raise AlgorithmUnavailableError(
        f"this ML-DSA-65 private key is a "
        f"{'seed' if is_seed else 'liboqs expanded secret key'} "
        f"({len(private_key_bytes)} bytes), and the backend that reads that "
        f"form is not installed"
    )


def _ml_dsa_verify_raw(
    public_key_bytes: bytes, data: bytes, signature: bytes
) -> bool:
    """Verify *signature*. Public keys are the same raw encoding in both
    backends, so verification is interoperable regardless of who signed."""
    if _CRYPTOGRAPHY_MLDSA_AVAILABLE:
        try:
            _mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes).verify(
                signature, data
            )
        except UnsupportedAlgorithm as exc:
            raise AlgorithmUnavailableError(
                f"ML-DSA-65 is not available from this OpenSSL build: {exc}"
            ) from exc
        except InvalidSignature:
            return False
        except ValueError:
            return False
        return True
    if _OQS_AVAILABLE:
        with _oqs.Signature(_ML_DSA_ALGO) as v:
            verified: bool = v.verify(data, signature, public_key_bytes)
        return verified
    _require_ml_dsa()
    return False  # unreachable; _require_ml_dsa always raises here


def generate_ml_dsa65() -> MlDsa65KeyPair:
    """Generate a fresh ML-DSA-65 key pair.

    Under cryptography the private key is the 32-byte seed, which is the
    portable form; under liboqs it is the expanded secret key. Public keys are
    the same 1952-byte encoding either way, so ``key_id`` - and every
    signature anyone else verifies - is identical across backends.
    """
    _require_ml_dsa()
    if _CRYPTOGRAPHY_MLDSA_AVAILABLE:
        try:
            key = _mldsa.MLDSA65PrivateKey.generate()
        except UnsupportedAlgorithm as exc:
            raise AlgorithmUnavailableError(
                f"ML-DSA-65 is not available from this OpenSSL build: {exc}"
            ) from exc
        return MlDsa65KeyPair(
            private_key_bytes=key.private_bytes_raw(),
            public_key_bytes=key.public_key().public_bytes_raw(),
        )
    with _oqs.Signature(_ML_DSA_ALGO) as sig:
        pub = sig.generate_keypair()
        priv = sig.export_secret_key()
    return MlDsa65KeyPair(private_key_bytes=priv, public_key_bytes=pub)


class MlDsa65Signer:
    """Signs manifest dicts with ML-DSA-65 (NIST FIPS 204)."""

    def __init__(self, keypair: MlDsa65KeyPair) -> None:
        _require_ml_dsa()
        self._kp = keypair

    def sign(self, manifest_dict: dict[str, Any]) -> dict[str, Any]:
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = _ml_dsa_sign_raw(self._kp.private_key_bytes, pre_image)
        return {
            "algorithm": "ML-DSA-65",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "signed_at": _signed_at_now(),
            "signature_value": _b64url_encode(sig_bytes),
            "signed_fields": list(SIGNED_FIELDS),
        }


class MlDsa65Verifier:
    def __init__(self, public_key_bytes: bytes) -> None:
        _require_ml_dsa()
        self._pub = public_key_bytes
        self._key_id = _key_id(public_key_bytes)

    @classmethod
    def from_b64url(cls, s: str) -> "MlDsa65Verifier":
        return cls(_b64url_decode(s))

    def verify_bytes(self, pre_image: bytes, signature_value: str) -> None:
        """Verify *signature_value* over already-canonicalized *pre_image* bytes.

        See :meth:`Ed25519Verifier.verify_bytes` for why this exists.
        """
        sig_bytes = _b64url_decode(signature_value)
        if not _ml_dsa_verify_raw(self._pub, pre_image, sig_bytes):
            raise InvalidSignature("ML-DSA-65 signature verification failed")

    def verify(self, manifest_dict: dict[str, Any], signature_value: str) -> None:
        self.verify_bytes(signing_pre_image(manifest_dict), signature_value)


# ---------------------------------------------------------------------------
# Hybrid mode (CRYPTO-006)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridKeyPair:
    """Combined Ed25519 + ML-DSA-65 key pair for hybrid signing."""

    ed25519: Ed25519KeyPair
    ml_dsa65: MlDsa65KeyPair

    def __repr__(self) -> str:
        return f"HybridKeyPair(key_id={self.key_id!r}, ed25519=<REDACTED>, ml_dsa65=<REDACTED>)"

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def key_id(self) -> str:
        # Combined key_id = sha256(classical_pub_bytes || pq_pub_bytes)
        combined = self.ed25519.public_bytes + self.ml_dsa65.public_key_bytes
        return hashlib.sha256(combined).hexdigest()


def generate_hybrid() -> HybridKeyPair:
    return HybridKeyPair(
        ed25519=generate_ed25519(),
        ml_dsa65=generate_ml_dsa65(),
    )


class HybridSigner:
    """Signs with both Ed25519 and ML-DSA-65 over the identical pre-image.

    Hybrid envelope format (spec Section 3.6, issue #30):
    {
        "algorithm": "hybrid-Ed25519-ML-DSA-65",
        "key_id": "<sha256(classical_pub || pq_pub)>",
        "key_type": "software",
        "classical_signature": "<base64url Ed25519 sig>",
        "pq_signature": "<base64url ML-DSA-65 sig>",
        "signature_value": "",
        "signed_fields": [...]
    }

    signature_value is empty string in hybrid mode - both component fields
    are the authoritative signatures. Kept for schema field compatibility.
    """

    def __init__(self, keypair: HybridKeyPair) -> None:
        _require_ml_dsa()
        self._kp = keypair

    def sign(self, manifest_dict: dict[str, Any]) -> dict[str, Any]:
        pre_image = signing_pre_image(manifest_dict)

        classical_sig = self._kp.ed25519.private_key.sign(pre_image)
        pq_sig = _ml_dsa_sign_raw(self._kp.ml_dsa65.private_key_bytes, pre_image)

        return {
            "algorithm": "hybrid-Ed25519-ML-DSA-65",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "signed_at": _signed_at_now(),
            "classical_signature": _b64url_encode(classical_sig),
            "pq_signature": _b64url_encode(pq_sig),
            "signature_value": "",
            "signed_fields": list(SIGNED_FIELDS),
        }


class HybridVerifier:
    """Verifies hybrid signatures - BOTH components must pass independently."""

    def __init__(
        self, ed25519_public_bytes: bytes, ml_dsa65_public_bytes: bytes
    ) -> None:
        _require_ml_dsa()
        self._classical = Ed25519Verifier(ed25519_public_bytes)
        self._pq_pub = ml_dsa65_public_bytes

    def verify_bytes(
        self, pre_image: bytes, signature_block: dict[str, Any]
    ) -> None:
        """Verify both components over already-canonicalized *pre_image* bytes.

        See :meth:`Ed25519Verifier.verify_bytes` for why this exists.

        Raises:
            InvalidSignature: If either component fails.
            KeyError: If the signature block is missing required fields.
        """
        # Verify classical component
        classical_bytes = _b64url_decode(signature_block["classical_signature"])
        self._classical._pub.verify(classical_bytes, pre_image)

        # Verify PQ component
        pq_bytes = _b64url_decode(signature_block["pq_signature"])
        if not _ml_dsa_verify_raw(self._pq_pub, pre_image, pq_bytes):
            raise InvalidSignature("Hybrid signature: ML-DSA-65 component failed")

    def verify(
        self, manifest_dict: dict[str, Any], signature_block: dict[str, Any]
    ) -> None:
        """Verify both components over the same manifest pre-image."""
        self.verify_bytes(signing_pre_image(manifest_dict), signature_block)
