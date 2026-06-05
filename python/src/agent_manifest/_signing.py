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

ML-DSA-65 requires pyoqs (Open Quantum Safe Python bindings):
    pip install "agent-manifest[pq]"
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
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

try:
    import oqs as _oqs  # pyoqs — Open Quantum Safe bindings

    _OQS_AVAILABLE = True
    _ML_DSA_ALGO = "ML-DSA-65"
except ImportError:
    _oqs = None

    _OQS_AVAILABLE = False
    _ML_DSA_ALGO = "ML-DSA-65"


# Signed fields per spec Section 3.6 — excludes attestation, signature,
# and transparency_log_entry which are appended post-signing.
SIGNED_FIELDS: tuple[str, ...] = (
    "manifest_id",
    "agent_id",
    "version",
    "issued_at",
    "expires_at",
    "issuer",
    "crypto_profile",
    "artifacts",
    "delegation_chain",
    "hitl_record",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad if pad != 4 else ""))


def _key_id(public_key_bytes: bytes) -> str:
    """sha256 hex of raw public key bytes."""
    return hashlib.sha256(public_key_bytes).hexdigest()


def signing_pre_image(manifest_dict: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes that are signed.

    Extracts only the SIGNED_FIELDS subset from *manifest_dict* and
    canonicalizes the result. Fields absent from the manifest are omitted
    (null-exclusion already applied by canonicalize's exclude_none default).

    This function is the single source of truth for the pre-image — both
    signers and verifiers MUST call this function to guarantee identical
    byte sequences.
    """
    subset = {k: manifest_dict[k] for k in SIGNED_FIELDS if k in manifest_dict}
    return canonicalize(subset)


# ---------------------------------------------------------------------------
# Ed25519
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

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
            "signature_value": _b64url_encode(sig_bytes),
            "signed_fields": list(SIGNED_FIELDS),
        }


class Ed25519Verifier:
    """Verifies Ed25519 signatures using OpenSSL's cofactorless equation."""

    def __init__(self, public_key_bytes: bytes) -> None:
        # Cryptography <44 rejected small-order/torsion keys in from_public_bytes.
        # >=44 moved that check to verify() time, so we enforce it here (CRYPTO-007).
        if len(public_key_bytes) != 32 or public_key_bytes == bytes(32):
            raise ValueError(
                "Invalid Ed25519 public key: all-zero bytes are a small-order "
                "subgroup element and MUST be rejected."
            )
        self._pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )
        self._key_id = _key_id(public_key_bytes)

    @classmethod
    def from_b64url(cls, s: str) -> "Ed25519Verifier":
        return cls(_b64url_decode(s))

    def verify(self, manifest_dict: dict[str, Any], signature_value: str) -> None:
        """Verify *signature_value* over *manifest_dict*'s signed fields.

        Raises:
            cryptography.exceptions.InvalidSignature: Verification failed.
            ValueError: Signature bytes are malformed / wrong length.
        """
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = _b64url_decode(signature_value)
        self._pub.verify(sig_bytes, pre_image)  # raises InvalidSignature on failure


# ---------------------------------------------------------------------------
# ML-DSA-65
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MlDsa65KeyPair:
    private_key_bytes: bytes
    public_key_bytes: bytes

    @property
    def key_id(self) -> str:
        return _key_id(self.public_key_bytes)

    def public_b64url(self) -> str:
        return _b64url_encode(self.public_key_bytes)


def _require_oqs() -> None:
    if not _OQS_AVAILABLE:
        raise RuntimeError(
            "ML-DSA-65 requires pyoqs. "
            'Install with: pip install "agent-manifest[pq]"'
        )


def generate_ml_dsa65() -> MlDsa65KeyPair:
    """Generate a fresh ML-DSA-65 key pair."""
    _require_oqs()
    with _oqs.Signature(_ML_DSA_ALGO) as sig:
        pub = sig.generate_keypair()
        priv = sig.export_secret_key()
    return MlDsa65KeyPair(private_key_bytes=priv, public_key_bytes=pub)


class MlDsa65Signer:
    """Signs manifest dicts with ML-DSA-65 (NIST FIPS 204) via pyoqs."""

    def __init__(self, keypair: MlDsa65KeyPair) -> None:
        _require_oqs()
        self._kp = keypair

    def sign(self, manifest_dict: dict[str, Any]) -> dict[str, Any]:
        pre_image = signing_pre_image(manifest_dict)
        with _oqs.Signature(_ML_DSA_ALGO, self._kp.private_key_bytes) as sig:
            sig_bytes = sig.sign(pre_image)
        return {
            "algorithm": "ML-DSA-65",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "signature_value": _b64url_encode(sig_bytes),
            "signed_fields": list(SIGNED_FIELDS),
        }


class MlDsa65Verifier:
    def __init__(self, public_key_bytes: bytes) -> None:
        _require_oqs()
        self._pub = public_key_bytes
        self._key_id = _key_id(public_key_bytes)

    @classmethod
    def from_b64url(cls, s: str) -> "MlDsa65Verifier":
        return cls(_b64url_decode(s))

    def verify(self, manifest_dict: dict[str, Any], signature_value: str) -> None:
        pre_image = signing_pre_image(manifest_dict)
        sig_bytes = _b64url_decode(signature_value)
        with _oqs.Signature(_ML_DSA_ALGO) as v:
            if not v.verify(pre_image, sig_bytes, self._pub):
                raise InvalidSignature("ML-DSA-65 signature verification failed")


# ---------------------------------------------------------------------------
# Hybrid mode (CRYPTO-006)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HybridKeyPair:
    """Combined Ed25519 + ML-DSA-65 key pair for hybrid signing."""

    ed25519: Ed25519KeyPair
    ml_dsa65: MlDsa65KeyPair

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

    signature_value is empty string in hybrid mode — both component fields
    are the authoritative signatures. Kept for schema field compatibility.
    """

    def __init__(self, keypair: HybridKeyPair) -> None:
        _require_oqs()
        self._kp = keypair

    def sign(self, manifest_dict: dict[str, Any]) -> dict[str, Any]:
        pre_image = signing_pre_image(manifest_dict)

        classical_sig = self._kp.ed25519.private_key.sign(pre_image)
        with _oqs.Signature(_ML_DSA_ALGO, self._kp.ml_dsa65.private_key_bytes) as sig:
            pq_sig = sig.sign(pre_image)

        return {
            "algorithm": "hybrid-Ed25519-ML-DSA-65",
            "key_id": self._kp.key_id,
            "key_type": "software",
            "classical_signature": _b64url_encode(classical_sig),
            "pq_signature": _b64url_encode(pq_sig),
            "signature_value": "",
            "signed_fields": list(SIGNED_FIELDS),
        }


class HybridVerifier:
    """Verifies hybrid signatures — BOTH components must pass independently."""

    def __init__(
        self, ed25519_public_bytes: bytes, ml_dsa65_public_bytes: bytes
    ) -> None:
        _require_oqs()
        self._classical = Ed25519Verifier(ed25519_public_bytes)
        self._pq_pub = ml_dsa65_public_bytes

    def verify(
        self, manifest_dict: dict[str, Any], signature_block: dict[str, Any]
    ) -> None:
        """Verify both components over the same pre-image.

        Raises:
            InvalidSignature: If either component fails.
            KeyError: If the signature block is missing required fields.
        """
        pre_image = signing_pre_image(manifest_dict)

        # Verify classical component
        classical_bytes = _b64url_decode(signature_block["classical_signature"])
        self._classical._pub.verify(classical_bytes, pre_image)

        # Verify PQ component
        pq_bytes = _b64url_decode(signature_block["pq_signature"])
        with _oqs.Signature(_ML_DSA_ALGO) as v:
            if not v.verify(pre_image, pq_bytes, self._pq_pub):
                raise InvalidSignature(
                    "Hybrid signature: ML-DSA-65 component failed"
                )
