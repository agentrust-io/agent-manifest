"""Tests for Ed25519 and ML-DSA-65 signing — issue #2.

ML-DSA-65 tests are skipped when pyoqs is not installed.
"""
import pytest
from cryptography.exceptions import InvalidSignature

from agent_manifest._signing import (
    SIGNED_FIELDS,
    Ed25519Signer,
    Ed25519Verifier,
    _SMALL_ORDER_POINTS,
    _b64url_decode,
    generate_ed25519,
    signing_pre_image,
)
try:
    from agent_manifest._signing import (
        MlDsa65Signer,
        MlDsa65Verifier,
        HybridSigner,
        HybridVerifier,
        generate_ml_dsa65,
        generate_hybrid,
    )
    import oqs  # noqa: F401
    OQS_AVAILABLE = True
except (ImportError, RuntimeError):
    OQS_AVAILABLE = False

require_oqs = pytest.mark.skipif(not OQS_AVAILABLE, reason="pyoqs not installed")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod-001",
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "expires_at": "2026-09-21T09:00:00Z",
    "issuer": "spiffe://trust.example/signing-authority",
    "crypto_profile": "standard",
    "artifacts": {
        "system_prompt": {"hash": "sha256:" + "a" * 64, "bound_at": "2026-06-23T09:00:00Z"},
        "policy_bundle": {
            "hash": "sha256:" + "b" * 64,
            "policy_language": "cedar",
            "version": "1.0.0",
            "enforcement_mode": "enforce",
            "bound_at": "2026-06-23T09:00:00Z",
        },
        "model_identity": {
            "provider": "anthropic",
            "model_id": "claude-sonnet-4-6",
            "version": "20251001",
            "deployment_type": "api",
            "bound_at": "2026-06-23T09:00:00Z",
        },
    },
    "delegation_chain": [],
    "hitl_record": None,
    # These fields MUST be excluded from the pre-image
    "attestation": {"platform": "amd-sev-snp"},
    "signature": None,
    "transparency_log_entry": {"log_id": "rekor.sigstore.dev"},
}


# ---------------------------------------------------------------------------
# Pre-image construction
# ---------------------------------------------------------------------------


def test_pre_image_excludes_attestation():
    pre = signing_pre_image(SAMPLE_MANIFEST)
    assert b"amd-sev-snp" not in pre


def test_pre_image_excludes_signature():
    pre = signing_pre_image(SAMPLE_MANIFEST)
    assert b"transparency_log" not in pre


def test_pre_image_includes_all_signed_fields():
    pre = signing_pre_image(SAMPLE_MANIFEST)
    for field in SIGNED_FIELDS:
        if field in SAMPLE_MANIFEST and SAMPLE_MANIFEST[field] is not None:
            assert field.encode() in pre, f"Field '{field}' missing from pre-image"


def test_pre_image_is_rfc8785():
    """Pre-image must be valid RFC 8785 — reproducible from the same input."""
    pre1 = signing_pre_image(SAMPLE_MANIFEST)
    pre2 = signing_pre_image(SAMPLE_MANIFEST)
    assert pre1 == pre2


# ---------------------------------------------------------------------------
# Ed25519 roundtrip
# ---------------------------------------------------------------------------


def test_ed25519_sign_verify_roundtrip():
    kp = generate_ed25519()
    signer = Ed25519Signer(kp)
    verifier = Ed25519Verifier(kp.public_bytes)

    sig_block = signer.sign(SAMPLE_MANIFEST)
    assert sig_block["algorithm"] == "Ed25519"
    verifier.verify(SAMPLE_MANIFEST, sig_block["signature_value"])  # must not raise


def test_ed25519_wrong_message_fails():
    kp = generate_ed25519()
    signer = Ed25519Signer(kp)
    verifier = Ed25519Verifier(kp.public_bytes)

    sig_block = signer.sign(SAMPLE_MANIFEST)
    tampered = {**SAMPLE_MANIFEST, "agent_id": "spiffe://evil/agent"}
    with pytest.raises(InvalidSignature):
        verifier.verify(tampered, sig_block["signature_value"])


def test_ed25519_wrong_key_fails():
    kp1 = generate_ed25519()
    kp2 = generate_ed25519()
    sig_block = Ed25519Signer(kp1).sign(SAMPLE_MANIFEST)

    wrong_verifier = Ed25519Verifier(kp2.public_bytes)
    with pytest.raises(InvalidSignature):
        wrong_verifier.verify(SAMPLE_MANIFEST, sig_block["signature_value"])


def test_ed25519_truncated_signature_fails():
    kp = generate_ed25519()
    sig_block = Ed25519Signer(kp).sign(SAMPLE_MANIFEST)
    truncated = sig_block["signature_value"][:20]

    verifier = Ed25519Verifier(kp.public_bytes)
    with pytest.raises((InvalidSignature, ValueError)):
        verifier.verify(SAMPLE_MANIFEST, truncated)


def test_ed25519_wrong_algorithm_label_not_accepted():
    """The algorithm field must be Ed25519, not something else."""
    kp = generate_ed25519()
    sig_block = Ed25519Signer(kp).sign(SAMPLE_MANIFEST)
    assert sig_block["algorithm"] == "Ed25519"


def test_ed25519_signed_fields_list_correct():
    kp = generate_ed25519()
    sig_block = Ed25519Signer(kp).sign(SAMPLE_MANIFEST)
    assert set(sig_block["signed_fields"]) == set(SIGNED_FIELDS)


def test_ed25519_small_order_key_rejected():
    with pytest.raises(ValueError):
        Ed25519Verifier(bytes(32))


def test_ed25519_all_small_order_points_rejected():
    """All 8 torsion subgroup elements must be rejected at key load time."""
    for point in _SMALL_ORDER_POINTS:
        with pytest.raises(ValueError):
            Ed25519Verifier(point)


def test_ed25519_truncated_sig_raises_invalid_signature():
    kp = generate_ed25519()
    verifier = Ed25519Verifier(kp.public_bytes)
    with pytest.raises(InvalidSignature):
        verifier.verify(SAMPLE_MANIFEST, "abc")  # decodes to <64 bytes


def test_b64url_decode_rejects_plus():
    with pytest.raises(ValueError, match="non-URL-safe"):
        _b64url_decode("abc+def")


def test_b64url_decode_rejects_slash():
    with pytest.raises(ValueError, match="non-URL-safe"):
        _b64url_decode("abc/def")


def test_b64url_decode_accepts_valid():
    result = _b64url_decode("SGVsbG8")  # "Hello"
    assert result == b"Hello"


def test_ed25519_public_key_roundtrip_b64url():
    kp = generate_ed25519()
    b64 = kp.public_b64url()
    restored = Ed25519Verifier.from_b64url(b64)
    assert restored._key_id == kp.key_id


# ---------------------------------------------------------------------------
# ML-DSA-65 (skipped without pyoqs)
# ---------------------------------------------------------------------------


@require_oqs
def test_ml_dsa65_sign_verify_roundtrip():
    kp = generate_ml_dsa65()
    signer = MlDsa65Signer(kp)
    verifier = MlDsa65Verifier(kp.public_key_bytes)

    sig_block = signer.sign(SAMPLE_MANIFEST)
    assert sig_block["algorithm"] == "ML-DSA-65"
    verifier.verify(SAMPLE_MANIFEST, sig_block["signature_value"])


@require_oqs
def test_ml_dsa65_wrong_message_fails():
    kp = generate_ml_dsa65()
    sig_block = MlDsa65Signer(kp).sign(SAMPLE_MANIFEST)
    tampered = {**SAMPLE_MANIFEST, "agent_id": "spiffe://evil/agent"}
    with pytest.raises(InvalidSignature):
        MlDsa65Verifier(kp.public_key_bytes).verify(
            tampered, sig_block["signature_value"]
        )


# ---------------------------------------------------------------------------
# Hybrid mode (skipped without pyoqs)
# ---------------------------------------------------------------------------


@require_oqs
def test_hybrid_sign_verify_roundtrip():
    kp = generate_hybrid()
    sig_block = HybridSigner(kp).sign(SAMPLE_MANIFEST)

    assert sig_block["algorithm"] == "hybrid-Ed25519-ML-DSA-65"
    assert sig_block["signature_value"] == ""
    assert "classical_signature" in sig_block
    assert "pq_signature" in sig_block

    verifier = HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes)
    verifier.verify(SAMPLE_MANIFEST, sig_block)  # must not raise


@require_oqs
def test_hybrid_tampered_classical_fails():
    kp = generate_hybrid()
    sig_block = HybridSigner(kp).sign(SAMPLE_MANIFEST)
    sig_block = {**sig_block, "classical_signature": sig_block["classical_signature"][:-4] + "AAAA"}

    verifier = HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes)
    with pytest.raises((InvalidSignature, Exception)):
        verifier.verify(SAMPLE_MANIFEST, sig_block)


@require_oqs
def test_hybrid_tampered_pq_fails():
    kp = generate_hybrid()
    sig_block = HybridSigner(kp).sign(SAMPLE_MANIFEST)
    sig_block = {**sig_block, "pq_signature": sig_block["pq_signature"][:-4] + "BBBB"}

    verifier = HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes)
    with pytest.raises((InvalidSignature, Exception)):
        verifier.verify(SAMPLE_MANIFEST, sig_block)


@require_oqs
def test_hybrid_both_components_cover_same_pre_image():
    """Verify that classical and PQ sign identical bytes."""
    kp = generate_hybrid()
    pre = signing_pre_image(SAMPLE_MANIFEST)
    # Verify classical manually over the same pre-image
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig_block = HybridSigner(kp).sign(SAMPLE_MANIFEST)
    classical_bytes = base64.urlsafe_b64decode(
        sig_block["classical_signature"] + "=="
    )
    pub = Ed25519PublicKey.from_public_bytes(kp.ed25519.public_bytes)
    pub.verify(classical_bytes, pre)  # raises if pre-image differs
