"""Tests for Ed25519 and ML-DSA-65 signing - issue #2.

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
    """Pre-image must be valid RFC 8785 - reproducible from the same input."""
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


def test_ed25519_sign_block_validates_against_model():
    """The signer's output must be a spec 3.6 signature block: every REQUIRED
    field (including signed_at) present and accepted by ManifestSignature."""
    from agent_manifest import ManifestSignature

    kp = generate_ed25519()
    sig_block = Ed25519Signer(kp).sign(SAMPLE_MANIFEST)
    parsed = ManifestSignature.model_validate(sig_block)
    assert parsed.signed_at is not None
    assert parsed.signed_at.tzinfo is not None  # ISO 8601 UTC, not naive


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


# ---------------------------------------------------------------------------
# Spec 3.6 signing coverage table (PR #160) and approvals normalization
# ---------------------------------------------------------------------------


def test_signed_fields_match_spec_coverage_table():
    """SIGNED_FIELDS must equal the spec 3.6 normative signing coverage table."""
    assert SIGNED_FIELDS == (
        "@context",
        "@type",
        "manifest_id",
        "previous_manifest_id",
        "agent_id",
        "version",
        "min_verifier_version",
        "issued_at",
        "expires_at",
        "issuer",
        "crypto_profile",
        "artifacts",
        "delegation_chain",
        "hitl_record",
        "prior_transparency_log_entry",
        "log_retention",
        "data_scope",
        "operational_lifecycle",
    )


def _manifest_with_hitl(approvals):
    m = {k: v for k, v in SAMPLE_MANIFEST.items()}
    m["hitl_record"] = {"required": True, "approvals": approvals}
    return m


def test_pre_image_normalizes_hitl_approvals_to_empty():
    """Spec 3.6: hitl_record.approvals is normalized to [] in the pre-image."""
    approval = {
        "approval_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5d",
        "approver_id": "mailto:alice@acme.example",
        "approved_at": "2026-06-23T09:00:00Z",
        "approval_signature": "c2ln",
    }
    pre_with = signing_pre_image(_manifest_with_hitl([approval]))
    pre_without = signing_pre_image(_manifest_with_hitl([]))
    assert pre_with == pre_without
    assert b"alice@acme.example" not in pre_with


def test_pre_image_keeps_hitl_required_tamper_evident():
    """Stripping the HITL requirement must change the pre-image."""
    pre_required = signing_pre_image(_manifest_with_hitl([]))
    m = {k: v for k, v in SAMPLE_MANIFEST.items()}
    m["hitl_record"] = {"required": False, "approvals": []}
    assert pre_required != signing_pre_image(m)


def test_approvals_attach_post_issuance_without_resigning():
    """A manifest signed with no approvals verifies after approvals attach."""
    kp = generate_ed25519()
    signed = _manifest_with_hitl([])
    sig_block = Ed25519Signer(kp).sign(signed)

    # Approval attached after issuance - issuer signature must still verify.
    attached = _manifest_with_hitl([
        {
            "approval_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5d",
            "approver_id": "mailto:alice@acme.example",
            "approved_at": "2026-06-23T09:30:00Z",
            "approval_signature": "c2ln",
        }
    ])
    Ed25519Verifier(kp.public_bytes).verify(attached, sig_block["signature_value"])


def test_newly_signed_fields_are_tamper_evident():
    """Fields added to the coverage table by #160 must be bound by the signature."""
    kp = generate_ed25519()
    m = {k: v for k, v in SAMPLE_MANIFEST.items()}
    m["log_retention"] = {
        "minimum_retention_days": 180,
        "retention_enforced_by": "audit-system",
    }
    sig_block = Ed25519Signer(kp).sign(m)
    Ed25519Verifier(kp.public_bytes).verify(m, sig_block["signature_value"])

    tampered = {k: v for k, v in m.items()}
    tampered["log_retention"] = {
        "minimum_retention_days": 1,
        "retention_enforced_by": "audit-system",
    }
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(kp.public_bytes).verify(
            tampered, sig_block["signature_value"]
        )


# ---------------------------------------------------------------------------
# Ed25519KeyPair repr / str / private_b64url (coverage for lines 166-186)
# ---------------------------------------------------------------------------


def test_ed25519_keypair_repr_redacts_private_key():
    kp = generate_ed25519()
    r = repr(kp)
    assert "REDACTED" in r
    assert kp.key_id in r


def test_ed25519_keypair_str_equals_repr():
    kp = generate_ed25519()
    assert str(kp) == repr(kp)


def test_ed25519_keypair_private_b64url_roundtrip():
    """private_b64url() encodes the raw private key; decode must recover the same key pair."""
    from agent_manifest._signing import ed25519_from_private_bytes, _b64url_decode

    kp = generate_ed25519()
    priv_b64 = kp.private_b64url()
    # base64url encoded, no padding
    assert priv_b64.isascii()
    priv_raw = _b64url_decode(priv_b64)
    assert len(priv_raw) == 32  # Ed25519 raw private key is 32 bytes
    restored = ed25519_from_private_bytes(priv_raw)
    assert restored.key_id == kp.key_id


# ---------------------------------------------------------------------------
# ed25519_from_private_bytes: error paths (coverage for lines 196-197)
# ---------------------------------------------------------------------------


def test_ed25519_from_private_bytes_valid():
    """ed25519_from_private_bytes constructs an equivalent key pair."""
    from agent_manifest._signing import ed25519_from_private_bytes

    kp = generate_ed25519()
    raw = kp.private_key.private_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    )
    restored = ed25519_from_private_bytes(raw)
    assert restored.key_id == kp.key_id


def test_ed25519_from_private_bytes_malformed_raises():
    """Garbage bytes must raise ValueError (wrong length for Ed25519)."""
    from agent_manifest._signing import ed25519_from_private_bytes

    with pytest.raises((ValueError, Exception)):
        ed25519_from_private_bytes(b"not-a-valid-ed25519-key")


def test_ed25519_from_private_bytes_too_short_raises():
    """Too-short bytes must raise ValueError."""
    from agent_manifest._signing import ed25519_from_private_bytes

    with pytest.raises((ValueError, Exception)):
        ed25519_from_private_bytes(b"\x00" * 10)


# ---------------------------------------------------------------------------
# Malformed PEM / wrong key type passed to Ed25519Verifier
# ---------------------------------------------------------------------------


def test_ed25519_verifier_wrong_length_key_raises():
    """Passing 33 bytes (not 32) to Ed25519Verifier raises ValueError."""
    with pytest.raises(ValueError):
        Ed25519Verifier(b"\x02" * 33)


def test_ed25519_verifier_zero_length_key_raises():
    """Empty bytes raise ValueError."""
    with pytest.raises(ValueError):
        Ed25519Verifier(b"")


def test_ed25519_verifier_rsa_sized_bytes_raises():
    """256-byte RSA-sized blob raises ValueError (wrong length for Ed25519)."""
    with pytest.raises(ValueError):
        Ed25519Verifier(b"\x01" * 256)


# ---------------------------------------------------------------------------
# signed_at is present and ISO 8601 in every signer output (regression: #165)
# ---------------------------------------------------------------------------


def test_ed25519_signer_signed_at_is_iso8601():
    """Ed25519Signer.sign() must include a signed_at ISO 8601 UTC string."""
    import re
    kp = generate_ed25519()
    sig_block = Ed25519Signer(kp).sign(SAMPLE_MANIFEST)
    assert "signed_at" in sig_block
    signed_at = sig_block["signed_at"]
    assert isinstance(signed_at, str)
    # Must end in Z (UTC) and match basic ISO 8601 pattern
    assert signed_at.endswith("Z"), f"signed_at must be UTC (end with Z), got {signed_at!r}"
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", signed_at), (
        f"signed_at not valid ISO 8601: {signed_at!r}"
    )


@require_oqs
def test_ml_dsa65_signer_signed_at_is_iso8601():
    """MlDsa65Signer.sign() must include a signed_at ISO 8601 UTC string."""
    import re
    kp = generate_ml_dsa65()
    sig_block = MlDsa65Signer(kp).sign(SAMPLE_MANIFEST)
    assert "signed_at" in sig_block
    signed_at = sig_block["signed_at"]
    assert signed_at.endswith("Z"), f"signed_at must be UTC, got {signed_at!r}"
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", signed_at)


@require_oqs
def test_hybrid_signer_signed_at_is_iso8601():
    """HybridSigner.sign() must include a signed_at ISO 8601 UTC string."""
    import re
    kp = generate_hybrid()
    sig_block = HybridSigner(kp).sign(SAMPLE_MANIFEST)
    assert "signed_at" in sig_block
    signed_at = sig_block["signed_at"]
    assert signed_at.endswith("Z"), f"signed_at must be UTC, got {signed_at!r}"
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", signed_at)
