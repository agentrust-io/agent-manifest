"""Tests for attestation providers — issue #5.

Hardware-dependent tests (actual TPM extension, quote) are skipped in CI
unless TPM2TOOLS_TCTI is set. Unit tests cover pre-image computation,
hash derivation, and report verification without hardware.
"""
import hashlib
import os

import pytest

from agent_manifest._providers import (
    AttestationReport,
    AttestationUnavailableError,
    TPMProvider,
    _TPM_DEFAULT_PCR,
)

NEEDS_TPM = pytest.mark.skipif(
    not os.environ.get("TPM2TOOLS_TCTI"),
    reason="Set TPM2TOOLS_TCTI to run hardware TPM tests",
)

# Minimal manifest dict for testing pre-image computation
SAMPLE_MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod-001",
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "expires_at": "2026-09-21T09:00:00Z",
    "issuer": "spiffe://trust.example/signing-authority",
    "crypto_profile": "standard",
    "artifacts": {},
    "delegation_chain": [],
    "hitl_record": None,
    "signature": {"algorithm": "Ed25519", "signature_value": "abc123"},
    # This field MUST be excluded from the pre-image
    "attestation": {"platform": "tpm", "measurement": "should_not_appear"},
}


# ---------------------------------------------------------------------------
# Pre-image computation
# ---------------------------------------------------------------------------


def test_pre_image_excludes_attestation():
    provider = TPMProvider()
    pre = provider.manifest_pre_image(SAMPLE_MANIFEST)
    assert b"should_not_appear" not in pre
    assert b"attestation" not in pre


def test_pre_image_includes_signature():
    """signature block IS included in the pre-image (unlike signing_pre_image)."""
    provider = TPMProvider()
    pre = provider.manifest_pre_image(SAMPLE_MANIFEST)
    assert b"signature" in pre


def test_pre_image_is_rfc8785():
    """Pre-image must be reproducible from identical input."""
    p = TPMProvider()
    assert p.manifest_pre_image(SAMPLE_MANIFEST) == p.manifest_pre_image(SAMPLE_MANIFEST)


def test_manifest_hash_value_format():
    provider = TPMProvider()
    h = provider.manifest_hash_value(SAMPLE_MANIFEST)
    assert h.startswith("sha256:")
    assert len(h) == 7 + 64


def test_manifest_hash_value_matches_sha256_of_pre_image():
    provider = TPMProvider()
    pre = provider.manifest_pre_image(SAMPLE_MANIFEST)
    expected = f"sha256:{hashlib.sha256(pre).hexdigest()}"
    assert provider.manifest_hash_value(SAMPLE_MANIFEST) == expected


def test_manifest_change_changes_hash():
    provider = TPMProvider()
    modified = {**SAMPLE_MANIFEST, "agent_id": "spiffe://evil/agent"}
    assert provider.manifest_hash_value(SAMPLE_MANIFEST) != provider.manifest_hash_value(modified)


def test_attestation_block_change_does_not_change_hash():
    """attestation is excluded — changing it must not change the hash."""
    provider = TPMProvider()
    modified = {**SAMPLE_MANIFEST, "attestation": {"platform": "different"}}
    assert provider.manifest_hash_value(SAMPLE_MANIFEST) == provider.manifest_hash_value(modified)


# ---------------------------------------------------------------------------
# PCR index selection
# ---------------------------------------------------------------------------


def test_default_pcr_is_15():
    provider = TPMProvider()
    # On non-Nitro systems, default PCR is 15
    if not os.path.exists("/dev/nsm"):
        assert provider.pcr_index == _TPM_DEFAULT_PCR


def test_custom_pcr_index():
    provider = TPMProvider(pcr_index=7)
    assert provider.pcr_index == 7


def test_platform_label_tpm():
    provider = TPMProvider()
    if not os.path.exists("/dev/nsm"):
        assert provider.platform_label == "tpm"


# ---------------------------------------------------------------------------
# Report verification (no hardware needed)
# ---------------------------------------------------------------------------


def test_verify_manifest_in_report_matching():
    provider = TPMProvider()
    expected_hash = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(
        platform="tpm",
        manifest_hash=expected_hash,
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_verify_manifest_in_report_mismatch():
    provider = TPMProvider()
    report = AttestationReport(
        platform="tpm",
        manifest_hash="sha256:" + "00" * 32,
    )
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_verify_manifest_tampered_manifest():
    provider = TPMProvider()
    good_hash = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="tpm", manifest_hash=good_hash)
    tampered = {**SAMPLE_MANIFEST, "version": "9.9"}
    assert not provider.verify_manifest_in_report(report, tampered)


#---------------------------------------------------------------------------
# SEC-TRANS-01: constant-time manifest_hash comparison
# ---------------------------------------------------------------------------


def test_verify_manifest_in_report_uses_constant_time_compare(monkeypatch):
    """verify_manifest_in_report must go through hmac.compare_digest."""
    import hmac as real_hmac
    from unittest.mock import patch

    provider = TPMProvider()
    expected_hash = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="tpm", manifest_hash=expected_hash)

    with patch(
        "agent_manifest._providers.hmac.compare_digest",
        wraps=real_hmac.compare_digest,
    ) as mock_compare:
        assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)

    mock_compare.assert_called_once_with(expected_hash, expected_hash)


def test_verify_manifest_in_report_same_length_wrong_hash_rejected():
    """Same-length-but-wrong digest must still fail after the compare_digest switch."""
    provider = TPMProvider()
    expected_hash = provider.manifest_hash_value(SAMPLE_MANIFEST)
    flipped = expected_hash[:-1] + ("0" if expected_hash[-1] != "0" else "1")
    report = AttestationReport(platform="tpm", manifest_hash=flipped)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_verify_manifest_in_report_non_string_hash_fails_closed_not_typeerror():
    """A non-string manifest_hash must return False, not raise TypeError."""
    provider = TPMProvider()
    report = AttestationReport(platform="tpm", manifest_hash="tpm")
    report.manifest_hash = None  # type: ignore[assignment]
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_verify_manifest_in_report_non_ascii_hash_fails_closed_not_typeerror():
    """A non-ASCII manifest_hash must also return False, not raise TypeError."""
    provider = TPMProvider()
    report = AttestationReport(platform="tpm", manifest_hash="é" * 64)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_unavailable_error_on_missing_tpm2_tools(monkeypatch):
    """If tpm2_extend is not in PATH, must raise AttestationUnavailableError."""
    monkeypatch.setenv("PATH", "")
    provider = TPMProvider()
    with pytest.raises(AttestationUnavailableError, match="tpm2-tools not found"):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)


# ---------------------------------------------------------------------------
# Hardware TPM tests (require TPM2TOOLS_TCTI in environment)
# ---------------------------------------------------------------------------


@NEEDS_TPM
def test_extend_and_read_pcr():
    provider = TPMProvider()
    provider.extend_manifest_hash(SAMPLE_MANIFEST)
    report = provider.get_attestation_report()
    assert f"PCR{provider.pcr_index}" in report.pcr_values
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)
