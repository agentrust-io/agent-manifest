"""Tests for the boot-time attestation-chain verifier (#204).

Covers the software-checkable steps (manifest-hash binding, measurement
allow-list) and confirms the verifier fails closed while the hardware
signature step is unimplemented.
"""

import hashlib

from agent_manifest._attestation import (
    ChainVerificationResult,
    SignatureStatus,
    verify_attestation_chain,
)
from agent_manifest._providers import AttestationReport

DIGEST = hashlib.sha256(b"manifest-pre-image").hexdigest()
MANIFEST_HASH = f"sha256:{DIGEST}"
MEASUREMENT = "ab" * 48


def _report(*, report_data_hex: str, measurement: str = MEASUREMENT) -> AttestationReport:
    return AttestationReport(
        platform="amd-sev-snp",
        manifest_hash=MANIFEST_HASH,
        raw={"report_data": report_data_hex, "measurement": measurement},
    )


def test_report_data_binding_matches():
    report = _report(report_data_hex=DIGEST + "00" * 32)  # digest || 32 zero bytes
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert isinstance(result, ChainVerificationResult)
    assert result.report_data_matched is True


def test_report_data_binding_mismatch():
    wrong = hashlib.sha256(b"different").hexdigest()
    report = _report(report_data_hex=wrong + "00" * 32)
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.report_data_matched is False
    assert any("manifest hash" in r for r in result.reasons)


def test_missing_report_data_field():
    report = AttestationReport(platform="amd-sev-snp", manifest_hash=MANIFEST_HASH, raw={})
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.report_data_matched is False


def test_measurement_allow_list_hit():
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement=MEASUREMENT)
    result = verify_attestation_chain(
        report, expected_manifest_hash=MANIFEST_HASH, expected_measurements={MEASUREMENT}
    )
    assert result.measurement_matched is True


def test_measurement_allow_list_miss():
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement="cc" * 48)
    result = verify_attestation_chain(
        report, expected_manifest_hash=MANIFEST_HASH, expected_measurements={MEASUREMENT}
    )
    assert result.measurement_matched is False


def test_measurement_not_checked_when_no_allow_list():
    report = _report(report_data_hex=DIGEST + "00" * 32)
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.measurement_matched is None


def test_signature_unimplemented_fails_closed_even_when_software_checks_pass():
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement=MEASUREMENT)
    result = verify_attestation_chain(
        report, expected_manifest_hash=MANIFEST_HASH, expected_measurements={MEASUREMENT}
    )
    # Software checks pass...
    assert result.report_data_matched is True
    assert result.measurement_matched is True
    # ...but the overall verdict is still False because the signature is unverified.
    assert result.signature is SignatureStatus.NOT_IMPLEMENTED
    assert result.passed is False
    assert any("not implemented" in r for r in result.reasons)
