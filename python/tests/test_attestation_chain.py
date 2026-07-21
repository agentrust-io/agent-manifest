"""Tests for the boot-time attestation-chain verifier (#204).

Covers the software-checkable steps (manifest-hash binding, measurement
allow-list), confirms the verifier fails closed when no VCEK material is
supplied, and confirms the overall verdict passes once the AMD SEV-SNP
signature and VCEK chain verify (synthetic self-consistent crypto).
"""

import hashlib

import pytest

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


def test_no_vcek_material_fails_closed_even_when_software_checks_pass():
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement=MEASUREMENT)
    result = verify_attestation_chain(
        report, expected_manifest_hash=MANIFEST_HASH, expected_measurements={MEASUREMENT}
    )
    # Software checks pass...
    assert result.report_data_matched is True
    assert result.measurement_matched is True
    # ...but the overall verdict is still False because no VCEK was supplied to
    # verify the hardware signature. An unverified report proves nothing.
    assert result.signature is SignatureStatus.NOT_IMPLEMENTED
    assert result.passed is False
    assert any("no VCEK" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Full-pass path: real SNP signature + VCEK chain (synthetic self-consistent).
# A VCEK leaf carrying the report-signing EC key, signed by an RSA ASK<-ARK
# chain, mirrors the AMD KDS hierarchy without any real hardware identifier.
# ---------------------------------------------------------------------------

pytest.importorskip("cryptography")


def _synthetic_snp_with_chain(report_data_digest_hex: str, measurement_hex: str):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    from agent_manifest._snp_verify import (
        _OFF_SIGNATURE,
        _SIG_COMPONENT_BYTES,
        _SIG_COMPONENT_STRIDE,
        _SNP_REPORT_LEN,
    )

    ec_key = ec.generate_private_key(ec.SECP384R1())  # the "VCEK" signing key
    body = bytearray(_OFF_SIGNATURE)
    body[0:4] = (3).to_bytes(4, "little")
    body[0x50:0x50 + 32] = bytes.fromhex(report_data_digest_hex)
    body[0x90:0x90 + 48] = bytes.fromhex(measurement_hex)
    der = ec_key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)
    sig = bytearray(512)
    sig[0:_SIG_COMPONENT_BYTES] = r.to_bytes(_SIG_COMPONENT_BYTES, "little")
    sig[_SIG_COMPONENT_STRIDE:_SIG_COMPONENT_STRIDE + _SIG_COMPONENT_BYTES] = s.to_bytes(
        _SIG_COMPONENT_BYTES, "little"
    )
    snp = bytes(body) + bytes(sig) + bytes(_SNP_REPORT_LEN - _OFF_SIGNATURE - 512)

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ark_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ARK-test")])
    ask_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ASK-test")])

    def cert(subj, pub, issuer_name, issuer_key):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subj)]))
            .issuer_name(issuer_name)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(t0)
            .not_valid_after(t0 + timedelta(days=3650))
            .sign(issuer_key, hashes.SHA384(), rsa_padding=pss)
        )

    ark = cert("ARK-test", ark_key.public_key(), ark_name, ark_key)
    ask = cert("ASK-test", ask_key.public_key(), ark_name, ark_key)
    # VCEK leaf carries the EC report-signing key, signed by the RSA ASK.
    vcek = cert("SEV-VCEK-test", ec_key.public_key(), ask_name, ask_key)
    chain = ask.public_bytes(Encoding.PEM) + ark.public_bytes(Encoding.PEM)
    return snp, vcek.public_bytes(Encoding.DER), chain


def test_full_chain_passes_when_signature_and_binding_verify():
    snp, vcek_der, chain = _synthetic_snp_with_chain(DIGEST, MEASUREMENT)
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement=MEASUREMENT)
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        expected_measurements={MEASUREMENT},
        snp_report_bytes=snp,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.measurement_matched is True
    assert result.passed is True


def test_full_chain_fails_when_report_signature_tampered():
    snp, vcek_der, chain = _synthetic_snp_with_chain(DIGEST, MEASUREMENT)
    tampered = bytearray(snp)
    tampered[0x90] ^= 0x01  # flip a measurement bit inside the signed body
    report = _report(report_data_hex=DIGEST + "00" * 32, measurement=MEASUREMENT)
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        snp_report_bytes=bytes(tampered),
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    assert result.signature is SignatureStatus.FAILED
    assert result.passed is False


def test_tdx_full_chain_passes():
    """A TDX report (self-contained quote) passes when the quote + PCK chain verify."""
    import os
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from test_tdx_verify import _build_quote  # reuse the synthetic quote builder

    quote, root_pem = _build_quote(bytes.fromhex(DIGEST))
    report = AttestationReport(
        platform="intel-tdx",
        manifest_hash=MANIFEST_HASH,
        quote=quote,
        raw={"report_data": DIGEST + "00" * 32, "measurement": "ab" * 48},
    )
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        trusted_tdx_root_pem=root_pem,
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.passed is True


def test_tdx_no_quote_fails_closed():
    report = AttestationReport(
        platform="intel-tdx",
        manifest_hash=MANIFEST_HASH,
        raw={"report_data": DIGEST + "00" * 32},
    )
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.signature is SignatureStatus.NOT_IMPLEMENTED
    assert result.passed is False


def test_full_chain_reads_snp_bytes_from_report_quote():
    snp, vcek_der, chain = _synthetic_snp_with_chain(DIGEST, MEASUREMENT)
    report = AttestationReport(
        platform="amd-sev-snp",
        manifest_hash=MANIFEST_HASH,
        quote=snp,  # provider stows the raw report here
        raw={"report_data": DIGEST + "00" * 32, "measurement": MEASUREMENT},
    )
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.passed is True
