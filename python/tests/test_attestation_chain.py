"""Tests for the boot-time attestation-chain verifier (#204).

Covers the software-checkable steps (manifest-hash binding, measurement
allow-list), confirms the verifier fails closed when no VCEK material is
supplied, and confirms the overall verdict passes once the AMD SEV-SNP
signature and VCEK chain verify (synthetic self-consistent crypto).
"""

import base64
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
    body[0x34:0x38] = (1).to_bytes(4, "little")  # sig_algo, as real silicon sets
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


# ---------------------------------------------------------------------------
# Azure paravisor SNP + unsupported-platform dispatch.
#
# REPORT_DATA on Azure is sha256(runtime_data), never the manifest hash (the
# guest does not control it). verify_attestation_chain establishes Azure's
# real manifest binding itself (a vTPM AK-signed quote over a PCR derived
# from the manifest hash, chained to REPORT_DATA via the runtime data -- see
# agent_manifest._azure_verify.verify_azure_manifest_binding) directly from
# evidence carried on the report. There is no caller-supplied boolean
# anywhere in this API that can substitute for that check -- see #373: an
# earlier revision accepted an `azure_manifest_binding_verified` flag from
# the caller, which let anyone construct a report with no real evidence at
# all and still get passed=True by asserting the flag. Platform dispatch
# must also be an explicit allow-list, not a catch-all, so an unrecognized
# platform label can't silently borrow the SNP verifier.
# ---------------------------------------------------------------------------


def _azure_build_attest(qualifying_data: bytes, pcr_digest: bytes) -> bytes:
    """Minimal structurally-valid TPMS_ATTEST (single sha256 PCR selected)."""
    from agent_manifest._tpm_verify import TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE

    out = TPM_GENERATED_VALUE.to_bytes(4, "big")
    out += TPM_ST_ATTEST_QUOTE.to_bytes(2, "big")
    out += (0).to_bytes(2, "big")  # qualifiedSigner: empty TPM2B_NAME
    out += len(qualifying_data).to_bytes(2, "big") + qualifying_data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += (1).to_bytes(4, "big")  # TPML_PCR_SELECTION count
    out += (0x000B).to_bytes(2, "big")  # hashAlg = sha256
    out += (3).to_bytes(1, "big")  # sizeofSelect
    out += b"\x00\x00\x01"  # pcrSelect bitmap
    out += len(pcr_digest).to_bytes(2, "big") + pcr_digest
    return out


def _azure_tpmt_sign(ak_key, attest: bytes) -> bytes:
    """RSASSA/SHA-256 TPMT_SIGNATURE over ``attest``."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    sig = ak_key.sign(attest, padding.PKCS1v15(), hashes.SHA256())
    return (0x0014).to_bytes(2, "big") + (0x000B).to_bytes(2, "big") + len(sig).to_bytes(2, "big") + sig


def _azure_good_fixture(*, manifest_digest_hex: str = DIGEST):
    """Build a fully self-consistent, cryptographically-valid Azure evidence set.

    Every field is genuinely tied together: the AK signs a quote over the
    manifest PCR, the AK is embedded in runtime_data, and runtime_data is
    bound (via REPORT_DATA) into the SNP report -- exactly the composite
    chain verify_attestation_chain must authenticate for an Azure report to
    pass. Mirrors the fixture in test_hw_providers.py (same crypto, reused
    here because verify_attestation_chain must establish this chain itself
    -- it is the object under test, not AzureCVMProvider).
    """
    import base64
    import json

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    expected_pcr_value = hashlib.sha256(bytes(32) + bytes.fromhex(manifest_digest_hex)).digest()
    pcr_digest = hashlib.sha256(expected_pcr_value).digest()

    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_pub_pem = ak_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()

    quote_msg = _azure_build_attest(bytes(16), pcr_digest)
    quote_sig = _azure_tpmt_sign(ak_key, quote_msg)

    numbers = ak_key.public_key().public_numbers()
    modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    n_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=").decode()
    runtime_data = json.dumps({"keys": [{"kid": "HCLAkPub", "n": n_b64, "e": "AQAB"}]}).encode()

    report_data = hashlib.sha256(runtime_data).digest() + bytes(32)
    snp, vcek_der, chain = _synthetic_snp_with_chain(report_data.hex()[:64], MEASUREMENT)

    return {
        "snp": snp,
        "vcek_der": vcek_der,
        "chain": chain,
        "raw": {
            "ak_pub_pem": ak_pub_pem,
            "runtime_data_hex": runtime_data.hex(),
            "quote_msg": base64.b64encode(quote_msg).decode(),
            "quote_sig": base64.b64encode(quote_sig).decode(),
            "measurement": MEASUREMENT,
        },
        "ak_key": ak_key,
        "pcr_digest": pcr_digest,
    }


def _azure_report_from_fixture(fx, *, raw_overrides=None):
    raw = dict(fx["raw"])
    if raw_overrides:
        raw.update(raw_overrides)
    return AttestationReport(
         platform="azure-cvm-sev-snp",
         manifest_hash=MANIFEST_HASH,
        quote=fx["snp"],
        raw=raw,
    )


def test_azure_report_full_composite_chain_passes():
    # The positive path: verify_attestation_chain establishes the entire
    # Azure binding itself (PCR-in-quote, AK signature, AK identity,
    # runtime_data->REPORT_DATA) purely from evidence on the report, plus
    # the SNP signature/VCEK chain -- and only then can passed be True.
    fx = _azure_good_fixture()
    report = _azure_report_from_fixture(fx)
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=fx["vcek_der"],
        cert_chain_pem=fx["chain"],
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.passed is True


def test_azure_report_with_valid_snp_signature_and_wrong_pcr_does_not_pass():
    # The maintainer's exact reproduction shape: a correctly signed SNP
    # report, but the PCR inside the AK-signed quote is wrong. A valid
    # hardware signature must not be enough on its own.
    fx = _azure_good_fixture()
    wrong_pcr_digest = hashlib.sha256(bytes(32) + b"\x00" * 32).digest()
    tampered_quote_msg = _azure_build_attest(bytes(16), wrong_pcr_digest)
    tampered_sig = _azure_tpmt_sign(fx["ak_key"], tampered_quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(tampered_quote_msg).decode(),
            "quote_sig": base64.b64encode(tampered_sig).decode(),
        },
    )
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=fx["vcek_der"],
        cert_chain_pem=fx["chain"],
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is False
    assert result.passed is False


def test_azure_report_with_no_evidence_supplied_fails_closed():
    # Nothing supplied at all (the common/default case): must not be quietly
    # assumed fine.
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=MANIFEST_HASH,
        raw={"report_data": DIGEST + "00" * 32, "measurement": MEASUREMENT},
    )

    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.report_data_matched is False
    assert result.passed is False
    assert any("not established" in r for r in result.reasons)


@pytest.mark.parametrize("arbitrary_hash", ["sha256:" + "11" * 32, "sha256:" + "22" * 32, "sha256:" + "ff" * 32])
def test_azure_report_fails_closed_for_any_expected_manifest_hash(arbitrary_hash):
    # The platform label and expected_manifest_hash alone must never combine
    # into a pass, regardless of which hash is expected -- reproduces the
    # reviewer's exact finding that a signed report passed for three
    # unrelated expected_manifest_hash values (11.., 22.., ff..).
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=MANIFEST_HASH,
        raw={"report_data": DIGEST + "00" * 32, "measurement": MEASUREMENT},
    )
    result = verify_attestation_chain(report, expected_manifest_hash=arbitrary_hash)
    assert result.passed is False


def test_azure_report_only_pcr_read_string_is_not_evidence():
    # The exact gap the reviewer flagged: a report that "looks Azure" (has a
    # plausible-looking legacy pcr_read string, a self-reported
    # runtime_data_binding_verified=True flag) but carries none of the
    # actual quote/signature/AK material must not pass.
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=MANIFEST_HASH,
        raw={
            "report_data": DIGEST + "00" * 32,
            "measurement": MEASUREMENT,
            "pcr_read": f"  16: 0x{'aa' * 32}",
            "runtime_data_binding_verified": True,
            "vcek_cert_chain_verified": True,
        },
    )
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.report_data_matched is False
    assert result.passed is False


def test_verify_attestation_chain_no_longer_accepts_a_binding_boolean():
    # the parameter itself must be gone, not merely ignored, so no
    # caller (old or new) can be under the impression that supplying it does
    # anything.
    import inspect

    sig = inspect.signature(verify_attestation_chain)
    assert "azure_manifest_binding_verified" not in sig.parameters


@pytest.mark.parametrize("unsupported_platform", ["opaque", "", "quantum-tee-v9"])
def test_unsupported_platform_label_does_not_borrow_the_snp_verifier(unsupported_platform):
    # #363 regression matrix: same exact SNP evidence, only the platform
    # label changes to an unrecognized/empty/future value. Dispatch must not
    # fall through to SNP verification for any of them.
    report = _report(report_data_hex=DIGEST + "00" * 32)
    report.platform = unsupported_platform
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.signature is SignatureStatus.NOT_IMPLEMENTED
    assert result.passed is False
    assert any("not a supported attestation profile" in r for r in result.reasons)


def test_non_azure_snp_still_requires_report_data_to_match():
    # Confirms the fix is scoped to azure-cvm-sev-snp: direct-silicon SNP
    # (amd-sev-snp) must still bind REPORT_DATA to the manifest hash directly.
    wrong = hashlib.sha256(b"different").hexdigest()
    report = _report(report_data_hex=wrong + "00" * 32)
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.report_data_matched is False
    assert result.passed is False
