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


def _azure_build_attest(
    qualifying_data: bytes,
    pcr_digest: bytes,
    *,
    hash_alg: int = 0x000B,
    bitmap: bytes = b"\x00\x00\x01",
    sizeof_select: int | None = None,
) -> bytes:
    """Minimal structurally-valid TPMS_ATTEST (single PCR-bank selection)."""

    from agent_manifest._tpm_verify import TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE

    out = TPM_GENERATED_VALUE.to_bytes(4, "big")
    out += TPM_ST_ATTEST_QUOTE.to_bytes(2, "big")
    out += (0).to_bytes(2, "big")  # qualifiedSigner: empty TPM2B_NAME
    out += len(qualifying_data).to_bytes(2, "big") + qualifying_data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += (1).to_bytes(4, "big")  # TPML_PCR_SELECTION count
    out += hash_alg.to_bytes(2, "big")
    out += (sizeof_select if sizeof_select is not None else len(bitmap)).to_bytes(1, "big")
    out += bitmap
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
    # a correctly signed SNP report, but the PCR inside the AK-signed quote is wrong.
    # A valid hardware signature must not be enough on its own.
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


def test_azure_report_wrong_pcr_selection_same_digest_bytes():
    # the signed selection bitmap changed from PCR16 (000001) to PCR17 (000002),
    # pcr_digest bytes unchanged, re-signed with the runtime-data-bound AK.
    # A verifier checking only pcr_digest returned signature=verified, report_data_matched=True,
    # passed=True. Must fail now: the bank/PCR the quote was actually signed over must be
    # checked, not just the digest value.
    fx = _azure_good_fixture()
    retargeted_quote_msg = _azure_build_attest(
        bytes(16), fx["pcr_digest"], sizeof_select=3, bitmap=b"\x00\x00\x02"
    )
    retargeted_sig = _azure_tpmt_sign(fx["ak_key"], retargeted_quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(retargeted_quote_msg).decode(),
            "quote_sig": base64.b64encode(retargeted_sig).decode(),
        },
    )
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=fx["vcek_der"],
        cert_chain_pem=fx["chain"],
        azure_expected_pcr_index=16,
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is False
    assert result.passed is False


def test_azure_report_ak_exponent_mismatch():
    # runtime-data JWK exponent changed to e=3 ("Aw") while the PEM
    # AK key keeps e=65537, rebound into a freshly signed SNP report.
    # A verifier comparing only the modulus returned
    # passed=True. Must fail now: both n and e must match.
    import json

    fx = _azure_good_fixture()
    numbers = fx["ak_key"].public_key().public_numbers()
    modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    n_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=").decode()
    wrong_e_b64 = base64.urlsafe_b64encode((3).to_bytes(1, "big")).rstrip(b"=").decode()
    runtime_data_wrong_e = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": n_b64, "e": wrong_e_b64}]}
    ).encode()

    report_data = hashlib.sha256(runtime_data_wrong_e).digest() + bytes(32)
    snp, vcek_der, chain = _synthetic_snp_with_chain(report_data.hex()[:64], MEASUREMENT)
    report = _azure_report_from_fixture(
        fx, raw_overrides={"runtime_data_hex": runtime_data_wrong_e.hex()}
    )
    report.quote = snp
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    assert result.report_data_matched is False
    assert result.passed is False


@pytest.mark.parametrize(
    "corrupt",
    [
        pytest.param(lambda n_b64: "!!!!" + n_b64, id="illegal-prefix"),
        pytest.param(lambda n_b64: n_b64 + "!!!!", id="illegal-suffix"),
        pytest.param(lambda n_b64: n_b64[:-1] + "+", id="standard-base64-plus-alias"),
        pytest.param(lambda n_b64: n_b64[:-1] + "/", id="standard-base64-slash-alias"),
    ],
)
def test_azure_report_malformed_jwk_modulus_encoding_fails_closed(corrupt):
    # base64.urlsafe_b64decode() silently *discards* characters outside the
    # base64 alphabet instead of raising -- so "!!!!<real n>" used to decode
    # to the same bytes as "<real n>". Rebind the corrupted n back into a
    # freshly, validly signed SNP report (report_data = sha256(runtime_data)
    # still matches exactly) and re-sign the AK quote over the same PCR, so
    # every other link in the chain is genuinely valid: only the JWK
    # encoding is malformed. Must fail closed -- a correctly rebound and
    # signed report must never pass with illegally-encoded JWK material.
    import json

    fx = _azure_good_fixture()
    numbers = fx["ak_key"].public_key().public_numbers()
    modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    good_n_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=").decode()
    corrupt_n_b64 = corrupt(good_n_b64)

    corrupt_runtime_data = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": corrupt_n_b64, "e": "AQAB"}]}
    ).encode()
    report_data = hashlib.sha256(corrupt_runtime_data).digest() + bytes(32)
    snp, vcek_der, chain = _synthetic_snp_with_chain(report_data.hex()[:64], MEASUREMENT)
    report = _azure_report_from_fixture(
        fx, raw_overrides={"runtime_data_hex": corrupt_runtime_data.hex()}
    )
    report.quote = snp
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    # The runtime data is still cryptographically committed into REPORT_DATA
    # (report_data_matched would be True under the old permissive decoder),
    # but the AK identity check must now reject the malformed JWK encoding.
    assert result.passed is False


def test_ak_public_numbers_and_modulus_reject_illegal_alphabet_direct():
    # Direct unit coverage: the strict decoder must reject illegal
    # prefixes/suffixes and standard-base64 +/ aliases for both n and e,
    # in both the (n, e) helper and the modulus-only helper.
    import json

    from agent_manifest._azure_verify import (
        ak_modulus_hex_from_runtime_data,
        ak_public_numbers_from_runtime_data,
    )

    good_n = base64.urlsafe_b64encode(b"\x01\x00\x01\xff").rstrip(b"=").decode()

    for bad_n in ("!!!!" + good_n, good_n + "!!!!", good_n[:-1] + "+", good_n[:-1] + "/"):
        runtime_data = json.dumps(
            {"keys": [{"kid": "HCLAkPub", "n": bad_n, "e": "AQAB"}]}
        ).encode()
        assert ak_modulus_hex_from_runtime_data(runtime_data) is None
        assert ak_public_numbers_from_runtime_data(runtime_data) is None

    # A bad exponent must also be rejected, even when n is well-formed.
    for bad_e in ("!!!!AQAB", "AQAB!!!!", "AQA+", "AQA/"):
        runtime_data = json.dumps(
            {"keys": [{"kid": "HCLAkPub", "n": good_n, "e": bad_e}]}
        ).encode()
        assert ak_public_numbers_from_runtime_data(runtime_data) is None

    # Sanity: the well-formed value still decodes fine through both helpers.
    good_runtime_data = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": good_n, "e": "AQAB"}]}
    ).encode()
    assert ak_modulus_hex_from_runtime_data(good_runtime_data) == "010001ff"
    assert ak_public_numbers_from_runtime_data(good_runtime_data) == ("010001ff", 65537)


def test_strict_b64url_decode_rejects_trailing_newline_regex_dollar_hole():
    # Python's `$` regex anchor matches at end-of-string OR just before a
    # single trailing '\n' -- so a naive `^[A-Za-z0-9_-]*$` alphabet check
    # would let "AQAB\n" through even though '\n' isn't in the alphabet,
    # and base64.urlsafe_b64decode then silently drops the '\n' and decodes
    # it identically to "AQAB". Must use fullmatch (no '$'/'\Z' hole) so a
    # trailing newline is rejected like any other illegal character.
    import binascii

    from agent_manifest._azure_verify import _strict_b64url_decode

    assert _strict_b64url_decode("AQAB") == bytes.fromhex("010001")
    with pytest.raises(binascii.Error):
        _strict_b64url_decode("AQAB\n")
    with pytest.raises(binascii.Error):
        _strict_b64url_decode("AQAB\n\n")


def test_azure_report_malformed_runtime_data_keys_shape():
    # valid JSON `{"keys": 1}`, correctly hash-bound into the signed SNP report.
    # The unpatched helper raised  TypeError: 'int' object is not iterable, which
    # leaked out of verify_attestation_chain despite the "never raises" contract. Must
    # fail closed (return False, no exception) now.
    import json

    fx = _azure_good_fixture()
    malformed_runtime_data = json.dumps({"keys": 1}).encode()
    report_data = hashlib.sha256(malformed_runtime_data).digest() + bytes(32)
    snp, vcek_der, chain = _synthetic_snp_with_chain(report_data.hex()[:64], MEASUREMENT)
    report = _azure_report_from_fixture(
        fx, raw_overrides={"runtime_data_hex": malformed_runtime_data.hex()}
    )
    report.quote = snp
    result = verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
    )
    assert result.report_data_matched is False
    assert result.passed is False


def test_verify_azure_manifest_binding_requires_expected_pcr_index_kwarg():
    # expected_pcr_index must be a real, required parameter -- not something
    # a caller can omit and have silently inferred from self-reported data.
    import inspect

    from agent_manifest._azure_verify import verify_azure_manifest_binding

    sig = inspect.signature(verify_azure_manifest_binding)
    assert "expected_pcr_index" in sig.parameters
    assert sig.parameters["expected_pcr_index"].default is inspect.Parameter.empty


def test_ak_public_numbers_from_runtime_data_malformed_keys_shape_returns_none():
    # Direct unit coverage of the fail-closed helper fix: {"keys": 1} used to
    # raise TypeError iterating an int; must now return None like every other
    # malformed-input case.
    import json

    from agent_manifest._azure_verify import (
        ak_modulus_hex_from_runtime_data,
        ak_public_numbers_from_runtime_data,
    )

    malformed = json.dumps({"keys": 1}).encode()
    assert ak_modulus_hex_from_runtime_data(malformed) is None
    assert ak_public_numbers_from_runtime_data(malformed) is None


@pytest.mark.parametrize(
    "runtime_json",
    [
        {"keys": "not-a-list"},
        {"keys": [1, 2, 3]},
        {"keys": None},
        "not-a-dict-at-top-level",
        123,
        [],
    ],
)


def test_ak_public_numbers_from_runtime_data_fails_closed_on_malformed_shapes(runtime_json):
    import json

    from agent_manifest._azure_verify import ak_public_numbers_from_runtime_data

    assert ak_public_numbers_from_runtime_data(json.dumps(runtime_json).encode()) is None


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
    # that a signed report passed for three unrelated expected_manifest_hash
    # values (11.., 22.., ff..).
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=MANIFEST_HASH,
        raw={"report_data": DIGEST + "00" * 32, "measurement": MEASUREMENT},
    )
    result = verify_attestation_chain(report, expected_manifest_hash=arbitrary_hash)
    assert result.passed is False


def test_azure_report_only_pcr_read_string_is_not_evidence():
    #  a report that "looks Azure" (has a plausible-looking legacy
    # pcr_read string, a self-reported runtime_data_binding_verified=True
    # flag) but carries none of the actual quote/signature/AK material must not pass.
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
