"""Tests for AMD SEV-SNP report parsing and signature-chain verification.

Two kinds of fixtures:

* ``vectors/snp/azure_*_redacted.bin`` — a genuine SEV-SNP report captured from
  an Azure confidential VM, with the 64-byte CHIP_ID zeroed (it is a hardware
  identifier). These exercise real-world parsing, offsets, and the Azure
  ``REPORT_DATA == sha256(runtime_data)`` binding. The real signature cannot
  verify once CHIP_ID is redacted, so signature checks use synthetic data.
* Synthetic, self-consistent keys/certs generated in-test — these exercise the
  ECDSA-P384 report-signature path and the RSASSA-PSS VCEK<-ASK<-ARK chain
  round-trip (plus tamper rejection) without publishing any real hardware id.

The full real chain (real report + real VCEK) was validated on live Azure
SEV-SNP silicon; that reproduction lives outside the repo.
"""
import hashlib
import pathlib

import pytest

from agent_manifest._snp_verify import (
    SnpVerificationError,
    parse_hcl_report,
    parse_snp_report,
    verify_runtime_data_binding,
    verify_snp_signature,
    verify_vcek_chain,
    _OFF_SIGNATURE,
    SIG_ALGO_ECDSA_P384_SHA384,
    _SIG_COMPONENT_BYTES,
    _SIG_COMPONENT_STRIDE,
    _SNP_REPORT_LEN,
)

VECTORS = pathlib.Path(__file__).parent / "vectors" / "snp"
HCL = VECTORS / "azure_hcl_report_redacted.bin"
SNP = VECTORS / "azure_snp_report_redacted.bin"

pytestmark = pytest.mark.skipif(
    not HCL.exists(), reason="SNP vectors not present"
)

# cryptography is a hard dependency for the verification path; skip the
# synthetic crypto tests cleanly if it is somehow absent.
crypto = pytest.importorskip("cryptography")


# ---------------------------------------------------------------------------
# Real (redacted) report: parsing, offsets, Azure binding
# ---------------------------------------------------------------------------


def test_parse_hcl_and_snp_report():
    snp_raw, runtime = parse_hcl_report(HCL.read_bytes())
    assert len(snp_raw) == _SNP_REPORT_LEN
    rep = parse_snp_report(snp_raw)
    assert rep.version == 3
    assert rep.policy == 0x3001F
    assert len(rep.report_data) == 64
    assert len(rep.measurement) == 48
    assert rep.tcb_spls == {"bl": 4, "tee": 0, "snp": 24, "ucode": 219}
    assert rep.chip_id == bytes(64)  # redacted in the committed vector


def test_azure_report_data_binds_runtime_data():
    """The captured REPORT_DATA is sha256 of the runtime-data blob (Azure)."""
    snp_raw, runtime = parse_hcl_report(HCL.read_bytes())
    rep = parse_snp_report(snp_raw)
    assert verify_runtime_data_binding(rep, runtime) is True
    # sanity: it is genuinely the sha256 relationship, not a trivial pass
    assert rep.report_data[:32] == hashlib.sha256(runtime).digest()


def test_binding_rejects_tampered_runtime_data():
    snp_raw, runtime = parse_hcl_report(HCL.read_bytes())
    rep = parse_snp_report(snp_raw)
    assert verify_runtime_data_binding(rep, runtime + b"x") is False


def test_standalone_snp_vector_matches_embedded():
    assert SNP.read_bytes() == parse_hcl_report(HCL.read_bytes())[0]


def test_parse_hcl_rejects_bad_magic():
    with pytest.raises(SnpVerificationError, match="not an HCL report"):
        parse_hcl_report(b"XXXX" + bytes(3000))


def test_parse_snp_rejects_short_report():
    with pytest.raises(SnpVerificationError, match="too short"):
        parse_snp_report(bytes(100))


# ---------------------------------------------------------------------------
# Synthetic ECDSA-P384 report-signature round-trip
# ---------------------------------------------------------------------------


def _self_signed_ec_cert(key):
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SEV-VCEK-test")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2020, 1, 1, tzinfo=timezone.utc) + timedelta(days=3650))
        .sign(key, hashes.SHA384())
    )


def _synthetic_signed_report():
    """Build a report whose 0x2a0 signature is a real P-384 sig over its body."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.serialization import Encoding

    key = ec.generate_private_key(ec.SECP384R1())
    body = bytearray(_OFF_SIGNATURE)
    body[0:4] = (3).to_bytes(4, "little")  # version
    # sig_algo must be set, as real silicon does: the genuine capture in
    # vectors/snp/azure_snp_report_redacted.bin carries 1 here. Leaving it zero
    # made the fixture describe a report no AMD processor emits, and
    # verify_snp_signature now checks the declared scheme before verifying.
    body[0x34:0x38] = SIG_ALGO_ECDSA_P384_SHA384.to_bytes(4, "little")
    body[0x50:0x50 + 32] = hashlib.sha256(b"runtime").digest()  # report_data
    der = key.sign(bytes(body), ec.ECDSA(hashes.SHA384()))
    r, s = utils.decode_dss_signature(der)
    sig = bytearray(512)
    sig[0:_SIG_COMPONENT_BYTES] = r.to_bytes(_SIG_COMPONENT_BYTES, "little")
    sig[_SIG_COMPONENT_STRIDE:_SIG_COMPONENT_STRIDE + _SIG_COMPONENT_BYTES] = s.to_bytes(
        _SIG_COMPONENT_BYTES, "little"
    )
    report = bytes(body) + bytes(sig) + bytes(_SNP_REPORT_LEN - _OFF_SIGNATURE - 512)
    vcek_der = _self_signed_ec_cert(key).public_bytes(Encoding.DER)
    return report, vcek_der


def test_verify_snp_signature_accepts_valid():
    report, vcek_der = _synthetic_signed_report()
    assert verify_snp_signature(parse_snp_report(report), vcek_der) is True


def test_verify_snp_signature_rejects_tampered_body():
    report, vcek_der = _synthetic_signed_report()
    tampered = bytearray(report)
    tampered[0x50] ^= 0x01  # flip a bit in the signed body
    assert verify_snp_signature(parse_snp_report(bytes(tampered)), vcek_der) is False


def test_verify_snp_signature_rejects_wrong_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding

    report, _ = _synthetic_signed_report()
    other = _self_signed_ec_cert(ec.generate_private_key(ec.SECP384R1()))
    assert verify_snp_signature(parse_snp_report(report), other.public_bytes(Encoding.DER)) is False


# ---------------------------------------------------------------------------
# Synthetic RSASSA-PSS VCEK <- ASK <- ARK chain round-trip
# ---------------------------------------------------------------------------


def _rsa_pss_chain():
    """Build (vcek_der, chain_pem) mirroring the AMD KDS PSS-signed hierarchy."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)

    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

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

    ark_key, ask_key, vcek_key = key(), key(), key()
    ark_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ARK-test")])
    ask_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ASK-test")])
    ark = cert("ARK-test", ark_key.public_key(), ark_name, ark_key)
    ask = cert("ASK-test", ask_key.public_key(), ark_name, ark_key)
    vcek = cert("SEV-VCEK-test", vcek_key.public_key(), ask_name, ask_key)
    chain = ask.public_bytes(Encoding.PEM) + ark.public_bytes(Encoding.PEM)
    return vcek.public_bytes(Encoding.DER), chain, ark.public_bytes(Encoding.DER)


def test_verify_vcek_chain_accepts_valid():
    vcek_der, chain_pem, _ = _rsa_pss_chain()
    assert verify_vcek_chain(vcek_der, chain_pem) is True


def test_verify_vcek_chain_pins_ark():
    vcek_der, chain_pem, ark_der = _rsa_pss_chain()
    assert verify_vcek_chain(vcek_der, chain_pem, trusted_ark_der=ark_der) is True


def test_verify_vcek_chain_rejects_wrong_pinned_ark():
    vcek_der, chain_pem, _ = _rsa_pss_chain()
    _, _, other_ark = _rsa_pss_chain()
    with pytest.raises(SnpVerificationError, match="pinned AMD root"):
        verify_vcek_chain(vcek_der, chain_pem, trusted_ark_der=other_ark)


def test_verify_vcek_chain_rejects_foreign_vcek():
    _, chain_pem, _ = _rsa_pss_chain()
    foreign_vcek, _, _ = _rsa_pss_chain()  # signed by a different ASK
    with pytest.raises(SnpVerificationError, match="VCEK<-ASK"):
        verify_vcek_chain(foreign_vcek, chain_pem)


def test_verify_vcek_chain_requires_two_certs():
    vcek_der, chain_pem, _ = _rsa_pss_chain()
    one = chain_pem.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    with pytest.raises(SnpVerificationError, match="ASK and ARK"):
        verify_vcek_chain(vcek_der, one)


# ---------------------------------------------------------------------------
# Declared signature algorithm and cert-bundle loading (union, agent-manifest 0.9)
# ---------------------------------------------------------------------------


def test_parse_exposes_the_fields_the_downstream_copies_carried():
    """guest_svn, vmpl and signature_algo came from cmcp's and ca2a's copies;
    without them a consumer cannot enforce checks those copies enforced."""
    rep = parse_snp_report(SNP.read_bytes())

    assert rep.signature_algo == SIG_ALGO_ECDSA_P384_SHA384  # real silicon sets 1
    assert rep.vmpl == 0
    assert isinstance(rep.guest_svn, int)


def test_verify_rejects_a_report_declaring_another_algorithm():
    """Verifying with ECDSA-P384/SHA-384 without checking the report says so
    would appraise a differently-signed report under the wrong scheme."""
    report, vcek_der = _synthetic_signed_report()
    other = bytearray(report)
    other[0x34:0x38] = (2).to_bytes(4, "little")

    with pytest.raises(SnpVerificationError, match="unsupported SNP signature algorithm"):
        verify_snp_signature(parse_snp_report(bytes(other)), vcek_der)


def _snp_shaped_bundle() -> bytes:
    """A PEM bundle shaped like a real SNP chain: EC VCEK leaf, RSA ASK and ARK.

    ``_rsa_pss_chain`` makes an RSA leaf, which is not what AMD issues; the VCEK
    is EC P-384 and that is precisely what tells it apart in a bundle.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)

    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def cert(subj, pub, issuer_name, issuer_key):
        return (
            x509.CertificateBuilder()
            .subject_name(name(subj))
            .issuer_name(issuer_name)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(t0)
            .not_valid_after(t0 + timedelta(days=3650))
            .sign(issuer_key, hashes.SHA384(), rsa_padding=pss)
        )

    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ask_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark = cert("ARK-test", ark_key.public_key(), name("ARK-test"), ark_key)
    ask = cert("ASK-test", ask_key.public_key(), name("ARK-test"), ark_key)
    vcek = cert("SEV-VCEK-test", vcek_key.public_key(), name("ASK-test"), ask_key)
    # Deliberately not leaf-first: order varies by source and must not matter.
    return (
        ask.public_bytes(Encoding.PEM)
        + vcek.public_bytes(Encoding.PEM)
        + ark.public_bytes(Encoding.PEM)
    )


def test_load_snp_cert_chain_sorts_by_shape_not_order():
    """The bundle order varies by source, so VCEK/ASK/ARK are told apart by key
    type and self-signedness rather than position."""
    from agent_manifest import load_snp_cert_chain

    vcek, ask, ark = load_snp_cert_chain(_snp_shaped_bundle())

    assert "VCEK" in vcek.subject.rfc4514_string()
    assert ark.subject == ark.issuer  # the self-signed one is the root
    assert ask.subject != ask.issuer


def test_load_snp_cert_chain_rejects_the_kds_cert_chain_endpoint_output():
    """AMD KDS's `cert_chain` endpoint returns ASK + ARK with no VCEK. Passing it
    whole is a real, recorded deployment mistake, so it must fail loudly rather
    than proceed with two of the three."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from agent_manifest import load_snp_cert_chain

    certs = x509.load_pem_x509_certificates(_snp_shaped_bundle())
    ask_and_ark = b"".join(
        c.public_bytes(Encoding.PEM) for c in certs if "VCEK" not in c.subject.rfc4514_string()
    )

    with pytest.raises(SnpVerificationError, match="must contain a VCEK"):
        load_snp_cert_chain(ask_and_ark)


def test_load_snp_cert_chain_rejects_unparseable_input():
    from agent_manifest import load_snp_cert_chain

    with pytest.raises(SnpVerificationError, match="could not parse"):
        load_snp_cert_chain(b"-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----\n")
