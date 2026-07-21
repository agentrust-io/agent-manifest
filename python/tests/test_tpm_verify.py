"""Tests for the shared TPM 2.0 quote verifier (`agent_manifest._tpm_verify`).

Synthetic, self-consistent crypto: a generated attestation key (EC or RSA), a
mock AK certificate chain to a test root, and a hand-built ``TPMS_ATTEST`` blob
signed by the AK. Covers the happy path plus tamper / pinning / wrong-key /
binding-mismatch rejection. (The parse + signature/chain logic is exercised
here; validation against a real TPM quote is tracked as follow-up.)
"""
import datetime

import pytest

crypto = pytest.importorskip("cryptography")

from agent_manifest._tpm_verify import (  # noqa: E402
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TpmVerificationError,
    parse_tpm_quote,
    verify_tpm_quote,
)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

_T0 = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, subject_pub, issuer, issuer_key, halg=hashes.SHA256()):
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_T0)
        .not_valid_after(_T0 + datetime.timedelta(days=3650))
        .sign(issuer_key, halg)
    )


def _ak_chain(kind="ec"):
    """Return (ak_private_key, ak_chain_pem, trusted_roots_pem) — root directly signs AK."""
    if kind == "ec":
        root_key = ec.generate_private_key(ec.SECP256R1())
        ak_key = ec.generate_private_key(ec.SECP256R1())
    else:
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert("test-tpm-root", root_key.public_key(), "test-tpm-root", root_key)
    ak = _cert("test-ak", ak_key.public_key(), "test-tpm-root", root_key)
    chain_pem = ak.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)
    return ak_key, chain_pem, root.public_bytes(Encoding.PEM)


def _build_attest(
    nonce: bytes,
    pcr_digest: bytes,
    magic: int = TPM_GENERATED_VALUE,
    attest_type: int = TPM_ST_ATTEST_QUOTE,
) -> bytes:
    """Construct a minimal but structurally-valid TPMS_ATTEST quote blob."""
    out = magic.to_bytes(4, "big")
    out += attest_type.to_bytes(2, "big")
    out += (0).to_bytes(2, "big")  # qualifiedSigner: empty TPM2B_NAME
    out += len(nonce).to_bytes(2, "big") + nonce  # extraData / qualifying data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += (1).to_bytes(4, "big")  # TPML_PCR_SELECTION count
    out += (0x000B).to_bytes(2, "big")  # hashAlg = sha256
    out += (3).to_bytes(1, "big")  # sizeofSelect
    out += b"\x00\x00\x01"  # pcrSelect bitmap
    out += len(pcr_digest).to_bytes(2, "big") + pcr_digest
    return out


def _sign(ak_key, attest):
    if isinstance(ak_key, ec.EllipticCurvePrivateKey):
        return ak_key.sign(attest, ec.ECDSA(hashes.SHA256()))
    return ak_key.sign(attest, padding.PKCS1v15(), hashes.SHA256())


NONCE = bytes(range(32))
PCR = bytes(range(32, 64))


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_extracts_fields():
    q = parse_tpm_quote(_build_attest(NONCE, PCR))
    assert q.magic == TPM_GENERATED_VALUE
    assert q.attest_type == TPM_ST_ATTEST_QUOTE
    assert q.qualifying_data == NONCE
    assert q.pcr_digest == PCR


def test_parse_rejects_truncated():
    with pytest.raises(TpmVerificationError):
        parse_tpm_quote(b"\xff")


# ---------------------------------------------------------------------------
# Full verification round-trip (EC and RSA AKs)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_verify_accepts_valid(kind):
    ak_key, chain, roots = _ak_chain(kind)
    attest = _build_attest(NONCE, PCR)
    sig = _sign(ak_key, attest)
    assert verify_tpm_quote(
        attest, sig, chain,
        trusted_roots_pem=roots,
        expected_qualifying_data=NONCE,
        expected_pcr_digest=PCR,
    ) is True


def test_verify_rejects_tampered_attest():
    ak_key, chain, roots = _ak_chain()
    attest = bytearray(_build_attest(NONCE, PCR))
    sig = _sign(ak_key, bytes(attest))
    attest[-1] ^= 0x01  # flip a PCR-digest bit after signing
    assert verify_tpm_quote(bytes(attest), sig, chain, trusted_roots_pem=roots) is False


def test_verify_rejects_wrong_ak_key():
    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR)
    other = ec.generate_private_key(ec.SECP256R1())
    sig = _sign(other, attest)  # signed by a key that is not the AK
    assert verify_tpm_quote(attest, sig, chain, trusted_roots_pem=roots) is False


def test_verify_rejects_untrusted_root():
    ak_key, chain, _roots = _ak_chain()
    _, _, other_roots = _ak_chain()  # a different, unrelated root
    attest = _build_attest(NONCE, PCR)
    sig = _sign(ak_key, attest)
    with pytest.raises(TpmVerificationError, match="trusted TPM roots"):
        verify_tpm_quote(attest, sig, chain, trusted_roots_pem=other_roots)


def test_verify_rejects_qualifying_data_mismatch():
    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR)
    sig = _sign(ak_key, attest)
    assert verify_tpm_quote(
        attest, sig, chain, trusted_roots_pem=roots,
        expected_qualifying_data=b"\x00" * 32,
    ) is False


def test_verify_rejects_pcr_mismatch():
    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR)
    sig = _sign(ak_key, attest)
    assert verify_tpm_quote(
        attest, sig, chain, trusted_roots_pem=roots,
        expected_pcr_digest=b"\x11" * 32,
    ) is False


def test_verify_raises_on_wrong_magic():
    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR, magic=0x00000000)
    sig = _sign(ak_key, attest)
    with pytest.raises(TpmVerificationError, match="TPM_GENERATED"):
        verify_tpm_quote(attest, sig, chain, trusted_roots_pem=roots)


def test_verify_raises_on_non_quote_type():
    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR, attest_type=0x8017)
    sig = _sign(ak_key, attest)
    with pytest.raises(TpmVerificationError, match="not a quote"):
        verify_tpm_quote(attest, sig, chain, trusted_roots_pem=roots)


# ---------------------------------------------------------------------------
# verify_attestation_chain dispatch (platform == "tpm")
# ---------------------------------------------------------------------------


def test_attestation_chain_dispatches_tpm():
    from agent_manifest import (
        AttestationReport,
        SignatureStatus,
        verify_attestation_chain,
    )

    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(NONCE, PCR)
    sig = _sign(ak_key, attest)
    # A TPM report binds the manifest via a PCR/qualifying-data, not report_data;
    # here we only assert the signature step reaches VERIFIED via the TPM path.
    report = AttestationReport(platform="tpm", manifest_hash="sha256:" + "00" * 32)
    result = verify_attestation_chain(
        report,
        expected_manifest_hash="sha256:" + "00" * 32,
        tpm_attest=attest,
        tpm_signature=sig,
        tpm_ak_chain_pem=chain,
        tpm_trusted_roots_pem=roots,
        expected_qualifying_data=NONCE,
    )
    assert result.signature is SignatureStatus.VERIFIED
