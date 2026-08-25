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
    TPM_ST_ATTEST_NV,
    TPM_ST_ATTEST_QUOTE,
    TpmVerificationError,
    parse_nv_certify_info,
    parse_tpm_attest,
    parse_tpm_nv_certify,
    parse_tpm_quote,
    parse_tpmt_signature,
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


def _build_nv_attest(
    qualifying_data: bytes,
    index_name: bytes,
    offset: int,
    nv_contents: bytes,
    qualified_signer: bytes = b"",
) -> bytes:
    """Construct a minimal ``TPMS_ATTEST`` carrying ``TPMS_NV_CERTIFY_INFO``."""
    out = TPM_GENERATED_VALUE.to_bytes(4, "big")
    out += TPM_ST_ATTEST_NV.to_bytes(2, "big")
    out += len(qualified_signer).to_bytes(2, "big") + qualified_signer
    out += len(qualifying_data).to_bytes(2, "big") + qualifying_data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += len(index_name).to_bytes(2, "big") + index_name
    out += offset.to_bytes(2, "big")
    out += len(nv_contents).to_bytes(2, "big") + nv_contents
    return out


def _sign(ak_key, attest):
    if isinstance(ak_key, ec.EllipticCurvePrivateKey):
        return ak_key.sign(attest, ec.ECDSA(hashes.SHA256()))
    return ak_key.sign(attest, padding.PKCS1v15(), hashes.SHA256())


def _tpmt_signature(ak_key, attest, *, sig_alg, hash_alg, digest):
    if isinstance(ak_key, ec.EllipticCurvePrivateKey):
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        signature = ak_key.sign(attest, ec.ECDSA(digest))
        r, s = decode_dss_signature(signature)
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, "big")
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")
        body = len(r_bytes).to_bytes(2, "big") + r_bytes
        body += len(s_bytes).to_bytes(2, "big") + s_bytes
    else:
        scheme = (
            padding.PKCS1v15()
            if sig_alg == 0x0014
            else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
        )
        signature = ak_key.sign(attest, scheme, digest)
        body = len(signature).to_bytes(2, "big") + signature
    return sig_alg.to_bytes(2, "big") + hash_alg.to_bytes(2, "big") + body


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


def test_common_parser_exposes_union_without_assuming_quote():
    qualifying_data = b"freshness"
    index_name = b"\x00\x0b" + b"\x77" * 32
    nv_contents = b"measured-gateway"
    signer = b"\x00\x0b" + b"\x22" * 32
    attest = _build_nv_attest(
        qualifying_data, index_name, 7, nv_contents, qualified_signer=signer
    )

    common = parse_tpm_attest(attest)
    info = parse_nv_certify_info(common.attested_raw)

    assert common.magic == TPM_GENERATED_VALUE
    assert common.attest_type == TPM_ST_ATTEST_NV
    assert common.qualifying_data == qualifying_data
    assert common.qualified_signer == signer
    assert common.clock_info == b"\x00" * 17
    assert common.firmware_version == 0
    assert common.raw == attest
    assert info.index_name == index_name
    assert info.offset == 7
    assert info.nv_contents == nv_contents


def test_common_parser_accepts_tpm2b_attest_framing():
    attest = _build_nv_attest(b"nonce", b"name", 0, b"contents")
    wrapped = len(attest).to_bytes(2, "big") + attest

    common = parse_tpm_attest(wrapped)

    assert common.raw == attest
    assert common.attest_type == TPM_ST_ATTEST_NV


def test_common_parser_rejects_tpm2b_trailing_data():
    attest = _build_nv_attest(b"nonce", b"name", 0, b"contents")
    wrapped = len(attest).to_bytes(2, "big") + attest + b"trailing"

    with pytest.raises(TpmVerificationError, match="no TPM_GENERATED magic"):
        parse_tpm_attest(wrapped)


def test_quote_parser_rejects_nv_certify_union():
    attest = _build_nv_attest(b"nonce", b"name", 0, b"contents")

    with pytest.raises(TpmVerificationError, match="not a quote"):
        parse_tpm_quote(attest)


def test_type_checked_nv_entry_point_rejects_quote():
    with pytest.raises(TpmVerificationError, match="not an NV certify"):
        parse_tpm_nv_certify(_build_attest(NONCE, PCR))


def test_type_checked_nv_entry_point_returns_header_and_info():
    attest = _build_nv_attest(b"nonce", b"name", 65535, b"contents")

    parsed = parse_tpm_nv_certify(attest)

    assert parsed.attest.qualifying_data == b"nonce"
    assert parsed.info.index_name == b"name"
    assert parsed.info.offset == 65535
    assert parsed.info.nv_contents == b"contents"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00\x10short",
        b"\x00\x01n\x00",
        b"\x00\x01n\x00\x00\x00\x08short",
    ],
    ids=["empty", "truncated_name", "truncated_offset", "truncated_contents"],
)
def test_nv_certify_parser_rejects_truncation(payload):
    with pytest.raises(TpmVerificationError, match="truncated"):
        parse_nv_certify_info(payload)


def test_nv_certify_parser_rejects_trailing_bytes():
    attest = _build_nv_attest(b"nonce", b"name", 0, b"contents")
    common = parse_tpm_attest(attest)

    with pytest.raises(TpmVerificationError, match="trailing bytes"):
        parse_nv_certify_info(common.attested_raw + b"extra")


def test_nv_certify_parsers_are_public_api():
    import agent_manifest

    assert agent_manifest.TPM_ST_ATTEST_NV == TPM_ST_ATTEST_NV
    assert agent_manifest.parse_tpm_attest is parse_tpm_attest
    assert agent_manifest.parse_nv_certify_info is parse_nv_certify_info
    assert agent_manifest.parse_tpm_nv_certify is parse_tpm_nv_certify


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


@pytest.mark.parametrize(
    ("kind", "sig_alg"),
    [("rsa", 0x0014), ("rsa", 0x0016), ("ec", 0x0018)],
)
def test_verify_accepts_sha384_tpmt_signature(kind, sig_alg):
    ak_key, chain, roots = _ak_chain(kind)
    attest = _build_attest(NONCE, PCR)
    signature = _tpmt_signature(
        ak_key,
        attest,
        sig_alg=sig_alg,
        hash_alg=0x000C,
        digest=hashes.SHA384(),
    )

    assert verify_tpm_quote(attest, signature, chain, trusted_roots_pem=roots) is True


def test_verify_rejects_tpmt_signature_with_unsupported_hash():
    ak_key, chain, roots = _ak_chain("rsa")
    attest = _build_attest(NONCE, PCR)
    signature = _tpmt_signature(
        ak_key,
        attest,
        sig_alg=0x0014,
        hash_alg=0x0004,
        digest=hashes.SHA1(),
    )

    with pytest.raises(TpmVerificationError, match="unsupported hash algorithm"):
        verify_tpm_quote(attest, signature, chain, trusted_roots_pem=roots)


def test_tpmt_signature_rejects_trailing_bytes():
    ak_key, _chain, _roots = _ak_chain("rsa")
    attest = _build_attest(NONCE, PCR)
    signature = _tpmt_signature(
        ak_key,
        attest,
        sig_alg=0x0014,
        hash_alg=0x000B,
        digest=hashes.SHA256(),
    )

    with pytest.raises(TpmVerificationError, match="trailing bytes"):
        parse_tpmt_signature(signature + b"extra")


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
