"""Tests for Intel TDX DCAP quote parsing and verification.

The synthetic tests build a self-consistent TDX v4 quote (P-256 attestation key,
QE report binding, a PCK leaf->intermediate->root chain) and drive all four
verification steps, plus tamper/pinning rejection — no real platform identifiers.

The full four-step verification was validated on a genuine TDX quote captured
from a GCP C3 confidential VM; that reproduction is kept out of the repo (the
PCK certificate identifies the CPU). Set ``AGENT_MANIFEST_TDX_QUOTE`` to a real
quote file to exercise it against the pinned Intel root.
"""
import hashlib
import os
import struct

import pytest

from agent_manifest._tdx_verify import (
    TdxVerificationError,
    parse_tdx_quote,
    verify_tdx_quote,
)

crypto = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

_HDR = 48
_BODY = 584


def _raw_sig(key, msg: bytes) -> bytes:
    der = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _cert(subject, pub, issuer_name, issuer_key, ca=False):
    from datetime import datetime, timedelta, timezone

    t0 = datetime(2020, 1, 1, tzinfo=timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer_name)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(t0)
        .not_valid_after(t0 + timedelta(days=3650))
    )
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def _build_quote(report_data_digest: bytes, mrtd: bytes = b"\x11" * 48):
    """Return (quote_bytes, test_root_pem) — a self-consistent TDX v4 quote."""
    # Header (48): version=4, att_key_type=2, tee_type=0x81, + 40 bytes padding.
    header = struct.pack("<HHI", 4, 2, 0x81) + bytes(40)
    body = bytearray(_BODY)
    body[136:136 + 48] = mrtd
    body[520:520 + 32] = report_data_digest  # REPORTDATA[:32]
    signed = header + bytes(body)

    att_key = ec.generate_private_key(ec.SECP256R1())
    att_pub_nums = att_key.public_key().public_numbers()
    att_pub = att_pub_nums.x.to_bytes(32, "big") + att_pub_nums.y.to_bytes(32, "big")
    sig = _raw_sig(att_key, signed)  # step 1

    # QE report (384): report_data[320:352] = sha256(att_pub || qe_auth); qe_auth empty.
    qe_auth = b""
    qe_report = bytearray(384)
    qe_report[320:352] = hashlib.sha256(att_pub + qe_auth).digest()

    # PCK chain: leaf (signs QE report) <- intermediate <- root (self-signed test root).
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SGX Root CA")])
    root = _cert("Test SGX Root CA", root_key.public_key(), root_name, root_key, ca=True)
    int_key = ec.generate_private_key(ec.SECP256R1())
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test PCK Platform CA")])
    intermediate = _cert("Test PCK Platform CA", int_key.public_key(), root_name, root_key, ca=True)
    pck_key = ec.generate_private_key(ec.SECP256R1())
    pck = _cert("Test PCK Cert", pck_key.public_key(), int_name, int_key)
    qe_report_sig = _raw_sig(pck_key, bytes(qe_report))  # step 3

    pem = pck.public_bytes(Encoding.PEM) + intermediate.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)

    cert_data = (
        bytes(qe_report)
        + qe_report_sig
        + struct.pack("<H", len(qe_auth)) + qe_auth
        + struct.pack("<HI", 5, len(pem)) + pem
    )
    auth = sig + att_pub + struct.pack("<HI", 6, len(cert_data)) + cert_data
    quote = signed + struct.pack("<I", len(auth)) + auth
    return quote, root.public_bytes(Encoding.PEM)


def test_parse_quote_fields():
    digest = hashlib.sha256(b"pre-image").digest()
    quote, _ = _build_quote(digest, mrtd=b"\xab" * 48)
    q = parse_tdx_quote(quote)
    assert q.version == 4
    assert q.tee_type == 0x81
    assert q.mrtd == b"\xab" * 48
    assert q.report_data[:32] == digest
    assert len(q.rtmrs) == 4


def test_parse_rejects_short():
    with pytest.raises(TdxVerificationError, match="too short"):
        parse_tdx_quote(bytes(100))


def test_parse_rejects_wrong_tee_type():
    quote, _ = _build_quote(hashlib.sha256(b"x").digest())
    bad = bytearray(quote)
    struct.pack_into("<I", bad, 4, 0x00)  # tee_type = SGX, not TDX
    with pytest.raises(TdxVerificationError, match="not a TDX quote"):
        parse_tdx_quote(bytes(bad))


def test_verify_full_chain_ok():
    quote, root_pem = _build_quote(hashlib.sha256(b"pre").digest())
    assert verify_tdx_quote(quote, trusted_root_pem=root_pem) is True


def test_verify_rejects_tampered_body():
    quote, root_pem = _build_quote(hashlib.sha256(b"pre").digest())
    bad = bytearray(quote)
    bad[520] ^= 0x01  # flip a REPORTDATA bit in the signed body
    assert verify_tdx_quote(bytes(bad), trusted_root_pem=root_pem) is False


def test_verify_rejects_wrong_pinned_root():
    quote, _ = _build_quote(hashlib.sha256(b"pre").digest())
    _, other_root = _build_quote(hashlib.sha256(b"other").digest())
    with pytest.raises(TdxVerificationError, match="pinned Intel SGX Root CA"):
        verify_tdx_quote(quote, trusted_root_pem=other_root)


def test_verify_default_root_is_intel():
    # A synthetic quote must NOT verify against the embedded real Intel root.
    quote, _ = _build_quote(hashlib.sha256(b"pre").digest())
    with pytest.raises(TdxVerificationError, match="pinned Intel SGX Root CA"):
        verify_tdx_quote(quote)  # no trusted_root_pem -> embedded Intel root


@pytest.mark.skipif(
    not os.environ.get("AGENT_MANIFEST_TDX_QUOTE"),
    reason="set AGENT_MANIFEST_TDX_QUOTE to a real quote file to verify against the Intel root",
)
def test_real_tdx_quote_against_intel_root():
    quote = open(os.environ["AGENT_MANIFEST_TDX_QUOTE"], "rb").read()
    assert verify_tdx_quote(quote) is True
