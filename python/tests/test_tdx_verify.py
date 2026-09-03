"""Tests for Intel TDX DCAP quote parsing and verification.

The synthetic tests build a self-consistent TDX v4 quote (P-256 attestation key,
QE report binding, a PCK leaf->intermediate->root chain) and drive all four
verification steps, plus tamper/pinning rejection — no real platform identifiers.

The full four-step verification is also driven against the genuine TDX quotes
captured from a GCP C3 confidential VM and committed under
``tests/fixtures/hardware/gcp-tdx-2026-07-21/``. Those run unconditionally, so a
change that breaks real-quote verification cannot pass CI green on synthetic
vectors alone. Set ``AGENT_MANIFEST_TDX_QUOTE`` to point at a different real
quote to exercise one that is not committed here.
"""
import hashlib
import os
import struct

import pytest
from agent_manifest._tdx_verify import (
    _OFF_MRTD,
    _QUOTE_HEADER_LEN,
    TdxVerificationError,
    parse_tdx_quote,
    parse_tdx_quote_signature,
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


def _build_quote(
    report_data_digest: bytes,
    mrtd: bytes = b"\x11" * 48,
    *,
    version: int = 4,
    att_key_type: int = 2,
    tee_type: int = 0x81,
):
    """Return a self-consistent quote whose signed header is caller-controlled."""
    # Header (48): caller-selected signed profile + 40 bytes padding.
    header = struct.pack("<HHI", version, att_key_type, tee_type) + bytes(40)
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
    quote, _ = _build_quote(hashlib.sha256(b"x").digest(), tee_type=0x00)
    with pytest.raises(TdxVerificationError, match="not a TDX quote"):
        parse_tdx_quote(quote)


def test_parse_rejects_wrong_attestation_key_type():
    quote, _ = _build_quote(hashlib.sha256(b"keytype").digest(), att_key_type=3)
    with pytest.raises(TdxVerificationError, match="attestation key type 3"):
        parse_tdx_quote(quote)


def test_parse_non_strict_is_diagnostic_only():
    quote, _ = _build_quote(
        hashlib.sha256(b"diagnostic").digest(),
        version=5,
        att_key_type=3,
        tee_type=0x00,
    )
    parsed = parse_tdx_quote(quote, strict=False)
    assert parsed.version == 5
    assert parsed.tee_type == 0x00


def test_verify_full_chain_ok():
    quote, root_pem = _build_quote(hashlib.sha256(b"pre").digest())
    assert verify_tdx_quote(quote, trusted_root_pem=root_pem) is True


@pytest.mark.parametrize(
    ("header_overrides", "message"),
    [
        ({"version": 5}, "unsupported TDX quote version 5"),
        ({"att_key_type": 3}, "attestation key type 3"),
        ({"tee_type": 0x00}, "not a TDX quote"),
    ],
)
def test_verify_rejects_self_consistent_signed_unsupported_header(
    header_overrides: dict[str, int], message: str
):
    """The header mutation is included in signed_body and re-signed by the same builder."""
    quote, root_pem = _build_quote(
        hashlib.sha256(b"profile-binding").digest(),
        **header_overrides,
    )
    with pytest.raises(TdxVerificationError, match=message):
        verify_tdx_quote(quote, trusted_root_pem=root_pem)


# ---------------------------------------------------------------------------
# CERT-011: every certificate in the PCK chain must be within its validity
# period. verify_tdx_quote used to check signatures only; a PCK leaf,
# intermediate, or root whose validity window had already expired still
# verified successfully.
# ---------------------------------------------------------------------------


def _build_quote_at(report_data_digest, not_before, not_after, mrtd: bytes = b"\x11" * 48):
    """Like ``_build_quote`` but the PCK chain gets a caller-chosen validity window."""
    def _cert_at(subject, pub, issuer_name, issuer_key, ca=False):
        b = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(issuer_name)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        if ca:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        return b.sign(issuer_key, hashes.SHA256())

    header = struct.pack("<HHI", 4, 2, 0x81) + bytes(40)
    body = bytearray(_BODY)
    body[136:136 + 48] = mrtd
    body[520:520 + 32] = report_data_digest
    signed = header + bytes(body)

    att_key = ec.generate_private_key(ec.SECP256R1())
    att_pub_nums = att_key.public_key().public_numbers()
    att_pub = att_pub_nums.x.to_bytes(32, "big") + att_pub_nums.y.to_bytes(32, "big")
    sig = _raw_sig(att_key, signed)

    qe_auth = b""
    qe_report = bytearray(384)
    qe_report[320:352] = hashlib.sha256(att_pub + qe_auth).digest()

    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SGX Root CA")])
    root = _cert_at("Test SGX Root CA", root_key.public_key(), root_name, root_key, ca=True)
    int_key = ec.generate_private_key(ec.SECP256R1())
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test PCK Platform CA")])
    intermediate = _cert_at("Test PCK Platform CA", int_key.public_key(), root_name, root_key, ca=True)
    pck_key = ec.generate_private_key(ec.SECP256R1())
    pck = _cert_at("Test PCK Cert", pck_key.public_key(), int_name, int_key)
    qe_report_sig = _raw_sig(pck_key, bytes(qe_report))

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


def test_verify_rejects_expired_pck_chain():
    from datetime import datetime, timezone

    quote, root_pem = _build_quote_at(
        hashlib.sha256(b"pre").digest(),
        datetime(2010, 1, 1, tzinfo=timezone.utc),
        datetime(2011, 1, 1, tzinfo=timezone.utc),  # expired a decade+ ago
    )
    with pytest.raises(TdxVerificationError, match="outside its validity period"):
        verify_tdx_quote(quote, trusted_root_pem=root_pem)


def test_verify_accepts_within_pinned_verification_time():
    from datetime import datetime, timezone

    not_before = datetime(2024, 1, 1, tzinfo=timezone.utc)
    not_after = datetime(2025, 1, 1, tzinfo=timezone.utc)
    quote, root_pem = _build_quote_at(hashlib.sha256(b"pre").digest(), not_before, not_after)
    assert verify_tdx_quote(
        quote, trusted_root_pem=root_pem,
        verification_time=datetime(2024, 6, 1, tzinfo=timezone.utc),
    ) is True


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


def test_signature_section_is_nested_under_a_qe_report_header():
    """Lock in the nested type-6 layout a flat parse gets wrong.

    A flat parse reads the QE report at ``auth[128]``, six bytes early, and
    rejects every genuine quote. Assert the de-nested fields line up instead.
    """
    quote, _ = _build_quote(hashlib.sha256(b"nested").digest())
    parsed = parse_tdx_quote_signature(quote)
    auth = quote[48 + 584 + 4:]
    cert_type, _cert_size = struct.unpack_from("<HI", auth, 128)
    assert cert_type == 6  # QE_REPORT_CERTIFICATION_DATA, not the QE report itself
    assert parsed.attestation_key == auth[64:128]
    assert parsed.qe_report == auth[134:134 + 384]  # after the 6-byte header
    assert len(parsed.qe_report) == 384
    assert parsed.pck_chain_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    # the QE report binds the attestation key over the de-nested auth data
    bind = hashlib.sha256(parsed.attestation_key + parsed.qe_auth_data).digest()
    assert parsed.qe_report[320:352] == bind


def test_parse_signature_rejects_wrong_certification_type():
    quote, _ = _build_quote(hashlib.sha256(b"badtype").digest())
    off = 48 + 584 + 4 + 128
    tampered = bytearray(quote)
    tampered[off:off + 2] = (5).to_bytes(2, "little")  # PCK chain where a QE report belongs
    with pytest.raises(TdxVerificationError, match="certification data type"):
        parse_tdx_quote_signature(bytes(tampered))


def test_parse_signature_rejects_overstated_cert_size():
    """A declared length longer than the buffer must fail, not silently shorten.

    Python slicing clamps rather than overreading, so an inflated `cert_size`
    used to yield a short `cert_data` and parsing continued against whatever
    fit. A fail-closed parser rejects the mismatch: verifying 300 bytes where
    the quote declared 400 is verifying something other than what the producer
    said it signed.
    """
    quote, _ = _build_quote(hashlib.sha256(b"certsize").digest())
    off = 48 + 584 + 4 + 130  # cert_size, just after the 2-byte cert_type
    tampered = bytearray(quote)
    tampered[off:off + 4] = (0xFFFF).to_bytes(4, "little")
    with pytest.raises(TdxVerificationError, match="QE certification data"):
        parse_tdx_quote_signature(bytes(tampered))


def test_parse_signature_rejects_overstated_auth_size():
    quote, _ = _build_quote(hashlib.sha256(b"authsize").digest())
    off = 48 + 584  # the uint32 signature-data length
    tampered = bytearray(quote)
    tampered[off:off + 4] = (0xFFFFF).to_bytes(4, "little")
    with pytest.raises(TdxVerificationError, match="signature data"):
        parse_tdx_quote_signature(bytes(tampered))


def test_parse_signature_rejects_overstated_qe_auth_size():
    quote, _ = _build_quote(hashlib.sha256(b"qeauth").digest())
    off = 48 + 584 + 4 + 134 + 384 + 64  # qe_auth_size, inside the cert data
    tampered = bytearray(quote)
    tampered[off:off + 2] = (0xFFFF).to_bytes(2, "little")
    with pytest.raises(TdxVerificationError, match="QE auth data"):
        parse_tdx_quote_signature(bytes(tampered))


# --- Committed real-hardware capture ------------------------------------------
# GCP C3 confidential VM, non-paravisor TDX, captured 2026-07-21 (#305). These
# ran nowhere until now: the only real-quote test was gated on an environment
# variable nothing sets, so the committed capture was inert and CI proved
# verification only against vectors this file mints itself. A synthetic quote
# cannot catch an offset or chain-walk regression that a genuine one would,
# which is the entire reason the capture was committed.

_HARDWARE = os.path.join(
    os.path.dirname(__file__), "fixtures", "hardware", "gcp-tdx-2026-07-21"
)

# Pinned so a swapped or re-captured file fails loudly rather than silently
# changing what "verified on real hardware" refers to.
_CAPTURE_SHA256 = {
    "tdx_quote.bin":
        "f9efbac112efe510aa8ccd20703b063591b8c2c54c474d0ff1d6500299bae0ba",
    "tdx_quote_manifest.bin":
        "1ae04c74b564ef8795d4c4e4ffd1835d080d9dad4f8879e5cd1e8249503828b2",
}

# One TD, so one launch measurement across both captures.
_CAPTURE_MRTD = (
    "9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3"
    "ee5e35e293fc410c061433163acb03a6"
)


def _capture(name):
    with open(os.path.join(_HARDWARE, name), "rb") as fh:
        return fh.read()


@pytest.mark.parametrize("name", sorted(_CAPTURE_SHA256))
def test_committed_capture_is_the_one_the_hardware_produced(name):
    assert hashlib.sha256(_capture(name)).hexdigest() == _CAPTURE_SHA256[name]


@pytest.mark.parametrize("name", sorted(_CAPTURE_SHA256))
def test_real_quote_verifies_against_the_pinned_intel_root(name):
    """The default root is the embedded Intel SGX Root CA, not a test root."""
    assert verify_tdx_quote(_capture(name)) is True


@pytest.mark.parametrize("name", sorted(_CAPTURE_SHA256))
def test_real_quote_carries_its_own_pck_chain(name):
    """Offline verification depends on the chain travelling inside the quote."""
    parsed = parse_tdx_quote_signature(_capture(name))
    assert parsed.pck_chain_pem.count(b"-----BEGIN CERTIFICATE-----") == 3


@pytest.mark.parametrize("name", sorted(_CAPTURE_SHA256))
def test_real_quote_binds_a_32_byte_digest_in_report_data(name):
    """The guest-controlled half carries the digest; the rest stays zero."""
    parsed = parse_tdx_quote(_capture(name))
    assert parsed.report_data[:32] != b"\x00" * 32
    assert parsed.report_data[32:] == b"\x00" * 32


def test_both_captures_share_one_mrtd_but_bind_different_digests():
    """Same TD, two bindings. Guards against a copy of one file under two names."""
    plain = parse_tdx_quote(_capture("tdx_quote.bin"))
    manifest = parse_tdx_quote(_capture("tdx_quote_manifest.bin"))
    assert plain.mrtd.hex() == manifest.mrtd.hex() == _CAPTURE_MRTD
    assert plain.report_data[:32] != manifest.report_data[:32]


def test_a_tampered_real_quote_is_rejected():
    """Flip a byte of MRTD, inside the region the attestation key signs.

    The quote stays well formed, so this is the False branch and not the raising
    one: a broken signature over a parseable quote is a verdict, not a parse
    error. Asserting ``is False`` rather than "falsy" keeps a future early
    return of None from counting as a rejection.
    """
    tampered = bytearray(_capture("tdx_quote.bin"))
    tampered[_QUOTE_HEADER_LEN + _OFF_MRTD] ^= 0xFF
    assert verify_tdx_quote(bytes(tampered)) is False
