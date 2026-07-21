"""Intel TDX DCAP quote parsing and signature-chain verification.

This is the TDX analogue of :mod:`._snp_verify`. It implements the hardware
signature backend the reviewer of #201 found missing for TDX (#204/#228): the
old provider returned a raw ``TDREPORT`` (not remotely verifiable) and nothing
ever checked a quote signature or the Intel PCK certificate chain.

Every offset and verification step here was validated against a genuine Intel
TDX v4 ECDSA quote captured from a GCP C3 confidential VM (non-paravisor TDX,
kernel 6.17, configfs-TSM ``tdx_guest`` provider); see ``tests/test_tdx_verify``.

A TDX v4 quote (Intel DCAP) is verified in four steps, all fail-closed:

1. the quote's per-attestation-key ECDSA-P256 signature covers the quote header
   plus the TD report body;
2. the Quoting Enclave (QE) report binds that attestation key
   (``report_data[:32] == sha256(att_pub || qe_auth_data)``);
3. the QE report is itself signed by the platform's PCK certificate; and
4. the embedded PCK certificate chain verifies up to the **Intel SGX Root CA**,
   which is pinned (embedded below; the chain's self-signed root must match it).

The manifest hash a guest binds lands in the TD report's ``REPORTDATA``
(guest-controlled on non-paravisor TDX). Only the ``cryptography`` package is
required; the PCK chain travels inside the quote, so verification is offline.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Any, Optional

# Intel SGX Provisioning Certification Root CA (public, long-lived). The PCK
# chain embedded in every quote must chain to this. Pinning it here makes quote
# verification fully offline and independent of what the quote itself carries.
INTEL_SGX_ROOT_CA_PEM = b"""-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----
"""

_QUOTE_HEADER_LEN = 48
_TD_REPORT_LEN = 584  # TDX v4 TD report body
# Field offsets within the TD report body.
_OFF_MRTD = 136
_OFF_RTMR0 = 328
_OFF_REPORTDATA = 520
# Quote header: version(2) att_key_type(2) tee_type(4) ...
_TDX_QUOTE_VERSION = 4
_ATT_KEY_TYPE_ECDSA_P256 = 2
_TEE_TYPE_TDX = 0x81
# QE (SGX) report: report_data is the trailing 64 bytes of the 384-byte report.
_SGX_REPORT_LEN = 384
_OFF_QE_REPORT_DATA = 320
# Certification-data types (Intel DCAP).
_CERT_TYPE_QE_REPORT = 6
_CERT_TYPE_PCK_CHAIN = 5


class TdxVerificationError(Exception):
    """Raised when a TDX quote or its certificate chain fails verification."""


@dataclass
class TdxQuote:
    """Parsed fields of an Intel TDX v4 DCAP quote."""

    version: int
    tee_type: int
    mrtd: bytes  # 48 bytes
    rtmrs: tuple[bytes, bytes, bytes, bytes]  # each 48 bytes
    report_data: bytes  # 64 bytes (guest-supplied; first 32 carry the manifest digest)
    raw: bytes  # the full quote


def parse_tdx_quote(quote: bytes, *, strict: bool = True) -> TdxQuote:
    """Parse an Intel TDX v4 DCAP quote's header + TD report body.

    Args:
        quote: the raw DCAP quote bytes.
        strict: when ``True`` (default), enforce the production layout —
            ``version == 4`` and ``tee_type == 0x81`` — raising on anything
            else. Pass ``strict=False`` to parse the header/body of an
            otherwise well-formed quote whose version/tee_type differ (e.g.
            synthetic test vectors), extracting the fields without asserting the
            production TDX identity. Signature verification
            (:func:`verify_tdx_quote`) is unaffected and always strict.
    """
    if len(quote) < _QUOTE_HEADER_LEN + _TD_REPORT_LEN:
        raise TdxVerificationError(
            f"quote too short: {len(quote)} bytes, need "
            f"{_QUOTE_HEADER_LEN + _TD_REPORT_LEN}"
        )
    version, att_key_type, tee_type = struct.unpack_from("<HHI", quote, 0)
    if strict:
        if version != _TDX_QUOTE_VERSION:
            raise TdxVerificationError(f"unsupported TDX quote version {version} (expected 4)")
        if tee_type != _TEE_TYPE_TDX:
            raise TdxVerificationError(f"not a TDX quote: tee_type {tee_type:#x}")
    body = quote[_QUOTE_HEADER_LEN:_QUOTE_HEADER_LEN + _TD_REPORT_LEN]
    rtmrs = tuple(body[_OFF_RTMR0 + i * 48:_OFF_RTMR0 + i * 48 + 48] for i in range(4))
    return TdxQuote(
        version=version,
        tee_type=tee_type,
        mrtd=body[_OFF_MRTD:_OFF_MRTD + 48],
        rtmrs=rtmrs,  # type: ignore[arg-type]
        report_data=body[_OFF_REPORTDATA:_OFF_REPORTDATA + 64],
        raw=quote,
    )


def _p256(xy: bytes) -> Any:
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + xy)


def _verify_raw_ecdsa(pub: Any, raw_sig: bytes, msg: bytes) -> None:
    """Verify a raw r||s (64-byte) ECDSA-P256/SHA-256 signature; raises on failure."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:64], "big")
    pub.verify(utils.encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))


def verify_tdx_quote(quote: bytes, *, trusted_root_pem: Optional[bytes] = None) -> bool:
    """Fully verify an Intel TDX v4 DCAP quote (all four steps, fail-closed).

    Returns True only when the attestation-key signature, the QE binding, the
    PCK signature over the QE report, and the PCK chain up to the pinned Intel
    SGX Root CA all check out. Raises :class:`TdxVerificationError` on a
    malformed quote / broken chain or if ``cryptography`` is unavailable; returns
    False on a well-formed-but-invalid signature.

    ``trusted_root_pem`` overrides the embedded Intel root (for testing).
    """
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as e:  # pragma: no cover
        raise TdxVerificationError(
            "TDX quote verification requires the 'cryptography' package"
        ) from e

    if len(quote) < _QUOTE_HEADER_LEN + _TD_REPORT_LEN + 4:
        raise TdxVerificationError("quote too short to contain a signature")

    signed = quote[:_QUOTE_HEADER_LEN + _TD_REPORT_LEN]
    off = _QUOTE_HEADER_LEN + _TD_REPORT_LEN
    (auth_size,) = struct.unpack_from("<I", quote, off)
    off += 4
    auth = quote[off:off + auth_size]
    if len(auth) < 134:
        raise TdxVerificationError("truncated quote signature data")

    sig = auth[0:64]
    att_pub = auth[64:128]
    cert_type, cert_size = struct.unpack_from("<HI", auth, 128)
    if cert_type != _CERT_TYPE_QE_REPORT:
        raise TdxVerificationError(
            f"unexpected certification data type {cert_type} (expected QE report)"
        )
    cert_data = auth[134:134 + cert_size]
    if len(cert_data) < 448 + 6:
        raise TdxVerificationError("truncated QE certification data")

    # Step 1: attestation key signs the quote header + TD report body.
    try:
        _verify_raw_ecdsa(_p256(att_pub), sig, signed)
    except InvalidSignature:
        return False

    # QE report certification data: qe_report[384], qe_report_sig[64],
    # qe_auth(size u16 + data), then the PCK cert chain (type 5).
    qe_report = cert_data[0:_SGX_REPORT_LEN]
    qe_report_sig = cert_data[_SGX_REPORT_LEN:_SGX_REPORT_LEN + 64]
    o2 = _SGX_REPORT_LEN + 64
    (qe_auth_size,) = struct.unpack_from("<H", cert_data, o2)
    o2 += 2
    qe_auth = cert_data[o2:o2 + qe_auth_size]
    o2 += qe_auth_size
    pck_cert_type, pck_size = struct.unpack_from("<HI", cert_data, o2)
    o2 += 6
    if pck_cert_type != _CERT_TYPE_PCK_CHAIN:
        raise TdxVerificationError(
            f"unexpected PCK certification type {pck_cert_type} (expected PEM chain)"
        )
    pem = cert_data[o2:o2 + pck_size]

    # Step 2: the QE report binds the attestation key.
    expected_bind = hashlib.sha256(att_pub + qe_auth).digest()
    if not hmac.compare_digest(qe_report[_OFF_QE_REPORT_DATA:_OFF_QE_REPORT_DATA + 32], expected_bind):
        return False

    # Parse the PCK chain (leaf first).
    certs = x509.load_pem_x509_certificates(pem)
    if len(certs) < 2:
        raise TdxVerificationError("PCK chain must contain at least a leaf and the root")
    pck = certs[0]

    # Step 3: the PCK certificate signs the QE report.
    pck_pub = pck.public_key()
    if not isinstance(pck_pub, ec.EllipticCurvePublicKey):
        raise TdxVerificationError("PCK certificate is not an EC key")
    try:
        _verify_raw_ecdsa(pck_pub, qe_report_sig, qe_report)
    except InvalidSignature:
        return False

    # Step 4: chain the PCK cert up to the pinned Intel SGX Root CA.
    root = x509.load_pem_x509_certificate(trusted_root_pem or INTEL_SGX_ROOT_CA_PEM)
    for i in range(len(certs) - 1):
        issuer_pub = certs[i + 1].public_key()
        if not isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            raise TdxVerificationError("PCK chain issuer is not an EC key")
        halg = certs[i].signature_hash_algorithm
        if halg is None:
            raise TdxVerificationError(f"PCK chain link {i} has no signature hash algorithm")
        try:
            issuer_pub.verify(
                certs[i].signature,
                certs[i].tbs_certificate_bytes,
                ec.ECDSA(halg),
            )
        except InvalidSignature as e:
            raise TdxVerificationError(f"PCK chain link {i} signature invalid") from e
    chain_root = certs[-1]
    if chain_root.fingerprint(hashes.SHA256()) != root.fingerprint(hashes.SHA256()):
        raise TdxVerificationError("PCK chain root does not match the pinned Intel SGX Root CA")
    return True
