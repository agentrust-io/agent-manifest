"""Build a synthetic-but-self-consistent SEV-SNP report + VCEK/ASK/ARK chain.

Extracted from ``test_attestation_chain.py`` (issue #204 test suite) so that
tests exercising PLATFORM_INFO appraisal (offset 0x40) can reuse the exact
same synthetic hardware chain instead of re-deriving the certificate
boilerplate. No real hardware identifier or AMD key material is involved:
this mirrors the AMD KDS hierarchy shape (VCEK <- ASK <- ARK) with freshly
generated keys, purely so ``verify_attestation_chain()`` has a cryptographically
valid signature and chain to check.
"""
from __future__ import annotations

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


def build_synthetic_snp_report_with_chain(
    report_data_digest_hex: str,
    measurement_hex: str,
    *,
    platform_info: int = 0,
) -> tuple[bytes, bytes, bytes]:
    """Return ``(raw_snp_report, vcek_cert_der, cert_chain_pem)``.

    ``platform_info`` is written to the PLATFORM_INFO field (offset 0x40,
    inside the signed body) so callers can appraise it with
    :func:`agent_manifest.parse_platform_info` /
    :func:`agent_manifest.appraise_platform_info` against a report whose
    hardware signature and chain cryptographically verify. Defaults to ``0`` (no
    bits set), matching every existing caller of this builder before
    PLATFORM_INFO appraisal existed.
    """
    ec_key = ec.generate_private_key(ec.SECP384R1())  # the "VCEK" signing key
    body = bytearray(_OFF_SIGNATURE)
    body[0:4] = (3).to_bytes(4, "little")
    body[0x34:0x38] = (1).to_bytes(4, "little")  # sig_algo, as real silicon sets
    body[0x40:0x48] = platform_info.to_bytes(8, "little")
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
