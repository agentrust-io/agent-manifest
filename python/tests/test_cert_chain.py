"""Tests for the generic, algorithm-agnostic certificate-chain verifier and the
lenient TDX-quote parse flag added for downstream consumers (cmcp, ca2a).

The chain verifier must accept whatever signature algorithm each certificate
actually uses — ECDSA (Intel PCK, AMD VCEK leaf), RSASSA-PSS (real AMD ARK/ASK),
and RSA PKCS#1 v1.5 (cmcp's synthetic ARK/ASK) — since the org's three verifier
call sites feed it all of these.
"""
from datetime import datetime, timedelta, timezone

import pytest

crypto = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from agent_manifest import CertChainError, verify_cert_chain  # noqa: E402
from agent_manifest._tdx_verify import TdxVerificationError, parse_tdx_quote  # noqa: E402

_T0 = datetime(2022, 1, 1, tzinfo=timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _sign(builder, issuer_key, *, pss=False):
    if pss and isinstance(issuer_key, rsa.RSAPrivateKey):
        return builder.sign(
            issuer_key,
            hashes.SHA384(),
            rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
        )
    return builder.sign(issuer_key, hashes.SHA384())


def _cert(subject_cn, issuer_cn, subject_pub, issuer_key, *, pss=False):
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_T0)
        .not_valid_after(_T0 + timedelta(days=3650))
    )
    return _sign(b, issuer_key, pss=pss)


def _ec():
    return ec.generate_private_key(ec.SECP384R1())


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_chain():
    """All-ECDSA chain (Intel PCK / ca2a shape): leaf <- inter <- root."""
    rk, ik, lk = _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk)
    inter = _cert("inter", "root", ik.public_key(), rk)
    leaf = _cert("leaf", "inter", lk.public_key(), ik)
    return [leaf, inter, root], root


def _amd_pss_chain():
    """Real-AMD shape: EC VCEK leaf, RSA-PSS ASK/ARK."""
    ark_k, ask_k, vcek_k = _rsa(), _rsa(), _ec()
    ark = _cert("ARK", "ARK", ark_k.public_key(), ark_k, pss=True)
    ask = _cert("ASK", "ARK", ask_k.public_key(), ark_k, pss=True)
    vcek = _cert("VCEK", "ASK", vcek_k.public_key(), ask_k, pss=True)
    return [vcek, ask, ark], ark


def _pkcs1v15_chain():
    """cmcp synthetic shape: EC VCEK leaf, RSA PKCS#1 v1.5 ASK/ARK."""
    ark_k, ask_k, vcek_k = _rsa(), _rsa(), _ec()
    ark = _cert("ARK", "ARK", ark_k.public_key(), ark_k)  # default = PKCS1v15
    ask = _cert("ASK", "ARK", ask_k.public_key(), ark_k)
    vcek = _cert("VCEK", "ASK", vcek_k.public_key(), ask_k)
    return [vcek, ask, ark], ark


@pytest.mark.parametrize("builder", [_ec_chain, _amd_pss_chain, _pkcs1v15_chain])
def test_valid_chain_verifies_for_each_algorithm(builder):
    chain, root = builder()
    assert verify_cert_chain(chain, [root]) is True


def test_root_pin_with_sha384():
    chain, root = _amd_pss_chain()
    assert verify_cert_chain(chain, [root], root_fingerprint_hash=hashes.SHA384()) is True


def test_wrong_root_rejected():
    chain, _root = _pkcs1v15_chain()
    _other_chain, other_root = _pkcs1v15_chain()
    with pytest.raises(CertChainError, match="does not match any trusted root"):
        verify_cert_chain(chain, [other_root])


def test_broken_link_rejected():
    # Graft a leaf from a different chain: its issuer name/sig won't match `inter`.
    chain, root = _ec_chain()
    foreign, _ = _ec_chain()
    tampered = [foreign[0], chain[1], chain[2]]  # foreign leaf, real inter, real root
    with pytest.raises(CertChainError, match="not validly issued"):
        verify_cert_chain(tampered, [root])


def test_empty_chain_rejected():
    _c, root = _ec_chain()
    with pytest.raises(CertChainError, match="empty certificate chain"):
        verify_cert_chain([], [root])


def test_no_trusted_roots_rejected():
    chain, _root = _ec_chain()
    with pytest.raises(CertChainError, match="no trusted roots"):
        verify_cert_chain(chain, [])


def test_two_cert_chain_leaf_and_root():
    # A minimal [leaf, root] chain (self-signed root) also verifies + pins.
    rk, lk = _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk)
    leaf = _cert("leaf", "root", lk.public_key(), rk)
    assert verify_cert_chain([leaf, root], [root]) is True


# --- parse_tdx_quote strict vs lenient -------------------------------------


def _tdx_bytes(version, tee_type):
    import struct
    header = struct.pack("<HHI", version, 2, tee_type)
    header += b"\x00" * (48 - len(header))
    body = b"\x00" * 584
    return header + body


def test_parse_tdx_quote_strict_rejects_nonproduction():
    with pytest.raises(TdxVerificationError):
        parse_tdx_quote(_tdx_bytes(version=1, tee_type=0x00))  # strict=True default


def test_parse_tdx_quote_lenient_parses_nonproduction():
    q = parse_tdx_quote(_tdx_bytes(version=1, tee_type=0x00), strict=False)
    assert q.version == 1
    assert len(q.mrtd) == 48 and len(q.report_data) == 64


def test_parse_tdx_quote_strict_accepts_production_shape():
    q = parse_tdx_quote(_tdx_bytes(version=4, tee_type=0x81))
    assert q.version == 4 and q.tee_type == 0x81
