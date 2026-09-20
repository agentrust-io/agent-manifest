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
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm  # noqa: E402
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


def _cert(
    subject_cn,
    issuer_cn,
    subject_pub,
    issuer_key,
    *,
    pss=False,
    ca=False,
    key_cert_sign=None,
    path_length=None,
    not_before=_T0,
    not_after=_T0 + timedelta(days=3650),
):
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
    )
    if key_cert_sign is not None:
        b = b.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    return _sign(b, issuer_key, pss=pss)


def _ec():
    return ec.generate_private_key(ec.SECP384R1())


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ec_chain():
    """All-ECDSA chain (Intel PCK / ca2a shape): leaf <- inter <- root."""
    rk, ik, lk = _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    inter = _cert("inter", "root", ik.public_key(), rk, ca=True)
    leaf = _cert("leaf", "inter", lk.public_key(), ik)
    return [leaf, inter, root], root


def _amd_pss_chain():
    """Real-AMD shape: EC VCEK leaf, RSA-PSS ASK/ARK."""
    ark_k, ask_k, vcek_k = _rsa(), _rsa(), _ec()
    ark = _cert("ARK", "ARK", ark_k.public_key(), ark_k, pss=True, ca=True)
    ask = _cert("ASK", "ARK", ask_k.public_key(), ark_k, pss=True, ca=True)
    vcek = _cert("VCEK", "ASK", vcek_k.public_key(), ask_k, pss=True)
    return [vcek, ask, ark], ark


def _pkcs1v15_chain():
    """cmcp synthetic shape: EC VCEK leaf, RSA PKCS#1 v1.5 ASK/ARK."""
    ark_k, ask_k, vcek_k = _rsa(), _rsa(), _ec()
    ark = _cert("ARK", "ARK", ark_k.public_key(), ark_k, ca=True)  # default = PKCS1v15
    ask = _cert("ASK", "ARK", ask_k.public_key(), ark_k, ca=True)
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
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    leaf = _cert("leaf", "root", lk.public_key(), rk)
    assert verify_cert_chain([leaf, root], [root]) is True


def test_expired_leaf_rejected():
    rk, lk = _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    leaf = _cert(
        "leaf",
        "root",
        lk.public_key(),
        rk,
        not_before=_T0,
        not_after=_T0 + timedelta(days=1),
    )
    with pytest.raises(CertChainError, match="outside its validity period"):
        verify_cert_chain([leaf, root], [root])


def test_leaf_valid_exactly_at_not_after_boundary():
    """RFC 5280 4.1.2.5: the validity period is notBefore through notAfter,
    *inclusive*. A certificate checked at the exact notAfter second must
    still verify."""
    rk, lk = _ec(), _ec()
    not_after = _T0 + timedelta(days=1)
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    leaf = _cert(
        "leaf", "root", lk.public_key(), rk, not_before=_T0, not_after=not_after
    )
    assert verify_cert_chain([leaf, root], [root], verification_time=not_after) is True


def test_leaf_rejected_one_second_past_not_after_boundary():
    """The second *after* notAfter is correctly outside the validity period."""
    rk, lk = _ec(), _ec()
    not_after = _T0 + timedelta(days=1)
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    leaf = _cert(
        "leaf", "root", lk.public_key(), rk, not_before=_T0, not_after=not_after
    )
    with pytest.raises(CertChainError, match="outside its validity period"):
        verify_cert_chain(
            [leaf, root], [root], verification_time=not_after + timedelta(seconds=1)
        )


def test_leaf_valid_exactly_at_not_before_boundary():
    """The lower bound was already inclusive; confirm it stays that way."""
    rk, lk = _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    leaf = _cert(
        "leaf", "root", lk.public_key(), rk, not_before=_T0, not_after=_T0 + timedelta(days=1)
    )
    assert verify_cert_chain([leaf, root], [root], verification_time=_T0) is True


def test_non_ca_issuer_rejected():
    rk, ik, lk = _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    inter = _cert("inter", "root", ik.public_key(), rk, ca=False)
    leaf = _cert("leaf", "inter", lk.public_key(), ik)
    with pytest.raises(CertChainError, match="is not a CA"):
        verify_cert_chain([leaf, inter, root], [root])


def test_naive_verification_time_rejected():
    chain, root = _ec_chain()
    with pytest.raises(CertChainError, match="timezone-aware"):
        verify_cert_chain(chain, [root], verification_time=datetime(2026, 1, 1))


def test_issuer_key_usage_must_allow_certificate_signing():
    rk, lk = _ec(), _ec()
    root = _cert(
        "root", "root", rk.public_key(), rk, ca=True, key_cert_sign=False
    )
    leaf = _cert("leaf", "root", lk.public_key(), rk)
    with pytest.raises(CertChainError, match="cannot sign certificates"):
        verify_cert_chain([leaf, root], [root])


def test_malformed_issuer_extension_raises_cert_chain_error_not_value_error():
    """Extensions parse lazily: a chain can load and then fail on access.
    That must be a CertChainError, not a bare ValueError.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    (leaf, inter, root), _ = _ec_chain()
    der = bytearray(inter.public_bytes(Encoding.DER))
    marker = bytes.fromhex("30030101ff")  # BasicConstraints value: CA=TRUE, no pathLen
    at = bytes(der).find(marker)
    assert at != -1
    der[at + 2] = 0x05  # BOOLEAN tag -> NULL tag
    broken = x509.load_der_x509_certificate(bytes(der))
    with pytest.raises(CertChainError, match="malformed extensions"):
        verify_cert_chain([leaf, broken, root], [root])


def test_issuer_with_unsupported_public_key_curve_raises_cert_chain_error():
    """An issuer whose key the library cannot use is a rejection.

    The library raises different exceptions for this depending on the release, so
    assert the CertChainError contract, not which exception it picks.
    """
    from cryptography.hazmat.primitives.serialization import Encoding

    (leaf, inter, root), _ = _ec_chain()  # P-384 keys
    der = bytearray(inter.public_bytes(Encoding.DER))
    curve_oid = bytes.fromhex("06052b81040022")  # secp384r1
    at = bytes(der).find(curve_oid)
    assert at != -1
    der[at + len(curve_oid) - 1] = 0x7F  # 1.3.132.0.127: well-formed OID, no such curve
    broken = x509.load_der_x509_certificate(bytes(der))  # still loads

    with pytest.raises(CertChainError, match="not validly issued by the next"):
        verify_cert_chain([leaf, broken, root], [root])


class _FailingIssuedByCheck:
    """A real certificate whose ``verify_directly_issued_by`` raises ``exc``."""

    def __init__(self, cert, exc):
        self._cert = cert
        self._exc = exc

    def __getattr__(self, name):
        return getattr(self._cert, name)

    def verify_directly_issued_by(self, issuer):
        raise self._exc


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("issuer name does not match subject"),
        TypeError("unsupported issuer public key type"),
        InvalidSignature(),
        UnsupportedAlgorithm("Curve 1.2.840.10045.3.1.9 is not supported"),
    ],
    ids=["ValueError", "TypeError", "InvalidSignature", "UnsupportedAlgorithm"],
)
def test_every_issued_by_failure_the_library_can_raise_becomes_cert_chain_error(exc):
    """Independent of which cryptography release is installed."""
    (leaf, inter, root), _ = _ec_chain()
    with pytest.raises(CertChainError, match="not validly issued by the next"):
        verify_cert_chain([_FailingIssuedByCheck(leaf, exc), inter, root], [root])


# --- pathLenConstraint (RFC 5280 4.2.1.9) -----------------------------------


def test_path_length_zero_forbids_a_ca_below_it():
    """root --(path_length=0)--> mid_ca --(ca=True)--> leaf is invalid.

    ``path_length=0`` on ``root`` means no CA certificate may follow it on
    the way to the leaf. ``mid_ca`` is a CA certificate that does exactly
    that, so the chain must be rejected even though every signature and
    every individual BasicConstraints/KeyUsage check on its own passes.
    """
    rk, mk, lk = _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True, path_length=0)
    mid_ca = _cert("mid", "root", mk.public_key(), rk, ca=True)
    leaf = _cert("leaf", "mid", lk.public_key(), mk)
    with pytest.raises(CertChainError, match="path_length"):
        verify_cert_chain([leaf, mid_ca, root], [root])


def test_path_length_zero_allows_a_direct_leaf():
    """root --(path_length=0)--> leaf is fine: zero CAs follow root."""
    rk, lk = _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True, path_length=0)
    leaf = _cert("leaf", "root", lk.public_key(), rk)
    assert verify_cert_chain([leaf, root], [root]) is True


def test_path_length_one_allows_exactly_one_ca_below():
    rk, mk, lk = _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True, path_length=1)
    mid_ca = _cert("mid", "root", mk.public_key(), rk, ca=True)
    leaf = _cert("leaf", "mid", lk.public_key(), mk)
    assert verify_cert_chain([leaf, mid_ca, root], [root]) is True


def test_path_length_violation_is_caught_at_any_position_not_just_root():
    """The constraint is enforced on whichever issuer declares it - not
    hard-coded to the root position. root -> ca_A(path_length=0) -> ca_B
    (a CA) -> leaf: ca_A is not the root and not the leaf's direct issuer,
    and its path_length=0 is still violated by ca_B."""
    rk, ak, bk, lk = _ec(), _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    ca_a = _cert("ca_a", "root", ak.public_key(), rk, ca=True, path_length=0)
    ca_b = _cert("ca_b", "ca_a", bk.public_key(), ak, ca=True)
    leaf = _cert("leaf", "ca_b", lk.public_key(), bk)
    with pytest.raises(CertChainError, match="path_length"):
        verify_cert_chain([leaf, ca_b, ca_a, root], [root])


def test_unconstrained_deep_chain_still_verifies():
    """Same shape as above but every CA is unconstrained: must still pass,
    confirming the new check has no false positives on a chain deeper than
    the existing 3-certificate fixtures exercise."""
    rk, ak, bk, lk = _ec(), _ec(), _ec(), _ec()
    root = _cert("root", "root", rk.public_key(), rk, ca=True)
    ca_a = _cert("ca_a", "root", ak.public_key(), rk, ca=True)
    ca_b = _cert("ca_b", "ca_a", bk.public_key(), ak, ca=True)
    leaf = _cert("leaf", "ca_b", lk.public_key(), bk)
    assert verify_cert_chain([leaf, ca_b, ca_a, root], [root]) is True


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
