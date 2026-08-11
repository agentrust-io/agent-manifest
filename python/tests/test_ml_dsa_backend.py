"""ML-DSA-65 backend selection and key-material handling.

The SDK takes ML-DSA-65 from cryptography (>= 47) where it is available and
from the liboqs bindings otherwise. These tests cover the seam: which backend
a given key belongs to, what a build without either one reports, and the
PKCS#8 wrapper that lets a seed be loaded at all.
"""
from types import SimpleNamespace

import pytest

from agent_manifest import _signing
from agent_manifest._signing import (
    AlgorithmUnavailableError,
    MlDsa65Signer,
    MlDsa65Verifier,
    generate_ml_dsa65,
    ml_dsa65_available,
)

require_pq = pytest.mark.skipif(
    not ml_dsa65_available(), reason="no ML-DSA-65 backend available"
)
require_cryptography_mldsa = pytest.mark.skipif(
    not _signing._CRYPTOGRAPHY_MLDSA_AVAILABLE, reason="cryptography < 47"
)

MESSAGE = b"agent manifest ml-dsa backend test"


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


@require_cryptography_mldsa
def test_ml_dsa_seed_wrapper_matches_cryptography():
    """The hardcoded PKCS#8 prefix must stay what cryptography itself emits.

    _signing wraps a raw seed in this prefix to load it, because cryptography
    exposes no raw-seed loader. If its encoding ever changes, every signature
    made from a stored seed would break; this catches that at test time
    rather than in the field.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mldsa

    key = mldsa.MLDSA65PrivateKey.generate()
    seed = key.private_bytes_raw()
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    assert der == _signing._ML_DSA_65_PKCS8_SEED_PREFIX + seed


@require_cryptography_mldsa
def test_a_seed_reconstructs_the_same_public_key():
    """A stored seed is a complete private key, not half of one."""
    kp = generate_ml_dsa65()
    assert len(kp.private_key_bytes) == _signing._ML_DSA_65_SEED_LEN
    reloaded = _signing._mldsa_key_from_seed(kp.private_key_bytes)
    assert reloaded.public_key().public_bytes_raw() == kp.public_key_bytes


@require_pq
def test_public_key_is_the_fips_204_encoding():
    """1952 bytes either way, which is what makes key ids backend-agnostic."""
    kp = generate_ml_dsa65()
    assert len(kp.public_key_bytes) == _signing._ML_DSA_65_PUBLIC_LEN
    assert len(kp.key_id) == 64  # sha256 hex of the public key


@require_pq
def test_sign_and_verify_roundtrip():
    kp = generate_ml_dsa65()
    manifest = {"manifest_id": "x", "version": "0.1", "crypto_profile": "post-quantum"}
    block = MlDsa65Signer(kp).sign(manifest)
    assert block["algorithm"] == "ML-DSA-65"
    MlDsa65Verifier(kp.public_key_bytes).verify(manifest, block["signature_value"])


@require_pq
def test_a_signature_does_not_verify_under_another_key():
    kp, other = generate_ml_dsa65(), generate_ml_dsa65()
    manifest = {"manifest_id": "x", "version": "0.1"}
    block = MlDsa65Signer(kp).sign(manifest)
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        MlDsa65Verifier(other.public_key_bytes).verify(
            manifest, block["signature_value"]
        )


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------


@require_cryptography_mldsa
def test_a_liboqs_expanded_key_without_liboqs_is_a_capability_gap(monkeypatch):
    """Not a bad key, and not a bad signature - a backend that is not here.

    Reported as AlgorithmUnavailableError so the engine renders it
    UNVERIFIABLE rather than MISMATCH.
    """
    monkeypatch.setattr(_signing, "_OQS_AVAILABLE", False)
    expanded_key = b"\x02" * 4032  # liboqs ML-DSA-65 secret key length
    with pytest.raises(AlgorithmUnavailableError, match="expanded secret key"):
        _signing._ml_dsa_sign_raw(expanded_key, MESSAGE)


def test_no_backend_at_all_is_reported_as_a_capability_gap(monkeypatch):
    monkeypatch.setattr(_signing, "_CRYPTOGRAPHY_MLDSA_AVAILABLE", False)
    monkeypatch.setattr(_signing, "_OQS_AVAILABLE", False)
    assert _signing.ml_dsa65_available() is False
    with pytest.raises(AlgorithmUnavailableError, match="cryptography >= 47"):
        _signing._require_ml_dsa()
    with pytest.raises(AlgorithmUnavailableError):
        generate_ml_dsa65()


def test_require_oqs_is_still_the_capability_check(monkeypatch):
    """The old private name kept working when the backend became pluggable."""
    assert _signing._require_oqs is _signing._require_ml_dsa


# ---------------------------------------------------------------------------
# The `oqs` module name is not evidence of post-quantum support
# ---------------------------------------------------------------------------


def test_an_oqs_module_without_signature_is_not_treated_as_a_backend():
    """`oqs` on PyPI is an unrelated project that squats the module name.

    Importing it must not be read as liboqs being present: doing so turns
    every ML-DSA call into an AttributeError instead of a clean capability
    error, and makes the SDK claim a post-quantum capability it does not have.
    """
    imposter = SimpleNamespace(__name__="oqs", OQSInterpreter=object)
    assert _signing._has_liboqs_api(imposter) is False


def test_a_module_exposing_the_liboqs_api_is_treated_as_a_backend():
    assert _signing._has_liboqs_api(SimpleNamespace(Signature=object)) is True
