"""TPM quote vectors from the reference implementation, run through the verifier.

The signature schemes and digests exercised here are the ones ``_tpm_verify``
supports, and ``test_tpm_verify.py`` already covers them. What it cannot supply
is an independent producer: its fixtures are signed by a helper that lives in
this repository, alongside the verifier that reads them, so producer and
consumer share an interpretation of the wire format. These vectors were emitted
by the Microsoft/TCG TPM 2.0 reference implementation instead, which puts a
provenance boundary between the bytes and the code under test.

They are simulator output, not captures from physical hardware, and the AK
certificate chains are synthetic wrappers around the simulator's own public
keys. ``fixtures/reference/ms-tpm-20-ref-v183/README.md`` records the source
commit, the tooling, and both caveats.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

crypto = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.hashes import SHA256  # noqa: E402

from agent_manifest import (  # noqa: E402
    ParsedSignature,
    TpmVerificationError,
    parse_tpmt_signature,
    verify_tpm_quote,
)

REF = Path(__file__).parent / "fixtures" / "reference" / "ms-tpm-20-ref-v183"
NONCE = bytes.fromhex((REF / "nonce.hex").read_text().strip())

_ALG_RSASSA, _ALG_RSAPSS, _ALG_ECDSA = 0x0014, 0x0016, 0x0018
_ALG_SHA256, _ALG_SHA384 = 0x000B, 0x000C

#: fixture prefix -> (sigAlg, hashAlg) the simulator actually emitted.
VECTORS: dict[str, tuple[int, int]] = {
    "rsassa-sha256": (_ALG_RSASSA, _ALG_SHA256),
    "rsapss-sha256": (_ALG_RSAPSS, _ALG_SHA256),
    "rsassa-sha384": (_ALG_RSASSA, _ALG_SHA384),
    "ecdsa-sha384": (_ALG_ECDSA, _ALG_SHA384),
}


def _load_vector(prefix: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (attest, marshalled TPMT_SIGNATURE, ak_chain_pem, roots_pem)."""
    return (
        (REF / f"{prefix}-attest.bin").read_bytes(),
        (REF / f"{prefix}-tpmt-signature.bin").read_bytes(),
        (REF / f"{prefix}-ak-chain.pem").read_bytes(),
        (REF / f"{prefix}-root.pem").read_bytes(),
    )


def _verify_vector(prefix: str, signature: bytes | ParsedSignature) -> bool:
    attest, _, chain, roots = _load_vector(prefix)
    return verify_tpm_quote(
        attest,
        signature,
        chain,
        trusted_roots_pem=roots,
        expected_qualifying_data=NONCE,
    )


# --- the corpus describes itself accurately ------------------------------------


@pytest.mark.parametrize(("prefix", "expected"), VECTORS.items())
def test_fixture_declares_the_algorithms_its_name_claims(
    prefix: str, expected: tuple[int, int]
) -> None:
    """Guards the corpus itself: a renamed or regenerated file must not quietly
    retarget the tests below at some other algorithm pair."""
    _, tpmt, _, _ = _load_vector(prefix)
    assert struct.unpack_from(">HH", tpmt, 0) == expected


# --- reference evidence verifies, in both accepted input forms ------------------


@pytest.mark.parametrize("prefix", list(VECTORS))
def test_reference_quote_verifies_as_marshalled_envelope(prefix: str) -> None:
    """A marshalled ``TPMT_SIGNATURE`` handed over as bytes -- the shape a caller
    reading ``tpm2_quote -s`` output actually holds."""
    assert _verify_vector(prefix, _load_vector(prefix)[1]) is True


@pytest.mark.parametrize("prefix", list(VECTORS))
def test_reference_quote_verifies_as_parsed_signature(prefix: str) -> None:
    assert _verify_vector(prefix, parse_tpmt_signature(_load_vector(prefix)[1])) is True


# --- metadata that misdescribes a genuine signature is refused ------------------


def test_reference_signature_with_wrong_declared_hash_is_rejected() -> None:
    parsed = parse_tpmt_signature(_load_vector("rsassa-sha384")[1])
    misdeclared = ParsedSignature(parsed.sig_alg, _ALG_SHA256, parsed.signature)
    assert _verify_vector("rsassa-sha384", misdeclared) is False


def test_reference_signature_with_wrong_declared_scheme_is_rejected() -> None:
    parsed = parse_tpmt_signature(_load_vector("rsassa-sha256")[1])
    misdeclared = ParsedSignature(_ALG_RSAPSS, parsed.hash_alg, parsed.signature)
    assert _verify_vector("rsassa-sha256", misdeclared) is False


def test_ecdsa_scheme_against_an_rsa_key_is_refused() -> None:
    parsed = parse_tpmt_signature(_load_vector("rsassa-sha256")[1])
    mismatched = ParsedSignature(_ALG_ECDSA, parsed.hash_alg, parsed.signature)
    with pytest.raises(TpmVerificationError, match="does not match the RSA attestation key"):
        _verify_vector("rsassa-sha256", mismatched)


@pytest.mark.parametrize("scheme", [_ALG_RSASSA, _ALG_RSAPSS])
def test_rsa_scheme_against_an_ec_key_is_refused(scheme: int) -> None:
    parsed = parse_tpmt_signature(_load_vector("ecdsa-sha384")[1])
    mismatched = ParsedSignature(scheme, parsed.hash_alg, parsed.signature)
    with pytest.raises(TpmVerificationError, match="does not match the EC attestation key"):
        _verify_vector("ecdsa-sha384", mismatched)


# --- tampering with reference evidence still fails ------------------------------


@pytest.mark.parametrize("prefix", list(VECTORS))
def test_tampered_reference_attest_fails(prefix: str) -> None:
    attest, tpmt, chain, roots = _load_vector(prefix)
    corrupted = bytearray(attest)
    corrupted[-1] ^= 0xFF
    assert (
        verify_tpm_quote(
            bytes(corrupted), parse_tpmt_signature(tpmt), chain, trusted_roots_pem=roots
        )
        is False
    )


@pytest.mark.parametrize("prefix", list(VECTORS))
def test_tampered_reference_signature_fails(prefix: str) -> None:
    parsed = parse_tpmt_signature(_load_vector(prefix)[1])
    corrupted = bytearray(parsed.signature)
    corrupted[-1] ^= 0xFF
    assert (
        _verify_vector(prefix, ParsedSignature(parsed.sig_alg, parsed.hash_alg, bytes(corrupted)))
        is False
    )


# --- what the reference PSS signature commits to --------------------------------


def test_reference_pss_signature_uses_a_digest_length_salt() -> None:
    """Evidence for the PSS salt length, taken from the reference signature
    rather than from the implementation that has to verify it.

    ``MAX_LENGTH`` is deliberately not contrasted here: ``cryptography`` treats
    it as "recover the salt length" when verifying, so it would accept this
    signature too and would prove nothing either way.
    """
    from cryptography.x509 import load_pem_x509_certificates

    attest, tpmt, chain, _roots = _load_vector("rsapss-sha256")
    parsed = parse_tpmt_signature(tpmt)
    ak_key = load_pem_x509_certificates(chain)[0].public_key()

    for salt_length in (SHA256().digest_size, padding.PSS.DIGEST_LENGTH):
        ak_key.verify(
            parsed.signature,
            attest,
            padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=salt_length),
            SHA256(),
        )
