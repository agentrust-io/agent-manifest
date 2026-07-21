"""TPM 2.0 quote (TPMS_ATTEST) parsing and offline signature-chain verification.

This is the TPM analogue of :mod:`._snp_verify` and :mod:`._tdx_verify`, and the
shared implementation the org consolidates onto (cmcp and ca2a consume it via
PyPI rather than carrying their own copies). It was ported from ca2a's
``ca2a_verify.tpm`` reference implementation.

Verification is fail-closed, in four steps:

1. The structure is confirmed to be a TPM-generated quote (``magic`` ==
   ``TPM_GENERATED_VALUE`` and ``attest_type`` == ``TPM_ST_ATTEST_QUOTE``).
2. The attestation-key (AK) certificate chain is verified up to a
   caller-supplied trusted root (leaf issued-by next, root pinned by
   SHA-256 fingerprint). A self-signed AK is never trusted on its own.
3. The AK signature over the ``TPMS_ATTEST`` blob is verified (ECDSA-P256 or
   RSA PKCS#1 v1.5, both over SHA-256).
4. The qualifying data (the verifier's nonce, carried in ``extraData``) and the
   PCR digest (the platform measurement) are checked against expected values
   with constant-time compares.

Unlike SEV-SNP/TDX there is no single published TPM root — AK certs chain to
per-vendor EK roots — so the caller supplies the vendor roots it trusts. Only
the ``cryptography`` package is required; no external tools run at verify time.

Note: the parsing and signature/chain logic are exercised against synthetic
self-consistent vectors (see ``tests/test_tpm_verify.py``). Unlike the SEV-SNP
and TDX paths, this verifier has not yet been validated against a quote from a
real TPM; that is tracked as follow-up hardware validation.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
_CLOCK_INFO_LEN = 17
_FIRMWARE_VERSION_LEN = 8


class TpmVerificationError(Exception):
    """Raised when a TPM quote or its certificate chain fails verification."""


def _read_u16(buf: bytes, pos: int) -> tuple[int, int]:
    if pos + 2 > len(buf):
        raise TpmVerificationError("TPM quote truncated reading a 16-bit field")
    return int.from_bytes(buf[pos:pos + 2], "big"), pos + 2


def _read_2b(buf: bytes, pos: int) -> tuple[bytes, int]:
    size, pos = _read_u16(buf, pos)
    if pos + size > len(buf):
        raise TpmVerificationError("TPM quote truncated reading a sized buffer")
    return buf[pos:pos + size], pos + size


@dataclass(frozen=True)
class TpmQuote:
    """The parsed subset of a TPM 2.0 quote (TPMS_ATTEST) that is appraised."""

    magic: int
    attest_type: int
    qualifying_data: bytes  # extraData: the verifier's nonce
    pcr_digest: bytes  # the platform measurement
    raw: bytes


def parse_tpm_quote(attest: bytes) -> TpmQuote:
    """Parse a ``TPMS_ATTEST`` quote blob into its appraised fields."""
    if len(attest) < 6:
        raise TpmVerificationError("TPM quote too short")
    magic = int.from_bytes(attest[0:4], "big")
    attest_type, pos = _read_u16(attest, 4)
    _qualified_signer, pos = _read_2b(attest, pos)  # TPM2B_NAME
    qualifying_data, pos = _read_2b(attest, pos)  # extraData / nonce
    pos += _CLOCK_INFO_LEN + _FIRMWARE_VERSION_LEN
    # TPML_PCR_SELECTION
    if pos + 4 > len(attest):
        raise TpmVerificationError("TPM quote truncated reading PCR selection count")
    count = int.from_bytes(attest[pos:pos + 4], "big")
    pos += 4
    for _ in range(count):
        if pos + 3 > len(attest):
            raise TpmVerificationError("TPM quote truncated reading a PCR selection")
        size_of_select = attest[pos + 2]
        pos += 3 + size_of_select
    pcr_digest, _pos = _read_2b(attest, pos)
    return TpmQuote(
        magic=magic,
        attest_type=attest_type,
        qualifying_data=qualifying_data,
        pcr_digest=pcr_digest,
        raw=bytes(attest),
    )


def _verify_ak_chain(ak_chain_pem: bytes, trusted_roots_pem: bytes) -> "object":
    """Verify a leaf-first AK chain up to a pinned trusted root; return the leaf.

    Raises :class:`TpmVerificationError` on any failure.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.hashes import SHA256

    chain = x509.load_pem_x509_certificates(ak_chain_pem)
    roots = x509.load_pem_x509_certificates(trusted_roots_pem)
    if not chain:
        raise TpmVerificationError("empty AK certificate chain")
    if not roots:
        raise TpmVerificationError("no trusted TPM roots supplied")

    for i in range(len(chain) - 1):
        try:
            chain[i].verify_directly_issued_by(chain[i + 1])
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise TpmVerificationError(
                f"AK chain certificate at position {i} is not validly issued by the next: {exc}"
            ) from exc

    trusted = {c.fingerprint(SHA256()) for c in roots}
    if chain[-1].fingerprint(SHA256()) not in trusted:
        raise TpmVerificationError(
            "AK chain root is not among the supplied trusted TPM roots"
        )
    return chain[0]


def verify_tpm_quote(
    attest: bytes,
    signature: bytes,
    ak_chain_pem: bytes,
    *,
    trusted_roots_pem: bytes,
    expected_qualifying_data: Optional[bytes] = None,
    expected_pcr_digest: Optional[bytes] = None,
) -> bool:
    """Fully verify a TPM 2.0 quote offline (all four steps, fail-closed).

    Args:
        attest: the raw ``TPMS_ATTEST`` blob the TPM signed.
        signature: the AK signature over ``attest`` (DER ECDSA-P256 or RSA
            PKCS#1 v1.5, SHA-256).
        ak_chain_pem: the AK certificate chain (PEM, leaf first).
        trusted_roots_pem: the caller's trusted vendor EK/AK roots (PEM).
        expected_qualifying_data: if given, the quote's ``extraData`` (nonce)
            must equal it.
        expected_pcr_digest: if given, the quote's PCR digest must equal it.

    Returns:
        ``True`` only when the structure, AK chain, AK signature, and any
        supplied bindings all check out. Returns ``False`` on a well-formed but
        invalid signature or a binding mismatch. Raises
        :class:`TpmVerificationError` on a malformed quote / broken chain or if
        ``cryptography`` is unavailable.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.hashes import SHA256
    except ImportError as e:  # pragma: no cover
        raise TpmVerificationError(
            "TPM quote verification requires the 'cryptography' package"
        ) from e

    quote = parse_tpm_quote(attest)

    # Step 1: structural — this must be a TPM-generated quote.
    if quote.magic != TPM_GENERATED_VALUE:
        raise TpmVerificationError(
            f"TPMS_ATTEST magic is not TPM_GENERATED (magic={quote.magic:#x})"
        )
    if quote.attest_type != TPM_ST_ATTEST_QUOTE:
        raise TpmVerificationError(
            f"attestation is not a quote (type={quote.attest_type:#x})"
        )

    # Step 2: AK certificate chain up to a pinned trusted root.
    ak = _verify_ak_chain(ak_chain_pem, trusted_roots_pem)
    ak_key = ak.public_key()  # type: ignore[attr-defined]

    # Step 3: AK signature over the TPMS_ATTEST blob.
    try:
        if isinstance(ak_key, ec.EllipticCurvePublicKey):
            ak_key.verify(signature, attest, ec.ECDSA(SHA256()))
        elif isinstance(ak_key, rsa.RSAPublicKey):
            ak_key.verify(signature, attest, padding.PKCS1v15(), SHA256())
        else:
            raise TpmVerificationError("unsupported AK public-key type for TPM quote")
    except InvalidSignature:
        return False

    # Step 4: bindings (constant-time).
    if expected_qualifying_data is not None and not hmac.compare_digest(
        quote.qualifying_data, expected_qualifying_data
    ):
        return False
    if expected_pcr_digest is not None and not hmac.compare_digest(
        quote.pcr_digest, expected_pcr_digest
    ):
        return False

    return True
