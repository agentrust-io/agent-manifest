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
3. The AK signature over the ``TPMS_ATTEST`` blob is verified. Bare signatures
   retain the legacy SHA-256 behavior; a ``TPMT_SIGNATURE`` selects RSASSA,
   RSAPSS, or ECDSA and SHA-256, SHA-384, or SHA-512 from its signed envelope.
4. The qualifying data (the verifier's nonce, carried in ``extraData``) and the
   PCR digest (the platform measurement) are checked against expected values
   with constant-time compares.

Unlike SEV-SNP/TDX there is no single published TPM root — AK certs chain to
per-vendor EK roots — so the caller supplies the vendor roots it trusts. Only
the ``cryptography`` package is required; no external tools run at verify time.

Two wire-format details exist because real tooling emits them, and both were
found by running against a TPM rather than by reading the TCG structures spec:

* **Quote framing.** ``tpm2_quote -m`` writes a bare ``TPMS_ATTEST``, while other
  producers write a ``TPM2B_ATTEST`` with a two-byte big-endian size prefix.
  :func:`parse_tpm_quote` accepts both and tells them apart by the magic, because
  a verifier that rejects the framing the standard tooling produces is a verifier
  nobody can use. It returns the inner ``TPMS_ATTEST`` as ``raw``, which is the
  byte range the AK actually signed.
* **Signature framing.** ``tpm2_quote -s`` and ``tpm2-pytss``'s
  ``signature.marshal()`` write a ``TPMT_SIGNATURE``, not a bare DER/PKCS#1
  signature. :func:`parse_tpmt_signature` unwraps it.

Hardware validation: exercised end to end against an AK-signed quote captured on
2026-07-31 from an Azure Trusted Launch vTPM (``Standard_D2s_v5``, Ubuntu 24.04,
``TPM2_PT_MANUFACTURER`` = ``MSFT``, RSASSA/SHA-256 AK, PCRs 0-7 under a fresh
32-byte nonce), with tampered attest blobs, tampered signatures and a wrong key
all rejected. That vector is committed in ``tests/test_tpm_hardware_vector.py``
because it carries no per-CPU identifier, so the signature path runs on every PR.
What remains unvalidated on Azure is the AK *certificate chain*: see
``LIMITATIONS.md`` and cmcp#431.
"""
from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass
from datetime import datetime

TPM_GENERATED_VALUE = 0xFF544347
TPM_ST_ATTEST_NV = 0x8014
TPM_ST_ATTEST_QUOTE = 0x8018
_CLOCK_INFO_LEN = 17
_FIRMWARE_VERSION_LEN = 8

# TPM2_ALG_ID values for the signing schemes a quote can use.
_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_ECDSA = 0x0018


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
class TpmAttest:
    """Common header and type-specific payload of a ``TPMS_ATTEST``.

    The bytes after the common header are intentionally left opaque.  Callers
    inspect ``attest_type`` before passing ``attested_raw`` to a parser for the
    corresponding member of the ``TPMU_ATTEST`` union.
    """

    magic: int
    attest_type: int
    qualified_signer: bytes
    qualifying_data: bytes
    clock_info: bytes
    firmware_version: int
    attested_raw: bytes
    raw: bytes


@dataclass(frozen=True)
class TpmQuote:
    """The parsed subset of a TPM 2.0 quote (TPMS_ATTEST) that is appraised."""

    magic: int
    attest_type: int
    qualifying_data: bytes  # extraData: the verifier's nonce
    pcr_digest: bytes  # the platform measurement
    raw: bytes


@dataclass(frozen=True)
class NvCertifyInfo:
    """The parsed ``TPMS_NV_CERTIFY_INFO`` member of ``TPMU_ATTEST``."""

    index_name: bytes
    offset: int
    nv_contents: bytes


@dataclass(frozen=True)
class TpmNvCertify:
    """A type-checked TPM NV certification and its signed common header."""

    attest: TpmAttest
    info: NvCertifyInfo


def _unwrap_attest(data: bytes) -> bytes:
    """Return the inner ``TPMS_ATTEST``, accepting either framing.

    A bare ``TPMS_ATTEST`` starts with ``TPM_GENERATED_VALUE``; a ``TPM2B_ATTEST``
    starts with a two-byte big-endian size. Framing is decided by requiring the
    magic to appear in the resulting blob under one reading or the other, not by
    the leading bytes alone. A blob whose magic is corrupt would otherwise be
    silently reinterpreted as a size prefix and reported as a framing fault,
    which sends whoever is debugging it to the wrong problem.
    """
    if len(data) < 6:
        raise TpmVerificationError("TPM quote too short")
    if int.from_bytes(data[0:4], "big") == TPM_GENERATED_VALUE:
        return data
    size = int.from_bytes(data[0:2], "big")
    if 0 < size == len(data) - 2:
        inner = data[2:2 + size]
        if len(inner) >= 4 and int.from_bytes(inner[0:4], "big") == TPM_GENERATED_VALUE:
            return inner
    raise TpmVerificationError(
        "not a TPM quote: no TPM_GENERATED magic as either a bare TPMS_ATTEST or "
        f"a size-prefixed TPM2B_ATTEST (leading bytes {data[:4].hex()})"
    )


def parse_tpm_attest(attest: bytes) -> TpmAttest:
    """Parse the common ``TPMS_ATTEST`` header without assuming a union type.

    Accepts the same bare and ``TPM2B_ATTEST`` framings as
    :func:`parse_tpm_quote`.  ``attested_raw`` starts at the ``TPMU_ATTEST``
    union, while ``raw`` is the complete inner structure signed by the AK.
    """
    attest = _unwrap_attest(attest)
    if len(attest) < 6:
        raise TpmVerificationError("TPM attestation too short")
    magic = int.from_bytes(attest[0:4], "big")
    attest_type, pos = _read_u16(attest, 4)
    qualified_signer, pos = _read_2b(attest, pos)
    qualifying_data, pos = _read_2b(attest, pos)
    if pos + _CLOCK_INFO_LEN + _FIRMWARE_VERSION_LEN > len(attest):
        raise TpmVerificationError("TPM attestation truncated reading clock or firmware data")
    clock_info = bytes(attest[pos:pos + _CLOCK_INFO_LEN])
    pos += _CLOCK_INFO_LEN
    firmware_version = int.from_bytes(attest[pos:pos + _FIRMWARE_VERSION_LEN], "big")
    pos += _FIRMWARE_VERSION_LEN
    return TpmAttest(
        magic=magic,
        attest_type=attest_type,
        qualified_signer=qualified_signer,
        qualifying_data=qualifying_data,
        clock_info=clock_info,
        firmware_version=firmware_version,
        attested_raw=bytes(attest[pos:]),
        raw=bytes(attest),
    )


def parse_nv_certify_info(attested_raw: bytes) -> NvCertifyInfo:
    """Parse a ``TPMS_NV_CERTIFY_INFO`` union payload.

    The caller must first use :func:`parse_tpm_attest` and require
    ``attest_type == TPM_ST_ATTEST_NV``.  Keeping the common-header and union
    parsers separate prevents a quote from being silently interpreted as an NV
    certify while still allowing consumers to branch on the signed type.
    """
    index_name, pos = _read_2b(attested_raw, 0)
    offset, pos = _read_u16(attested_raw, pos)
    nv_contents, pos = _read_2b(attested_raw, pos)
    if pos != len(attested_raw):
        raise TpmVerificationError(
            "TPMS_NV_CERTIFY_INFO has trailing bytes after nvContents"
        )
    return NvCertifyInfo(
        index_name=index_name,
        offset=offset,
        nv_contents=nv_contents,
    )


def parse_tpm_nv_certify(attest: bytes) -> TpmNvCertify:
    """Parse a full NV-certify attestation and enforce its signed union type."""
    common = parse_tpm_attest(attest)
    if common.attest_type != TPM_ST_ATTEST_NV:
        raise TpmVerificationError(
            f"attestation is not an NV certify (type={common.attest_type:#x})"
        )
    return TpmNvCertify(attest=common, info=parse_nv_certify_info(common.attested_raw))


def parse_tpm_quote(attest: bytes) -> TpmQuote:
    """Parse a quote blob into its appraised fields.

    Accepts a bare ``TPMS_ATTEST`` or a size-prefixed ``TPM2B_ATTEST``. The
    returned ``raw`` is always the inner ``TPMS_ATTEST``, which is the byte range
    the attestation key signed and therefore what a signature check must cover.
    """
    common = parse_tpm_attest(attest)
    if common.attest_type != TPM_ST_ATTEST_QUOTE:
        raise TpmVerificationError(
            f"attestation is not a quote (type={common.attest_type:#x})"
        )
    attested = common.attested_raw
    pos = 0
    # TPML_PCR_SELECTION
    if pos + 4 > len(attested):
        raise TpmVerificationError("TPM quote truncated reading PCR selection count")
    count = int.from_bytes(attested[pos:pos + 4], "big")
    pos += 4
    for _ in range(count):
        if pos + 3 > len(attested):
            raise TpmVerificationError("TPM quote truncated reading a PCR selection")
        size_of_select = attested[pos + 2]
        pos += 3 + size_of_select
    pcr_digest, _pos = _read_2b(attested, pos)
    return TpmQuote(
        magic=common.magic,
        attest_type=common.attest_type,
        qualifying_data=common.qualifying_data,
        pcr_digest=pcr_digest,
        raw=common.raw,
    )


@dataclass(frozen=True)
class ParsedSignature:
    """A parsed ``TPMT_SIGNATURE``: the algorithm ids and the bare signature.

    ``signature`` is in the form ``cryptography`` verifies against: PKCS#1 for
    RSA, and a DER-encoded sequence for ECDSA (the TPM emits R and S as two
    size-prefixed integers, which are re-encoded here).
    """

    sig_alg: int
    hash_alg: int
    signature: bytes


def parse_tpmt_signature(blob: bytes) -> ParsedSignature:
    """Unwrap a ``TPMT_SIGNATURE`` into a bare signature.

    Layout: ``sigAlg`` (2), ``hashAlg`` (2), then the algorithm-specific body. For
    RSA that is a size-prefixed ``TPM2B_PUBLIC_KEY_RSA``. For ECDSA it is two
    size-prefixed integers, R then S.

    Raises :class:`TpmVerificationError` on anything malformed, so a caller
    cannot mistake a truncated blob for a signature that failed to verify.
    """
    if len(blob) < 6:
        raise TpmVerificationError("TPMT_SIGNATURE too short")
    try:
        sig_alg, hash_alg = struct.unpack_from(">HH", blob, 0)
        offset = 4

        if sig_alg in (_ALG_RSASSA, _ALG_RSAPSS):
            (size,) = struct.unpack_from(">H", blob, offset)
            offset += 2
            if len(blob) < offset + size:
                raise TpmVerificationError("TPMT_SIGNATURE truncated inside the RSA signature")
            offset += size
            if offset != len(blob):
                raise TpmVerificationError("TPMT_SIGNATURE has trailing bytes")
            return ParsedSignature(sig_alg, hash_alg, blob[offset - size:offset])

        if sig_alg == _ALG_ECDSA:
            from cryptography.hazmat.primitives.asymmetric.utils import (
                encode_dss_signature,
            )

            parts: list[bytes] = []
            for _ in range(2):
                (size,) = struct.unpack_from(">H", blob, offset)
                offset += 2
                if len(blob) < offset + size:
                    raise TpmVerificationError(
                        "TPMT_SIGNATURE truncated inside the ECDSA signature"
                    )
                parts.append(blob[offset:offset + size])
                offset += size
            if offset != len(blob):
                raise TpmVerificationError("TPMT_SIGNATURE has trailing bytes")
            return ParsedSignature(
                sig_alg,
                hash_alg,
                encode_dss_signature(
                    int.from_bytes(parts[0], "big"), int.from_bytes(parts[1], "big")
                ),
            )
    except struct.error as exc:
        raise TpmVerificationError(f"TPMT_SIGNATURE is malformed: {exc}") from exc

    raise TpmVerificationError(f"unsupported signature algorithm 0x{sig_alg:04x}")


def _verify_ak_chain(
    ak_chain_pem: bytes,
    trusted_roots_pem: bytes,
    *,
    verification_time: datetime | None = None,
) -> object:
    """Verify a leaf-first AK chain up to a pinned trusted root; return the leaf.

    Every certificate in the chain must be within its validity period (see
    :func:`._cert_chain.check_validity_period`); an expired AK certificate or
    an expired link above it is rejected even if every signature in the chain
    is otherwise valid.

    Raises :class:`TpmVerificationError` on any failure.
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.hashes import SHA256

    from ._cert_chain import CertChainError, check_validity_period

    chain = x509.load_pem_x509_certificates(ak_chain_pem)
    roots = x509.load_pem_x509_certificates(trusted_roots_pem)
    if not chain:
        raise TpmVerificationError("empty AK certificate chain")
    if not roots:
        raise TpmVerificationError("no trusted TPM roots supplied")

    for i, cert in enumerate(chain):
        try:
            check_validity_period(
                cert, label=f"AK chain certificate at position {i}", verification_time=verification_time
            )
        except CertChainError as e:
            raise TpmVerificationError(str(e)) from e

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


def verify_ak_signature(
    ak_public_key: object,
    attest_raw: bytes,
    signature: bytes | ParsedSignature,
) -> bool:
    """Verify a quote's AK signature over ``attest_raw``, given a trusted AK key.

    This is exactly step 3 of :func:`verify_tpm_quote` (the signature check),
    factored out so a caller who establishes trust in the AK by some route
    other than an X.509 chain can still reuse the same signature-verification
    code instead of re-implementing ``TPMT_SIGNATURE``/legacy-signature framing
    and algorithm selection. For example, an Azure vTPM AK is not chained to a
    CA at all: it is trusted because its public key is embedded in runtime
    data that is itself bound (via ``REPORT_DATA``) into a VCEK-signed SNP
    report, verified elsewhere. ``ak_public_key`` must already be an
    ``ec.EllipticCurvePublicKey`` or ``rsa.RSAPublicKey``; establishing that
    the key is the *right* one is the caller's responsibility.

    Returns ``True`` only when the signature verifies. Returns ``False`` on a
    well-formed but invalid signature or key/algorithm mismatch. Raises
    :class:`TpmVerificationError` on a malformed ``TPMT_SIGNATURE`` or an
    unsupported algorithm.
    """

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError as e:  # pragma: no cover
        raise TpmVerificationError(
            "TPM quote verification requires the 'cryptography' package"
        ) from e

    parsed_signature: ParsedSignature | None = None
    if isinstance(signature, ParsedSignature):
        parsed_signature = signature
    elif len(signature) >= 2 and int.from_bytes(signature[:2], "big") in (
        _ALG_RSASSA,
        _ALG_RSAPSS,
        _ALG_ECDSA,
    ):
        parsed_signature = parse_tpmt_signature(signature)

    if parsed_signature is None:
        assert isinstance(signature, bytes)
        bare_signature = signature
        signature_algorithm = None
        digest: hashes.HashAlgorithm = hashes.SHA256()
    else:
        bare_signature = parsed_signature.signature
        signature_algorithm = parsed_signature.sig_alg
        if parsed_signature.hash_alg == 0x000B:
            digest = hashes.SHA256()
        elif parsed_signature.hash_alg == 0x000C:
            digest = hashes.SHA384()
        elif parsed_signature.hash_alg == 0x000D:
            digest = hashes.SHA512()
        else:
            raise TpmVerificationError(
                f"unsupported hash algorithm 0x{parsed_signature.hash_alg:04x}"
            )

    try:
        if isinstance(ak_public_key, ec.EllipticCurvePublicKey):
            if signature_algorithm not in (None, _ALG_ECDSA):
                raise TpmVerificationError(
                    "TPMT_SIGNATURE algorithm does not match the EC attestation key"
                )
            ak_public_key.verify(bare_signature, attest_raw, ec.ECDSA(digest))
        elif isinstance(ak_public_key, rsa.RSAPublicKey):
            signature_padding: padding.AsymmetricPadding
            if signature_algorithm in (None, _ALG_RSASSA):
                signature_padding = padding.PKCS1v15()
            elif signature_algorithm == _ALG_RSAPSS:
                signature_padding = padding.PSS(
                    mgf=padding.MGF1(digest), salt_length=digest.digest_size
                )
            else:
                raise TpmVerificationError(
                    "TPMT_SIGNATURE algorithm does not match the RSA attestation key"
                )
            ak_public_key.verify(bare_signature, attest_raw, signature_padding, digest)
        else:
            raise TpmVerificationError("unsupported AK public-key type for TPM quote")
    except InvalidSignature:
        return False
    return True

def verify_tpm_quote(
    attest: bytes,
    signature: bytes | ParsedSignature,
    ak_chain_pem: bytes,
    *,
    trusted_roots_pem: bytes,
    expected_qualifying_data: bytes | None = None,
    expected_pcr_digest: bytes | None = None,
    verification_time: datetime | None = None,
) -> bool:
    """Fully verify a TPM 2.0 quote offline (all four steps, fail-closed).

    Args:
        attest: the raw ``TPMS_ATTEST`` blob the TPM signed.
        signature: either the legacy bare AK signature (DER ECDSA or RSA
            PKCS#1 v1.5 over SHA-256), a parsed :class:`ParsedSignature`, or a
            marshalled ``TPMT_SIGNATURE``. Envelopes select RSASSA, RSAPSS, or
            ECDSA and SHA-256, SHA-384, or SHA-512 from their algorithm ids.
        ak_chain_pem: the AK certificate chain (PEM, leaf first).
        trusted_roots_pem: the caller's trusted vendor EK/AK roots (PEM).
        expected_qualifying_data: if given, the quote's ``extraData`` (nonce)
            must equal it.
        expected_pcr_digest: if given, the quote's PCR digest must equal it.
        verification_time: UTC-aware time used to check AK chain certificate
            validity periods (default: current UTC time). Primarily useful
            for deterministic tests.

    Returns:
        ``True`` only when the structure, AK chain, AK signature, and any
        supplied bindings all check out. Returns ``False`` on a well-formed but
        invalid signature or a binding mismatch. Raises
        :class:`TpmVerificationError` on a malformed quote / broken chain or if
        ``cryptography`` is unavailable.
    """
    try:
        import cryptography  # noqa: F401
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
    ak = _verify_ak_chain(ak_chain_pem, trusted_roots_pem, verification_time=verification_time)
    ak_key = ak.public_key()  # type: ignore[attr-defined]

    # Step 3: AK signature over the TPMS_ATTEST blob. Use quote.raw rather than
    # the argument: when the caller passes a size-prefixed TPM2B_ATTEST, the TPM
    # signed the inner structure, so verifying over the outer bytes would fail a
    # genuine quote.
    if not verify_ak_signature(ak_key, quote.raw, signature):
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
