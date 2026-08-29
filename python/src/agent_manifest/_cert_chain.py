"""Generic, algorithm-agnostic X.509 certificate-chain verification.

This is the shared primitive the org's hardware-attestation verifiers build on.
An AMD SEV-SNP VCEK chain (RSA-PSS ``ARK``/``ASK`` + EC ``VCEK``), an Intel TDX
PCK chain (all EC), and a TPM attestation-key chain (per-vendor EK roots, RSA or
EC) are all the same shape: *a leaf-first chain in which each certificate is
issued by the next, up to a trusted root pinned by fingerprint*. The only thing
that differs is the signature algorithm on each link.

:func:`verify_cert_chain` verifies any of them by honoring **each certificate's
own** signature algorithm (ECDSA, RSASSA-PSS, or RSA PKCS#1 v1.5) via
:meth:`cryptography.x509.Certificate.verify_directly_issued_by`, then pins the
chain's final certificate to a caller-supplied trusted root by fingerprint. It
is fail-closed: any broken link or unpinned root raises :class:`CertChainError`.

cmcp and ca2a consume this (via the ``agent-manifest`` PyPI package) instead of
each carrying their own chain verifier; the AMD-specific
:func:`._snp_verify.verify_vcek_chain` is a thin specialisation of it.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.hashes import HashAlgorithm


class CertChainError(Exception):
    """Raised when a certificate chain fails to verify or pin to a trusted root."""


def check_validity_period(
    cert: x509.Certificate,
    *,
    label: str,
    verification_time: datetime | None = None,
) -> None:
    """Raise :class:`CertChainError` if *cert* is expired or not yet valid.

    Every certificate-chain verifier in this package (SEV-SNP, TDX, TPM, and
    this module's own :func:`verify_cert_chain`) needs the same check, so it
    lives here once rather than as three copies that can silently drift out
    of sync with each other.

    Args:
        cert: the certificate to check.
        label: identifies which certificate this is in the caller's chain
            (e.g. ``"VCEK"``, ``"PCK chain link 0"``), for the error message.
        verification_time: UTC-aware time to check against (default: current
            UTC time). Primarily useful for deterministic tests.
    """
    now = verification_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise CertChainError("verification_time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
        raise CertChainError(
            f"{label} is outside its validity period "
            f"({cert.not_valid_before_utc.isoformat()} - "
            f"{cert.not_valid_after_utc.isoformat()}, checked at {now.isoformat()})"
        )


def verify_cert_chain(
    chain: Sequence[x509.Certificate],
    trusted_roots: Sequence[x509.Certificate],
    *,
    root_fingerprint_hash: HashAlgorithm | None = None,
    verification_time: datetime | None = None,
) -> bool:
    """Verify a leaf-first certificate chain up to a fingerprint-pinned root.

    Args:
        chain: certificates ordered **leaf first, root last** (e.g.
            ``[VCEK, ASK, ARK]`` for SEV-SNP, or ``[PCK_leaf, …, root]`` for
            TDX). Each certificate must be directly issued by the next.
        trusted_roots: the roots the caller trusts. The chain's final
            certificate must match one of these by fingerprint.
        root_fingerprint_hash: hash used to compare root fingerprints
            (default SHA-256). The pin is on identity, so any collision-
            resistant hash works as long as it is used consistently.
        verification_time: UTC-aware time used for certificate validity checks
            (default: current UTC time). Primarily useful for deterministic tests.

    Returns:
        ``True`` when every link verifies (honoring each child's own signature
        algorithm) and the chain root is pinned. Never returns ``False`` —
        failure raises so a caller can never mistake a broken chain for a pass.

    Raises:
        CertChainError: on an empty chain, no trusted roots, a link that is not
            validly issued by the next, an expired or not-yet-valid certificate,
            an issuer that is not a CA, an issuer whose key usage forbids
            certificate signing, an unpinned root, or missing ``cryptography``.
    """
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.hashes import SHA256
    except ImportError as e:  # pragma: no cover - exercised via install extra
        raise CertChainError(
            "certificate-chain verification requires the 'cryptography' package"
        ) from e

    if not chain:
        raise CertChainError("empty certificate chain")
    if not trusted_roots:
        raise CertChainError("no trusted roots supplied")

    now = verification_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise CertChainError("verification_time must be timezone-aware")
    now = now.astimezone(timezone.utc)

    for i, cert in enumerate(chain):
        check_validity_period(cert, label=f"certificate at position {i}", verification_time=now)

    for i, issuer in enumerate(chain[1:], start=1):
        try:
            constraints = issuer.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as exc:
            raise CertChainError(
                f"issuer certificate at position {i} has no BasicConstraints"
            ) from exc
        if not constraints.ca:
            raise CertChainError(f"issuer certificate at position {i} is not a CA")
        try:
            key_usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            pass
        else:
            if not key_usage.key_cert_sign:
                raise CertChainError(
                    f"issuer certificate at position {i} cannot sign certificates"
                )

    for i in range(len(chain) - 1):
        try:
            # Honors the child's own signature algorithm (ECDSA / RSA-PSS /
            # RSA-PKCS#1 v1.5) and checks issuer/subject-name chaining.
            chain[i].verify_directly_issued_by(chain[i + 1])
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise CertChainError(
                f"certificate at position {i} is not validly issued by the next: {exc}"
            ) from exc

    halg = root_fingerprint_hash or SHA256()
    trusted_fps = {c.fingerprint(halg) for c in trusted_roots}
    if chain[-1].fingerprint(halg) not in trusted_fps:
        raise CertChainError("chain root does not match any trusted root")

    return True
