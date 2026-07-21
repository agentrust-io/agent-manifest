"""Attestation-chain verification for boot-time attestation reports (issue #204).

A boot-time ``AttestationReport`` is only trustworthy to a third party once a
verifier has checked three things:

1. **Signature / quote chain** — the report is signed by genuine platform
   hardware. For AMD SEV-SNP this is implemented (:mod:`._snp_verify`): the
   report's ECDSA-P384 signature is verified against the VCEK, and the
   VCEK<-ASK<-ARK chain against the AMD root. For Intel TDX the self-contained
   DCAP quote is verified (ECDSA-P256 signature, QE binding, and the PCK chain
   to the pinned Intel SGX Root CA) — see :mod:`._tdx_verify`. Both were
   validated against reports captured from real silicon (SEV-SNP + TDX).
2. **Launch measurement** — ``MEASUREMENT`` / ``MRTD`` / PCRs match a known-good
   value (or an allow-list of accepted measurements). Implemented below.
3. **Bound field** — the guest-supplied ``REPORT_DATA`` carries the expected
   manifest hash. Implemented below. NOTE: this applies to the *direct* SNP
   model where the guest controls ``REPORT_DATA``. On Azure confidential VMs
   the guest does not control ``REPORT_DATA`` (the paravisor binds the vTPM AK
   there); manifest binding on Azure is via the vTPM quote produced by
   ``AzureCVMProvider``, not this field.

:func:`verify_attestation_chain` **fails closed**: ``passed`` is ``True`` only
when the hardware signature is ``VERIFIED``, the manifest-hash binding matches,
and the measurement is accepted (or no allow-list was requested). If no VCEK /
certificate material is supplied, the signature step is reported as
``NOT_IMPLEMENTED`` (not performed) and the result cannot pass.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SignatureStatus(str, Enum):
    """Outcome of the hardware signature / quote-chain check."""

    VERIFIED = "verified"
    FAILED = "failed"
    # No verification material supplied, or a platform whose backend is not yet
    # implemented (Intel TDX Quote verification is tracked in #204/#205).
    NOT_IMPLEMENTED = "not_implemented"


@dataclass
class ChainVerificationResult:
    """Result of verifying a boot-time attestation report against expectations.

    ``passed`` requires ALL of: signature ``VERIFIED``, the launch measurement
    accepted (or not requested), and the manifest-hash binding matched. Until
    the signature backends land (#204), ``passed`` is always ``False`` and
    ``reasons`` explains why.
    """

    passed: bool
    signature: SignatureStatus
    report_data_matched: bool
    measurement_matched: Optional[bool]  # None = no allow-list supplied
    reasons: list[str] = field(default_factory=list)


def _report_data_hex(report: Any) -> Optional[str]:
    """Return the hex of the guest-supplied report-data field, if present."""
    raw = getattr(report, "raw", None)
    if not isinstance(raw, dict):
        return None
    # SNP/TDX providers expose the guest field under "report_data".
    value = raw.get("report_data")
    return value if isinstance(value, str) else None


def _verify_snp_signature_step(
    report: Any,
    snp_report_bytes: Optional[bytes],
    vcek_cert_der: Optional[bytes],
    cert_chain_pem: Optional[bytes],
    trusted_ark_der: Optional[bytes],
    reasons: list[str],
) -> SignatureStatus:
    """Run the AMD SEV-SNP signature + VCEK-chain check, if material is present.

    Returns ``VERIFIED`` only when the report signature and the VCEK<-ASK<-ARK
    chain both check out. Returns ``FAILED`` when material is supplied but does
    not verify, and ``NOT_IMPLEMENTED`` when no VCEK/chain was provided.
    """
    if vcek_cert_der is None or cert_chain_pem is None:
        reasons.append(
            "hardware signature not checked: no VCEK certificate / chain supplied"
        )
        return SignatureStatus.NOT_IMPLEMENTED

    # The raw SNP report bytes come from the explicit argument, else the
    # report's quote blob (SEVSNPProvider stows the raw report there).
    raw = snp_report_bytes
    if raw is None:
        raw = getattr(report, "quote", None)
    if not raw:
        reasons.append(
            "hardware signature not checked: no raw SNP report bytes on the report"
        )
        return SignatureStatus.NOT_IMPLEMENTED

    from ._snp_verify import (
        SnpVerificationError,
        parse_snp_report,
        verify_snp_signature,
        verify_vcek_chain,
    )

    try:
        parsed = parse_snp_report(raw)
        if not verify_snp_signature(parsed, vcek_cert_der):
            reasons.append("SNP report signature did not verify against the VCEK")
            return SignatureStatus.FAILED
        verify_vcek_chain(vcek_cert_der, cert_chain_pem, trusted_ark_der=trusted_ark_der)
    except SnpVerificationError as e:
        reasons.append(f"SNP certificate chain verification failed: {e}")
        return SignatureStatus.FAILED
    return SignatureStatus.VERIFIED


def _verify_tdx_signature_step(
    report: Any, reasons: list[str], trusted_tdx_root_pem: Optional[bytes] = None
) -> SignatureStatus:
    """Verify a self-contained Intel TDX DCAP quote (signature + PCK chain).

    The quote carries its own PCK certificate chain, so no external material is
    needed: the report's ``quote`` blob is verified against the pinned Intel SGX
    Root CA (or ``trusted_tdx_root_pem`` when supplied). Returns ``VERIFIED`` /
    ``FAILED`` / ``NOT_IMPLEMENTED`` (no quote).
    """
    quote = getattr(report, "quote", None)
    if not quote:
        reasons.append("hardware signature not checked: no TDX quote on the report")
        return SignatureStatus.NOT_IMPLEMENTED
    from ._tdx_verify import TdxVerificationError, verify_tdx_quote

    try:
        if verify_tdx_quote(quote, trusted_root_pem=trusted_tdx_root_pem):
            return SignatureStatus.VERIFIED
        reasons.append("TDX quote signature did not verify")
        return SignatureStatus.FAILED
    except TdxVerificationError as e:
        reasons.append(f"TDX quote verification failed: {e}")
        return SignatureStatus.FAILED


def verify_attestation_chain(
    report: Any,
    *,
    expected_manifest_hash: str,
    expected_measurements: Optional[set[str]] = None,
    snp_report_bytes: Optional[bytes] = None,
    vcek_cert_der: Optional[bytes] = None,
    cert_chain_pem: Optional[bytes] = None,
    trusted_ark_der: Optional[bytes] = None,
    trusted_tdx_root_pem: Optional[bytes] = None,
) -> ChainVerificationResult:
    """Verify a boot-time ``AttestationReport`` against expected values.

    Args:
        report: An ``AttestationReport`` from a hardware provider.
        expected_manifest_hash: The manifest hash the report must bind, in
            ``"sha256:<hex>"`` form.
        expected_measurements: Optional allow-list of acceptable launch
            measurements (hex). If ``None``, the measurement step is skipped
            (recorded as ``measurement_matched=None``) and does not gate the
            result; pass a set to enforce it.
        snp_report_bytes: Raw SEV-SNP attestation report (1184 bytes). If
            omitted, the report's ``quote`` attribute is used.
        vcek_cert_der: The VCEK leaf certificate (DER) for the report's chip and
            TCB. Supply this together with ``cert_chain_pem`` to have the
            hardware signature actually verified. Fetch via
            :func:`._snp_verify.fetch_vcek`, or read from the report aux blob.
        cert_chain_pem: The AMD KDS ``cert_chain`` blob (ASK then ARK, PEM).
        trusted_ark_der: Optional pinned AMD root (ARK) certificate. When given,
            the chain's ARK public key must match it.

    Returns:
        A :class:`ChainVerificationResult`. ``passed`` is ``True`` only when the
        hardware signature is ``VERIFIED``, the manifest-hash binding matches,
        and the measurement is accepted (or no allow-list was requested).
        Without VCEK material the signature step is not performed and the result
        cannot pass, because an unverified report proves nothing.
    """
    reasons: list[str] = []

    # Step 3: manifest-hash binding (software-checkable).
    expected_digest = expected_manifest_hash.split(":", 1)[-1].lower()
    actual_hex = _report_data_hex(report)
    if actual_hex is None:
        report_data_matched = False
        reasons.append("report has no 'report_data' field to check the manifest binding against")
    else:
        # The first 32 bytes (64 hex chars) of REPORT_DATA carry the digest.
        report_data_matched = hmac.compare_digest(actual_hex[:64].lower(), expected_digest)
        if not report_data_matched:
            reasons.append("manifest hash does not match the report_data binding")

    # Step 2: launch-measurement allow-list (software-checkable, optional).
    measurement_matched: Optional[bool]
    if expected_measurements is None:
        measurement_matched = None
        reasons.append("no measurement allow-list supplied; launch measurement not checked")
    else:
        raw = getattr(report, "raw", {}) or {}
        actual_measurement = raw.get("measurement") if isinstance(raw, dict) else None
        allow = {m.lower() for m in expected_measurements}
        measurement_matched = (
            isinstance(actual_measurement, str) and actual_measurement.lower() in allow
        )
        if not measurement_matched:
            reasons.append("launch measurement is not in the supplied allow-list")

    # Step 1: hardware signature / quote chain, dispatched by platform.
    # AMD SEV-SNP verifies the report signature + VCEK<-ASK<-ARK chain (needs the
    # VCEK material). Intel TDX verifies the self-contained DCAP quote + PCK chain
    # to the pinned Intel SGX Root CA. Either way, without a verifiable signature
    # the result cannot pass.
    platform = getattr(report, "platform", "") or ""
    if platform == "intel-tdx":
        signature = _verify_tdx_signature_step(report, reasons, trusted_tdx_root_pem)
    else:
        signature = _verify_snp_signature_step(
            report,
            snp_report_bytes,
            vcek_cert_der,
            cert_chain_pem,
            trusted_ark_der,
            reasons,
        )

    passed = (
        signature == SignatureStatus.VERIFIED
        and report_data_matched
        and measurement_matched is not False
    )

    return ChainVerificationResult(
        passed=passed,
        signature=signature,
        report_data_matched=report_data_matched,
        measurement_matched=measurement_matched,
        reasons=reasons,
    )


# Re-export the existing runtime freshness check so the verification surface
# lives in one place. (Defined in _verify.py to avoid a circular import.)
def verify_runtime_freshness(report: Any, nonce: bytes, context_hash: str) -> bool:
    """Thin alias for :func:`agent_manifest._verify.verify_runtime_report`.

    Confirms a RuntimeAttestationReport's ``report_data_hash`` derives from the
    given nonce and context hash (anti-replay). Does NOT verify the hardware
    signature on the quote blob; see :func:`verify_attestation_chain`.
    """
    from ._verify import verify_runtime_report

    return verify_runtime_report(report, nonce, context_hash)
