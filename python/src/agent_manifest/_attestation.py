"""Attestation-chain verification for boot-time attestation reports (issue #204).

EXPERIMENTAL — the hardware signature step is NOT implemented yet.

A boot-time ``AttestationReport`` is only trustworthy to a third party once a
verifier has checked three things:

1. **Signature / quote chain** — the report is signed by genuine platform
   hardware (AMD SEV-SNP: VCEK chain from AMD KDS; Intel TDX: a Quote verified
   via Intel QVL/PCS; TPM: AK cert + ``tpm2_checkquote``). This requires
   platform vendor libraries and real-hardware test vectors and is **not
   implemented here** — see :data:`SignatureStatus.NOT_IMPLEMENTED`.
2. **Launch measurement** — ``MEASUREMENT`` / ``MRTD`` / PCRs match a known-good
   value (or an allow-list of accepted measurements). Implemented below.
3. **Bound field** — the guest-supplied ``REPORT_DATA`` carries the expected
   manifest hash. Implemented below.

Because step 1 is unimplemented, :func:`verify_attestation_chain` **fails
closed**: ``passed`` is never ``True`` today. The per-step results are still
returned so callers (and tests) can confirm the software-checkable steps, and
so the remaining work is a drop-in: implement the signature backends and the
overall verdict starts passing. See #204 for the phased plan.
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
    NOT_IMPLEMENTED = "not_implemented"  # vendor-library work tracked in #204


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


def verify_attestation_chain(
    report: Any,
    *,
    expected_manifest_hash: str,
    expected_measurements: Optional[set[str]] = None,
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

    Returns:
        A :class:`ChainVerificationResult`. ``passed`` is ``False`` until the
        hardware signature backends are implemented (#204), regardless of the
        software checks, because an unverified report proves nothing.
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

    # Step 1: hardware signature / quote chain (NOT IMPLEMENTED — fails closed).
    signature = SignatureStatus.NOT_IMPLEMENTED
    reasons.append(
        "hardware signature/quote verification is not implemented; full "
        "verification fails closed until vendor backends land (#204)"
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
