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
   ``AzureCVMProvider``, not this field. A ``platform`` value only selects
   which of the above applies as it never itself evidence that any of them
   ran. For Azure, this function takes the caller's already-authenticated
   result as the ``azure_manifest_binding_verified`` argument rather than
   inferring anything from the platform string.

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
from typing import Any


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

    For ``"azure-cvm-sev-snp"`` reports, ``report_data_matched`` reflects the
    caller-supplied ``azure_manifest_binding_verified`` argument to
    :func:`verify_attestation_chain`, not the ``report_data`` field itself
    (which does not carry the manifest hash on Azure). It is genuinely
    three-state here, the same discipline as ``measurement_matched``:
    ``True`` only from an authenticated caller-supplied ``True``; ``False``
    for an explicit caller-supplied ``False`` (checked, and failed --
    e.g. a wrong PCR); and ``None`` when nothing was supplied at all (never
    checked, so never established). ``None`` and ``False`` both gate
    ``passed`` identically -- neither is ever treated as a pass -- but they
    are represented as distinct values so a caller can tell "we checked and
    it was wrong" apart from "we never checked at all". Every other platform
    always reports a definite ``True``/``False`` here, never ``None``.
    """

    passed: bool
    signature: SignatureStatus
    report_data_matched: bool | None  # None only for azure-cvm-sev-snp "not established"
    measurement_matched: bool | None  # None = no allow-list supplied
    reasons: list[str] = field(default_factory=list)


def _report_data_hex(report: Any) -> str | None:
    """Return the hex of the guest-supplied report-data field, if present."""
    raw = getattr(report, "raw", None)
    if not isinstance(raw, dict):
        return None
    # SNP/TDX providers expose the guest field under "report_data".
    value = raw.get("report_data")
    return value if isinstance(value, str) else None


def _verify_snp_signature_step(
    report: Any,
    snp_report_bytes: bytes | None,
    vcek_cert_der: bytes | None,
    cert_chain_pem: bytes | None,
    trusted_ark_der: bytes | None,
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
    report: Any, reasons: list[str], trusted_tdx_root_pem: bytes | None = None
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


def _verify_tpm_signature_step(
    tpm_attest: bytes | None,
    tpm_signature: bytes | None,
    tpm_ak_chain_pem: bytes | None,
    tpm_trusted_roots_pem: bytes | None,
    expected_qualifying_data: bytes | None,
    expected_pcr_digest: bytes | None,
    reasons: list[str],
) -> SignatureStatus:
    """Verify a TPM 2.0 quote (AK chain + AK signature + bindings), if supplied.

    Requires the TPMS_ATTEST blob, its AK signature, the AK certificate chain,
    and the caller's trusted TPM roots (there is no single published TPM root).
    Returns ``VERIFIED`` / ``FAILED`` / ``NOT_IMPLEMENTED`` (material absent).
    """
    if not (tpm_attest and tpm_signature and tpm_ak_chain_pem and tpm_trusted_roots_pem):
        reasons.append(
            "hardware signature not checked: TPM attest/signature/AK-chain/"
            "trusted-roots not all supplied"
        )
        return SignatureStatus.NOT_IMPLEMENTED
    from ._tpm_verify import TpmVerificationError, verify_tpm_quote

    try:
        ok = verify_tpm_quote(
            tpm_attest,
            tpm_signature,
            tpm_ak_chain_pem,
            trusted_roots_pem=tpm_trusted_roots_pem,
            expected_qualifying_data=expected_qualifying_data,
            expected_pcr_digest=expected_pcr_digest,
        )
    except TpmVerificationError as e:
        reasons.append(f"TPM quote verification failed: {e}")
        return SignatureStatus.FAILED
    if ok:
        return SignatureStatus.VERIFIED
    reasons.append("TPM quote signature or binding did not verify")
    return SignatureStatus.FAILED


def verify_attestation_chain(
    report: Any,
    *,
    expected_manifest_hash: str,
    expected_measurements: set[str] | None = None,
    snp_report_bytes: bytes | None = None,
    vcek_cert_der: bytes | None = None,
    cert_chain_pem: bytes | None = None,
    trusted_ark_der: bytes | None = None,
    trusted_tdx_root_pem: bytes | None = None,
    tpm_attest: bytes | None = None,
    tpm_signature: bytes | None = None,
    tpm_ak_chain_pem: bytes | None = None,
    tpm_trusted_roots_pem: bytes | None = None,
    expected_qualifying_data: bytes | None = None,
    expected_pcr_digest: bytes | None = None,
    azure_manifest_binding_verified: bool | None = None,
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
        azure_manifest_binding_verified: For ``"azure-cvm-sev-snp"`` reports
            only. This function cannot itself check Azure's manifest binding
            (REPORT_DATA there is ``sha256(runtime_data)``, not the manifest
            hash — the actual binding is a vTPM AK-signed quote over a PCR
            derived from the manifest hash). Pass the caller's own
            authenticated result from
            ``AzureCVMProvider.verify_manifest_in_report(report, manifest)``
            here: ``True`` if that call verified the PCR/AK-quote binding for
            *this* manifest, ``False`` if it did not (wrong PCR, bad AK
            signature, etc). Leaving this ``None`` means the binding was
            never established -- reported as ``report_data_matched=None``,
            never treated as a pass, but distinct from an explicit ``False``.
            Ignored for every other platform.

    Returns:
        A :class:`ChainVerificationResult`. ``passed`` is ``True`` only when the
        hardware signature is ``VERIFIED``, the manifest-hash binding matches,
        and the measurement is accepted (or no allow-list was requested).
        Without VCEK material the signature step is not performed and the result
        cannot pass, because an unverified report proves nothing. An
        unrecognized ``report.platform`` value also cannot pass: the signature
        step is reported as ``NOT_IMPLEMENTED`` rather than falling through to
        a verifier for a different profile. For ``"azure-cvm-sev-snp"``
        reports, the manifest-hash binding step has three distinct outcomes:
        ``True`` only when ``azure_manifest_binding_verified=True`` was
        supplied (an authenticated result the caller obtained elsewhere);
        ``False`` for an explicit ``azure_manifest_binding_verified=False``
        (e.g. a wrong PCR); and ``None`` -- meaning "not established", never
        "assumed fine" -- when the caller supplied nothing at all. Both
        ``False`` and ``None`` are treated identically for gating ``passed``
        (neither ever passes); they are kept distinct only so a caller can
        tell "checked and failed" apart from "never checked". A
        ``platform`` value only selects which verification procedure applies;
        it is never itself evidence that the procedure ran.
    """
    reasons: list[str] = []
    platform = getattr(report, "platform", "") or ""

    # Step 3: manifest-hash binding (software-checkable).
    #
    # Does not apply on Azure via REPORT_DATA: the guest never controls that
    # field there (the paravisor sets it to sha256(runtime_data) to bind the
    # vTPM AK, not the manifest hash). Azure's real binding is a vTPM
    # AK-signed quote over a PCR derived from the manifest hash, established
    # by AzureCVMProvider.verify_manifest_in_report() -- outside this
    # function's own crypto boundary. So this step must never be set True
    # from the platform label alone: a `platform` value says which procedure
    # applies, it is not evidence that the procedure ran. It can only become
    # True from an authenticated result the caller actually obtained and
    # passed in via azure_manifest_binding_verified. No such result means
    # "not established" -- treated the same as a failed check, never as a
    # pass by default.
    azure_paravisor = platform == "azure-cvm-sev-snp"
    azure_paravisor = platform == "azure-cvm-sev-snp"
    if azure_paravisor:
        if azure_manifest_binding_verified is True:
            report_data_matched = True
            reasons.append(
                "Azure manifest binding confirmed by an authenticated result "
                "supplied by the caller (azure_manifest_binding_verified=True)"
            )
        elif azure_manifest_binding_verified is False:
            report_data_matched = False
            reasons.append(
                "Azure manifest binding check failed: caller supplied "
                "azure_manifest_binding_verified=False (e.g. wrong PCR "
                "or invalid AK-quote signature)"
            )
        else:
            report_data_matched = None
            reasons.append(
                "Azure manifest binding not established: no authenticated "
                "result was supplied via azure_manifest_binding_verified; "
                "report_data itself does not carry the manifest hash on "
                "Azure, so it cannot be checked directly -- run "
                "AzureCVMProvider.verify_manifest_in_report() and pass its "
                "result in"
            )
    else:
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
    measurement_matched: bool | None
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
    # AMD SEV-SNP (bare-metal and Azure's paravisor variant, which carries a
    # real SNP report too) verifies the report signature + VCEK<-ASK<-ARK
    # chain (needs the VCEK material). Intel TDX verifies the self-contained
    # DCAP quote + PCK chain to the pinned Intel SGX Root CA. TPM/AWS Nitro
    # verify an AK-signed quote. Dispatch is an explicit allow-list, not a
    # catch-all: an unrecognized platform label must fail closed rather than
    # silently inherit a verifier meant for a different profile.
    if platform == "intel-tdx":
        signature = _verify_tdx_signature_step(report, reasons, trusted_tdx_root_pem)
    elif platform in ("tpm", "aws-nitro"):
        signature = _verify_tpm_signature_step(
            tpm_attest,
            tpm_signature,
            tpm_ak_chain_pem,
            tpm_trusted_roots_pem,
            expected_qualifying_data,
            expected_pcr_digest,
            reasons,
        )
    elif platform in ("amd-sev-snp", "azure-cvm-sev-snp"):
        signature = _verify_snp_signature_step(
            report,
            snp_report_bytes,
            vcek_cert_der,
            cert_chain_pem,
            trusted_ark_der,
            reasons,
        )
    else:
        signature = SignatureStatus.NOT_IMPLEMENTED
        reasons.append(f"platform {platform!r} is not a supported attestation profile")

    passed = bool(
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
