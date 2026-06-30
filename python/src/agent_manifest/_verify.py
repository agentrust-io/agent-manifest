"""Agent Manifest verification engine and FastAPI endpoint.

Two hosting modes (spec Section 5.1 / SPEC-07):
  SDK-hosted:    FastAPI server embedded in the agent process, served over
                 mTLS using the agent's SPIFFE SVID.  Runtime artifact hashes
                 are computed by the trusted component that holds the manifest.
  OPAQUE-hosted: Results are served from hashes pushed by the agent SDK at
                 startup to OPAQUE's attestation service.

The verification engine itself is hosting-agnostic - it takes a Manifest
dict and a set of running artifact hashes and produces a VerificationResult.
The FastAPI router wires the engine to HTTP.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class OverallResult(str, Enum):
    VALID = "VALID"
    MISMATCH = "MISMATCH"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INCOMPLETE = "INCOMPLETE"
    ATTESTATION_UNAVAILABLE = "ATTESTATION_UNAVAILABLE"
    INCOMPATIBLE_VERSION = "INCOMPATIBLE_VERSION"
    # Fail-closed statuses (spec 5.3: VALID requires a valid signature):
    # SIGNATURE_MISSING - the manifest carries no signature block at all.
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    # UNVERIFIABLE - a signature or delegation chain is present but the
    # verifier lacks the key material to verify it. MUST NOT be treated
    # as VALID by relying parties.
    UNVERIFIABLE = "UNVERIFIABLE"


class FieldResult(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_BOUND = "NOT_BOUND"
    EXPIRED = "EXPIRED"


class DelegationResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_PRESENT = "NOT_PRESENT"
    # Chain present but the verifier lacks the public keys (or constraint
    # evaluation capability) to verify it - spec 3.4.1 / 5.2.
    UNVERIFIABLE = "UNVERIFIABLE"


class HitlResult(str, Enum):
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    NOT_REQUIRED = "NOT_REQUIRED"
    MISSING = "MISSING"
    APPROVAL_INSUFFICIENT = "APPROVAL_INSUFFICIENT"


class MismatchDetail(BaseModel):
    field: str
    expected_hash: str
    actual_hash: str
    delta_detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FieldsVerified(BaseModel):
    system_prompt: FieldResult = FieldResult.NOT_BOUND
    policy_bundle: FieldResult = FieldResult.NOT_BOUND
    tool_manifest: FieldResult = FieldResult.NOT_BOUND
    model_identity: FieldResult = FieldResult.NOT_BOUND
    rag_corpus: FieldResult = FieldResult.NOT_BOUND
    memory_baseline: FieldResult = FieldResult.NOT_BOUND
    decision_trace: FieldResult = FieldResult.NOT_BOUND
    supply_chain: FieldResult = FieldResult.NOT_BOUND
    delegation_chain: DelegationResult = DelegationResult.NOT_PRESENT
    hitl_record: HitlResult = HitlResult.NOT_REQUIRED


class EvidencePack(BaseModel):
    trace_id: Optional[str] = None
    signed_by: Optional[str] = None
    pack_hash: Optional[str] = None
    pack_uri: Optional[str] = None


class VerificationResult(BaseModel):
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    manifest_id: str
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    result: OverallResult
    signature_verified: bool = False
    attestation_verified: bool = False
    fields_verified: FieldsVerified = Field(default_factory=FieldsVerified)
    mismatch_details: list[MismatchDetail] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence_pack: Optional[EvidencePack] = None
    verification_signature: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response schema (Schema F-13 fix - closes spec gap)."""

    error_code: str
    error_message: str
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    retry_after_seconds: Optional[int] = None


class RevocationRecord(BaseModel):
    manifest_id: str
    revoked_at: datetime
    reason: str
    revoked_by: str


class VerifyRequest(BaseModel):
    """Request body for ``POST /verify``.

    ``trusted_keys`` maps key_id (sha256 hex of the raw public key bytes) to
    the base64url-encoded public key. Signature verification is fail-closed:
    without trusted keys, a signed manifest yields ``UNVERIFIABLE`` and an
    unsigned manifest yields ``SIGNATURE_MISSING`` - never ``VALID``.
    """

    manifest_id: str
    enforce_hitl: bool = False
    enforce_attestation: bool = False
    # key_id (sha256 hex of pub key bytes) -> base64url-encoded public key bytes
    trusted_keys: dict[str, str] = Field(default_factory=dict)
    # principal_id -> base64url-encoded public key bytes (for delegation chain)
    delegation_public_keys: dict[str, str] = Field(default_factory=dict)
    # When True, a manifest without a delegation_chain is a verification failure
    require_delegation: bool = False


# ---------------------------------------------------------------------------
# Verification engine
# ---------------------------------------------------------------------------


class VerificationContext(BaseModel):
    """Runtime artifact hashes and keys provided by the trusted component."""

    system_prompt_hash: Optional[str] = None
    policy_bundle_hash: Optional[str] = None
    tool_catalog_hash: Optional[str] = None
    model_version: Optional[str] = None
    rag_corpus_merkle_root: Optional[str] = None
    memory_snapshot_hash: Optional[str] = None
    audit_chain_root: Optional[str] = None
    container_image_digest: Optional[str] = None
    enforce_hitl: bool = False
    enforce_attestation: bool = False
    min_slsa_level: int = 0
    # key_id (sha256 hex of pub key bytes) -> base64url-encoded public key bytes
    trusted_keys: dict[str, str] = Field(default_factory=dict)
    # principal_id -> base64url-encoded public key bytes (for delegation chain)
    delegation_public_keys: dict[str, str] = Field(default_factory=dict)
    # When True, bound artifacts without runtime hashes cause INCOMPLETE result
    strict_artifact_verification: bool = False
    # When True, manifest must have a delegation chain
    require_delegation: bool = False
    # Conformance level for enforcing spec §3.2.5.1 poisoning_scan rules.
    # Level 0: not-scanned is permitted (warning only).
    # Level 1+: not-scanned is a verification failure.
    conformance_level: int = 0


# Manifest spec versions this verifier implementation can process (spec 2.4).
SUPPORTED_MANIFEST_VERSIONS: frozenset[str] = frozenset({"0.1"})


def _strict_schema_violations(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    """Run the manifest through the Pydantic schema and return fail-closed errors.

    Returns a list of (location, message) tuples for every validation error
    that is NOT a tolerated "missing required field" error. An empty list
    means the manifest carries no disqualifying schema violation.

    Tolerated: ``missing`` errors only. Disqualifying: unknown fields
    (``extra_forbidden``), type errors, bad enums, unparseable or
    out-of-window timestamps, and any ``value_error`` raised by a model
    validator (e.g. the expiry-window rule).
    """
    from pydantic import ValidationError

    from .models import Manifest

    # An empty delegation_chain means "no delegation"; the engine already
    # normalizes it to absent (``manifest.get("delegation_chain") or []``).
    # The schema models it as ``min_length=1`` (omit when empty), so drop an
    # empty/None chain before validating to avoid flagging the benign idiom.
    if not manifest.get("delegation_chain"):
        manifest = {k: v for k, v in manifest.items() if k != "delegation_chain"}

    try:
        Manifest.model_validate(manifest)
    except ValidationError as exc:
        violations: list[tuple[str, str]] = []
        for err in exc.errors():
            if err.get("type") == "missing":
                continue
            loc = ".".join(str(p) for p in err.get("loc", ()))
            violations.append((loc, err.get("msg", "schema error")))
        return violations
    return []


def verify_manifest(
    manifest: dict[str, Any],
    context: VerificationContext,
    revocation_store: "RevocationStore",
) -> VerificationResult:
    """Core verification engine - hosting-model agnostic and fail-closed.

    Checks version compatibility, signature, expiry, revocation, artifact
    hashes, delegation chain, and HITL. Returns a VerificationResult with
    per-field status and mismatch details.

    Fail-closed semantics (spec 5.3 - VALID requires a valid signature):

    - A manifest with an unsupported (or missing) ``version`` returns
      ``INCOMPATIBLE_VERSION`` without further processing (spec 2.4).
    - A manifest without a ``signature`` block returns ``SIGNATURE_MISSING``.
    - A signed manifest verified without any ``trusted_keys`` in the context
      returns ``UNVERIFIABLE`` - never ``VALID``.
    - A delegation chain that cannot be verified (no
      ``delegation_public_keys``) is marked ``UNVERIFIABLE`` and the overall
      result is ``UNVERIFIABLE`` (spec 3.4.1 / 5.2).
    - ``enforce_hitl=True`` with no ``hitl_record`` in the manifest is a
      failure (``HitlResult.MISSING`` and a non-VALID overall result).
    """
    from cryptography.exceptions import InvalidSignature

    manifest_id = manifest.get("manifest_id", "unknown")
    result = VerificationResult(manifest_id=manifest_id, result=OverallResult.VALID)
    mismatches: list[MismatchDetail] = []
    fields = result.fields_verified

    # --- Schema validation (fail-closed). verify_manifest accepts a raw dict,
    # so it must run the manifest through the Pydantic guards before trusting
    # any field. This makes extra="forbid" (unknown fields), enum/type
    # constraints, the expiry window, and timestamp parsing actually apply on
    # the verify path. A malformed expires_at is a schema failure here, not a
    # silently non-expiring manifest.
    #
    # Only pure "missing required field" errors are tolerated: the engine
    # treats absent artifact bindings and metadata as NOT_BOUND and degrades
    # safely, and requiring every business field would reject otherwise
    # well-formed manifests the engine can still evaluate. Every other class of
    # error (unknown field, wrong type, bad enum, unparseable/out-of-window
    # timestamp, or any value_error from a model validator) fails closed.
    schema_violations = _strict_schema_violations(manifest)
    if schema_violations:
        result.result = OverallResult.MISMATCH
        for loc, msg in schema_violations:
            mismatches.append(MismatchDetail(
                field=f"schema:{loc}" if loc else "schema",
                expected_hash="<schema-valid manifest>",
                actual_hash=f"<{msg}>",
            ))
        result.mismatch_details = mismatches
        return result

    # --- Version negotiation (spec 2.2 / 2.4) - MUST be checked before
    # verifying so unsupported manifests are never silently misinterpreted.
    version = manifest.get("version")
    if version not in SUPPORTED_MANIFEST_VERSIONS:
        result.result = OverallResult.INCOMPATIBLE_VERSION
        return result

    # --- Revocation check (must happen before VALID can be returned)
    if revocation_store.is_revoked(manifest_id):
        result.result = OverallResult.REVOKED
        return result

    # --- Expiry check
    expires_at = manifest.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp < datetime.now(timezone.utc):
                result.result = OverallResult.EXPIRED
                return result
        except (ValueError, AttributeError):
            pass

    # --- Signature verification (CRYPTO-004, fail-closed per spec 5.3)
    sig_block = manifest.get("signature") or {}
    signature_missing = not sig_block
    if sig_block and context.trusted_keys:
        algorithm = sig_block.get("algorithm", "Ed25519")
        key_id = sig_block.get("key_id", "")
        pub_b64 = context.trusted_keys.get(key_id)
        if pub_b64 is None:
            mismatches.append(MismatchDetail(
                field="signature",
                expected_hash=f"<key_id={key_id} in trusted_keys>",
                actual_hash="<key_id not found in trusted_keys>",
            ))
        else:
            from ._signing import (
                Ed25519Verifier,
                MlDsa65Verifier,
                HybridVerifier,
                _b64url_decode,
            )
            try:
                pub_bytes = _b64url_decode(pub_b64)
                if algorithm == "Ed25519":
                    Ed25519Verifier(pub_bytes).verify(manifest, sig_block.get("signature_value", ""))
                    result.signature_verified = True
                elif algorithm == "ML-DSA-65":
                    MlDsa65Verifier(pub_bytes).verify(manifest, sig_block.get("signature_value", ""))
                    result.signature_verified = True
                elif algorithm == "hybrid-Ed25519-ML-DSA-65":
                    # Hybrid needs both key components - key_id covers combined hash;
                    # callers must pass both keys in trusted_keys under their individual key_ids.
                    ed_key_id = sig_block.get("ed25519_key_id", key_id)
                    pq_key_id = sig_block.get("ml_dsa65_key_id", key_id)
                    ed_pub_b64 = context.trusted_keys.get(ed_key_id, pub_b64)
                    pq_pub_b64 = context.trusted_keys.get(pq_key_id, pub_b64)
                    ed_bytes = _b64url_decode(ed_pub_b64)
                    pq_bytes = _b64url_decode(pq_pub_b64)
                    HybridVerifier(ed_bytes, pq_bytes).verify(manifest, sig_block)
                    result.signature_verified = True
                else:
                    mismatches.append(MismatchDetail(
                        field="signature",
                        expected_hash="<known algorithm: Ed25519|ML-DSA-65|hybrid-Ed25519-ML-DSA-65>",
                        actual_hash=f"<unknown algorithm: {algorithm!r}>",
                    ))
            except InvalidSignature:
                mismatches.append(MismatchDetail(
                    field="signature",
                    expected_hash="<valid signature>",
                    actual_hash="<invalid signature>",
                ))
            except ValueError as e:
                mismatches.append(MismatchDetail(
                    field="signature",
                    expected_hash="<valid signature>",
                    actual_hash=f"<malformed: {e}>",
                ))

    # --- Artifact hash verification
    artifacts = manifest.get("artifacts") or {}
    unverified_bound: list[str] = []  # bound artifacts with no runtime hash (VERIFY-001)

    def _check(field_name: str, manifest_val: Optional[str], runtime_val: Optional[str]) -> FieldResult:
        if manifest_val is None:
            return FieldResult.NOT_BOUND
        if runtime_val is None:
            unverified_bound.append(field_name)
            return FieldResult.NOT_BOUND
        # Constant-time comparison to prevent timing side-channels (CRYPTO-002)
        if hmac.compare_digest(manifest_val, runtime_val):
            return FieldResult.MATCH
        mismatches.append(MismatchDetail(
            field=field_name,
            expected_hash=manifest_val,
            actual_hash=runtime_val,
        ))
        return FieldResult.MISMATCH

    sp = artifacts.get("system_prompt") or {}
    fields.system_prompt = _check(
        "system_prompt",
        sp.get("hash"),
        context.system_prompt_hash,
    )

    pb = artifacts.get("policy_bundle") or {}
    fields.policy_bundle = _check(
        "policy_bundle",
        pb.get("hash"),
        context.policy_bundle_hash,
    )

    tm = artifacts.get("tool_manifest") or {}
    fields.tool_manifest = _check(
        "tool_manifest",
        tm.get("catalog_hash"),
        context.tool_catalog_hash,
    )

    mi = artifacts.get("model_identity") or {}
    # For api-deployed models, bind by version string, not binary hash
    mi_bound = mi.get("model_hash") or mi.get("version")
    fields.model_identity = _check(
        "model_identity",
        mi_bound,
        context.model_version,
    )

    rc = artifacts.get("rag_corpus") or {}
    fields.rag_corpus = _check(
        "rag_corpus",
        rc.get("merkle_root"),
        context.rag_corpus_merkle_root,
    )

    # --- Poisoning scan rules (spec §3.2.5.1)
    poisoning_scan = rc.get("poisoning_scan") or {}
    poisoning_result = poisoning_scan.get("result")
    if poisoning_result == "flagged":
        mismatches.append(MismatchDetail(
            field="rag_corpus.poisoning_scan",
            expected_hash="<result: clean or not-scanned>",
            actual_hash="<result: flagged>",
        ))
    elif poisoning_result == "not-scanned":
        if context.conformance_level >= 1:
            mismatches.append(MismatchDetail(
                field="rag_corpus.poisoning_scan",
                expected_hash="<result: clean>",
                actual_hash="<result: not-scanned>",
            ))
        else:
            result.warnings.append(
                "rag_corpus.poisoning_scan.result is 'not-scanned'; scan before Level 1 conformance"
            )

    mb = artifacts.get("memory_baseline") or {}
    if mb:
        from datetime import timedelta
        # Check TTL expiry for memory baseline
        ttl = mb.get("ttl_seconds")
        approved_at = mb.get("approved_at")
        baseline_expired = False
        if ttl and approved_at:
            try:
                approved = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > approved + timedelta(seconds=ttl):
                    baseline_expired = True
            except (ValueError, AttributeError):
                pass
        if baseline_expired:
            fields.memory_baseline = FieldResult.EXPIRED
        else:
            fields.memory_baseline = _check(
                "memory_baseline",
                mb.get("snapshot_hash"),
                context.memory_snapshot_hash,
            )

    dt = artifacts.get("decision_trace") or {}
    fields.decision_trace = _check(
        "decision_trace",
        dt.get("audit_chain_root"),
        context.audit_chain_root,
    )

    sc = artifacts.get("supply_chain") or {}
    fields.supply_chain = _check(
        "supply_chain",
        sc.get("container_image_digest"),
        context.container_image_digest,
    )

    # --- Delegation chain (VERIFY-002)
    chain = manifest.get("delegation_chain") or []
    if chain:
        if context.delegation_public_keys:
            try:
                from ._delegation import verify_delegation_chain
                from ._signing import _b64url_decode
                pub_keys = {
                    pid: _b64url_decode(b64)
                    for pid, b64 in context.delegation_public_keys.items()
                }
                # Bind the chain root to the manifest signing identity so a
                # valid chain cannot be grafted onto an unrelated manifest.
                manifest_issuer = manifest.get("issuer") or manifest.get("agent_id")
                verify_delegation_chain(
                    chain, pub_keys, manifest_id, manifest_issuer=manifest_issuer
                )
                fields.delegation_chain = DelegationResult.VALID
            except (InvalidSignature, ValueError) as e:
                fields.delegation_chain = DelegationResult.INVALID
                mismatches.append(MismatchDetail(
                    field="delegation_chain",
                    expected_hash="<valid chain>",
                    actual_hash=f"<invalid: {e}>",
                ))
        else:
            # No public keys provided - the chain cannot be verified.
            # Fail closed: surface UNVERIFIABLE rather than VALID (spec 3.4.1 / 5.2).
            fields.delegation_chain = DelegationResult.UNVERIFIABLE
    else:
        fields.delegation_chain = DelegationResult.NOT_PRESENT
        if context.require_delegation:
            mismatches.append(MismatchDetail(
                field="delegation_chain",
                expected_hash="<delegation chain present>",
                actual_hash="<delegation chain absent>",
            ))

    # --- HITL
    hitl = manifest.get("hitl_record")
    if hitl and isinstance(hitl, dict):
        required = hitl.get("required", False)
        approvals = hitl.get("approvals") or []
        if not required and not context.enforce_hitl:
            fields.hitl_record = HitlResult.NOT_REQUIRED
        elif not approvals:
            if context.enforce_hitl:
                mismatches.append(MismatchDetail(
                    field="hitl_record",
                    expected_hash="<approval present>",
                    actual_hash="<none>",
                ))
            fields.hitl_record = HitlResult.MISSING
        else:
            # Check if any approval has expired (HITL-001: parse failure must set all_ok=False)
            now = datetime.now(timezone.utc)
            all_ok = True
            for approval in approvals:
                approved_at = approval.get("approved_at", "")
                duration = approval.get("approved_scope", {}).get("approval_duration_seconds", 0)
                try:
                    ap_time = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
                    from datetime import timedelta
                    if now > ap_time + timedelta(seconds=duration):
                        all_ok = False
                        break
                except (ValueError, AttributeError):
                    # Unparseable timestamp - treat as expired to fail safe (HITL-001)
                    all_ok = False
                    break
            if not all_ok:
                # Expired approvals always add to mismatches regardless of enforce_hitl (HITL-002)
                mismatches.append(MismatchDetail(
                    field="hitl_record",
                    expected_hash="<valid unexpired approval>",
                    actual_hash="<approval expired or unparseable>",
                ))
            fields.hitl_record = HitlResult.APPROVED if all_ok else HitlResult.EXPIRED
    elif context.enforce_hitl:
        # enforce_hitl with no hitl_record at all - fail closed. Omitting the
        # record entirely MUST NOT be weaker than declaring it with no approvals.
        fields.hitl_record = HitlResult.MISSING
        mismatches.append(MismatchDetail(
            field="hitl_record",
            expected_hash="<hitl_record with valid approval>",
            actual_hash="<hitl_record absent>",
        ))

    # --- Attestation block verification (HW-010)
    # Check that manifest_hash_in_report matches the computed manifest hash.
    attestation_block = manifest.get("attestation") or {}
    if attestation_block:
        reported_hash = attestation_block.get("manifest_hash_in_report", "")
        if reported_hash:
            from ._canonicalize import canonicalize as _canonicalize
            import hashlib as _hashlib
            # Spec 3.3: the pre-image excludes the attestation block AND the
            # top-level transparency_log_entry (populated after log submission).
            subset = {
                k: v
                for k, v in manifest.items()
                if k not in ("attestation", "transparency_log_entry")
            }
            expected_attest_hash = "sha256:" + _hashlib.sha256(_canonicalize(subset)).hexdigest()
            if hmac.compare_digest(reported_hash, expected_attest_hash):
                result.attestation_verified = True
            elif context.enforce_attestation:
                mismatches.append(MismatchDetail(
                    field="attestation",
                    expected_hash=expected_attest_hash,
                    actual_hash=reported_hash,
                ))

    # --- Final result (fail-closed: VALID requires a verified signature and
    # a verifiable delegation chain - spec 5.3)
    result.mismatch_details = mismatches
    if mismatches:
        result.result = OverallResult.MISMATCH
    elif signature_missing:
        result.result = OverallResult.SIGNATURE_MISSING
    elif not result.signature_verified:
        # Signature present but no trusted keys (or verification never ran) -
        # the manifest cannot be authenticated. Never VALID.
        result.result = OverallResult.UNVERIFIABLE
    elif fields.delegation_chain == DelegationResult.UNVERIFIABLE:
        result.result = OverallResult.UNVERIFIABLE
    elif OverallResult.VALID == result.result:
        # VERIFY-001: bound artifacts with no runtime hashes in strict mode
        if context.strict_artifact_verification and unverified_bound:
            result.result = OverallResult.INCOMPLETE
        elif context.enforce_attestation and not result.attestation_verified:
            result.result = OverallResult.ATTESTATION_UNAVAILABLE

    # Surface bound-but-unchecked artifacts even in non-strict mode so callers
    # never read a VALID result as proof that artifact bindings were checked.
    # A signature-only VALID means the manifest is authentic, not that the
    # running artifacts match what it bound (VERIFY-001).
    if unverified_bound:
        result.warnings.append(
            "artifact bindings NOT verified (no runtime hashes provided for "
            + ", ".join(sorted(unverified_bound))
            + "); VALID reflects signature only"
        )

    return result


# ---------------------------------------------------------------------------
# Runtime attestation verification
# ---------------------------------------------------------------------------


def verify_runtime_report(
    report: Any,
    nonce: bytes,
    context_hash: str,
) -> bool:
    """Check the software-verifiable consistency of a RuntimeAttestationReport.

    Verifies that ``report.report_data_hash`` equals the expected derivation:
        sha256(sha256(nonce || bytes.fromhex(context_hash_hex)))

    This proves the report was produced for *this* nonce and *this* context_hash
    — i.e., it is not a replay of an older report. It does NOT verify the
    hardware signature on the underlying TEE quote blob; for that, use the
    platform vendor SDK (amd sev-snp-verify, Intel TDX Attest SDK,
    tpm2_checkquote) against ``report.quote``.

    Args:
        report:       RuntimeAttestationReport returned by attest_runtime_state().
        nonce:        The freshness token you supplied to attest_runtime_state().
        context_hash: The context hash you supplied to attest_runtime_state(),
                      in "sha256:<hex>" format.

    Returns:
        True if the report_data_hash is consistent with the nonce and context.
    """
    from ._providers import RuntimeAttestationReport as _RRT
    if not isinstance(report, _RRT):
        raise TypeError(f"expected RuntimeAttestationReport, got {type(report).__name__}")

    ctx_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
    qualifying = hashlib.sha256(nonce + ctx_bytes).digest()
    expected = "sha256:" + hashlib.sha256(qualifying).hexdigest()
    return hmac.compare_digest(report.report_data_hash, expected)


# ---------------------------------------------------------------------------
# Revocation store
# ---------------------------------------------------------------------------


class RevocationStore:
    """In-memory revocation store. Production should use a persistent backend."""

    def __init__(self) -> None:
        self._revoked: dict[str, RevocationRecord] = {}

    def revoke(self, record: RevocationRecord) -> None:
        self._revoked[record.manifest_id] = record

    def is_revoked(self, manifest_id: str) -> bool:
        return manifest_id in self._revoked

    def get_record(self, manifest_id: str) -> Optional[RevocationRecord]:
        return self._revoked.get(manifest_id)


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------


def create_router(
    manifest_store: dict[str, dict[str, Any]],
    revocation_store: RevocationStore,
) -> Any:
    """Return a FastAPI APIRouter with /verify and /revocation-status endpoints.

    Args:
        manifest_store: Dict mapping manifest_id -> manifest dict.
        revocation_store: Revocation store instance.
    """
    try:
        from fastapi import APIRouter, HTTPException, Query
        from fastapi.responses import JSONResponse  # noqa: F401
    except ImportError:
        raise ImportError(
            "FastAPI is required for the verification endpoint. "
            'Install with: pip install "agent-manifest[server]"'
        )

    router = APIRouter()

    def _lookup_manifest(manifest_id: str) -> dict[str, Any]:
        """Validate manifest_id format and fetch the manifest or raise."""
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message="manifest_id must be a UUID v7",
                ).model_dump(),
            )

        manifest = manifest_store.get(manifest_id)
        if manifest is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="MANIFEST_NOT_FOUND",
                    error_message="The requested manifest was not found.",
                ).model_dump(),
            )
        return manifest

    @router.get("/verify", response_model=VerificationResult)
    async def verify(
        manifest_id: str = Query(..., description="UUID v7 manifest identifier"),
        enforce_hitl: bool = Query(False),
        enforce_attestation: bool = Query(False),
    ) -> VerificationResult:
        """Verify a manifest without caller-supplied key material.

        This endpoint cannot receive trusted keys, so signature verification
        is fail-closed: a signed manifest returns ``UNVERIFIABLE`` and an
        unsigned manifest returns ``SIGNATURE_MISSING`` - never ``VALID``.
        Callers that hold the issuer's public keys MUST use ``POST /verify``
        and supply ``trusted_keys`` to obtain a ``VALID`` result.
        """
        manifest = _lookup_manifest(manifest_id)
        ctx = VerificationContext(
            enforce_hitl=enforce_hitl,
            enforce_attestation=enforce_attestation,
        )
        return verify_manifest(manifest, ctx, revocation_store)

    @router.post("/verify", response_model=VerificationResult)
    async def verify_post(request: VerifyRequest) -> VerificationResult:
        """Verify a manifest with caller-supplied trusted keys.

        The request body carries ``trusted_keys`` (key_id -> base64url public
        key) used for manifest signature verification, and optionally
        ``delegation_public_keys`` (principal_id -> base64url public key) for
        delegation chain verification. Verification is fail-closed - see
        :func:`verify_manifest`.
        """
        manifest = _lookup_manifest(request.manifest_id)
        ctx = VerificationContext(
            enforce_hitl=request.enforce_hitl,
            enforce_attestation=request.enforce_attestation,
            trusted_keys=request.trusted_keys,
            delegation_public_keys=request.delegation_public_keys,
            require_delegation=request.require_delegation,
        )
        return verify_manifest(manifest, ctx, revocation_store)

    @router.get("/revocation-status")
    async def revocation_status(
        manifest_id: str = Query(...),
    ) -> RevocationRecord:
        # Validate manifest_id to prevent log injection (INJ-005/SEC-009)
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message="manifest_id must be a UUID v7",
                ).model_dump(),
            )
        record = revocation_store.get_record(manifest_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="NOT_REVOKED",
                    error_message="The requested manifest has no revocation record.",
                ).model_dump(),
            )
        return record

    return router
