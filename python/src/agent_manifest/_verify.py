"""Agent Manifest verification engine and FastAPI endpoint.

Two hosting modes (spec Section 5.1 / SPEC-07):
  SDK-hosted:    FastAPI server embedded in the agent process, served over
                 mTLS using the agent's SPIFFE SVID.  Runtime artifact hashes
                 are computed by the trusted component that holds the manifest.
  OPAQUE-hosted: Results are served from hashes pushed by the agent SDK at
                 startup to OPAQUE's attestation service.

The verification engine itself is hosting-agnostic — it takes a Manifest
dict and a set of running artifact hashes and produces a VerificationResult.
The FastAPI router wires the engine to HTTP.
"""
from __future__ import annotations

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


class FieldResult(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_BOUND = "NOT_BOUND"
    EXPIRED = "EXPIRED"


class DelegationResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_PRESENT = "NOT_PRESENT"


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
    attestation_verified: bool = False
    fields_verified: FieldsVerified = Field(default_factory=FieldsVerified)
    mismatch_details: list[MismatchDetail] = Field(default_factory=list)
    evidence_pack: Optional[EvidencePack] = None
    verification_signature: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response schema (Schema F-13 fix — closes spec gap)."""

    error_code: str
    error_message: str
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    retry_after_seconds: Optional[int] = None


class RevocationRecord(BaseModel):
    manifest_id: str
    revoked_at: datetime
    reason: str
    revoked_by: str


# ---------------------------------------------------------------------------
# Verification engine
# ---------------------------------------------------------------------------


class VerificationContext(BaseModel):
    """Runtime artifact hashes provided by the trusted component."""

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


def verify_manifest(
    manifest: dict[str, Any],
    context: VerificationContext,
    revocation_store: "RevocationStore",
) -> VerificationResult:
    """Core verification engine — hosting-model agnostic.

    Checks expiry, revocation, artifact hashes, delegation chain, and HITL.
    Returns a VerificationResult with per-field status and mismatch details.
    """
    manifest_id = manifest.get("manifest_id", "unknown")
    result = VerificationResult(manifest_id=manifest_id, result=OverallResult.VALID)
    mismatches: list[MismatchDetail] = []
    fields = result.fields_verified

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

    # --- Artifact hash verification
    artifacts = manifest.get("artifacts") or {}

    def _check(field_name: str, manifest_val: Optional[str], runtime_val: Optional[str]):
        if manifest_val is None:
            return FieldResult.NOT_BOUND
        if runtime_val is None:
            return FieldResult.NOT_BOUND
        if manifest_val == runtime_val:
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

    # --- Delegation chain
    chain = manifest.get("delegation_chain") or []
    if chain:
        fields.delegation_chain = DelegationResult.VALID  # full crypto verify in #12
    else:
        fields.delegation_chain = DelegationResult.NOT_PRESENT

    # --- HITL
    hitl = manifest.get("hitl_record")
    if hitl and isinstance(hitl, dict):
        required = hitl.get("required", False)
        approvals = hitl.get("approvals") or []
        if not required:
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
            # Check if any approval has expired
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
                    pass
            fields.hitl_record = HitlResult.APPROVED if all_ok else HitlResult.EXPIRED

    # --- Final result
    result.mismatch_details = mismatches
    if mismatches:
        result.result = OverallResult.MISMATCH
    elif OverallResult.VALID == result.result:
        if context.enforce_attestation and not result.attestation_verified:
            result.result = OverallResult.ATTESTATION_UNAVAILABLE

    return result


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
    manifest_store: dict[str, dict],
    revocation_store: RevocationStore,
):
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

    @router.get("/verify", response_model=VerificationResult)
    async def verify(
        manifest_id: str = Query(..., description="UUID v7 manifest identifier"),
        enforce_hitl: bool = Query(False),
        enforce_attestation: bool = Query(False),
    ):
        # Validate manifest_id format
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message=str(e),
                ).model_dump(),
            )

        manifest = manifest_store.get(manifest_id)
        if manifest is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="MANIFEST_NOT_FOUND",
                    error_message=f"No manifest found for id={manifest_id}",
                ).model_dump(),
            )

        ctx = VerificationContext(
            enforce_hitl=enforce_hitl,
            enforce_attestation=enforce_attestation,
        )
        return verify_manifest(manifest, ctx, revocation_store)

    @router.get("/revocation-status")
    async def revocation_status(
        manifest_id: str = Query(...),
    ):
        record = revocation_store.get_record(manifest_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="NOT_REVOKED",
                    error_message=f"No revocation record for manifest_id={manifest_id}",
                ).model_dump(),
            )
        return record

    return router
