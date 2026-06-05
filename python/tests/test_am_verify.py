"""AM-VERIFY: Verification endpoint conformance tests — issue #19.

Covers VerificationResult schema, all result states, mismatch detection,
delegation chain validation, HITL verification, and the FastAPI endpoint
HTTP contract. Target: 52 tests.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._verify import (
    DelegationResult,
    ErrorResponse,
    FieldResult,
    HitlResult,
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

NOW = datetime.now(timezone.utc)
TS_FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
TS_PAST   = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
MID   = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"


def manifest(**overrides):
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": TS_FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA_A},
            "policy_bundle": {"hash": SHA_B, "enforcement_mode": "enforce"},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
            "decision_trace": {"audit_chain_root": SHA_C},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    m.update(overrides)
    return m


def ctx(**overrides):
    c = VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        audit_chain_root=SHA_C,
    )
    for k, v in overrides.items():
        setattr(c, k, v)
    return c


def store():
    return RevocationStore()


# ---------------------------------------------------------------------------
# VerificationResult schema (AM-VERIFY-01 to 06)
# ---------------------------------------------------------------------------

def test_result_has_verification_id():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.verification_id and len(r.verification_id) > 0

def test_result_has_manifest_id():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.manifest_id == MID

def test_result_has_verified_at():
    r = verify_manifest(manifest(), ctx(), store())
    assert isinstance(r.verified_at, datetime)

def test_result_has_fields_verified():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.fields_verified is not None

def test_result_fields_includes_decision_trace():
    r = verify_manifest(manifest(), ctx(), store())
    assert hasattr(r.fields_verified, "decision_trace")

def test_result_mismatch_details_empty_on_valid():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.result == OverallResult.VALID
    assert r.mismatch_details == []


# ---------------------------------------------------------------------------
# VALID (AM-VERIFY-07 to 10)
# ---------------------------------------------------------------------------

def test_valid_all_match():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.result == OverallResult.VALID

def test_valid_unbound_fields_not_counted_as_mismatch():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.fields_verified.rag_corpus == FieldResult.NOT_BOUND
    assert r.result == OverallResult.VALID

def test_valid_decision_trace_match():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.fields_verified.decision_trace == FieldResult.MATCH

def test_valid_all_fields_verified_count():
    r = verify_manifest(manifest(), ctx(), store())
    fv = r.fields_verified
    match_count = sum(
        1 for f in [fv.system_prompt, fv.policy_bundle, fv.model_identity, fv.decision_trace]
        if f == FieldResult.MATCH
    )
    assert match_count == 4


# ---------------------------------------------------------------------------
# MISMATCH (AM-VERIFY-11 to 20)
# ---------------------------------------------------------------------------

def test_mismatch_system_prompt():
    r = verify_manifest(manifest(), ctx(system_prompt_hash=SHA_B), store())
    assert r.result == OverallResult.MISMATCH
    assert r.fields_verified.system_prompt == FieldResult.MISMATCH

def test_mismatch_policy_bundle():
    r = verify_manifest(manifest(), ctx(policy_bundle_hash=SHA_C), store())
    assert r.result == OverallResult.MISMATCH
    assert r.fields_verified.policy_bundle == FieldResult.MISMATCH

def test_mismatch_decision_trace():
    r = verify_manifest(manifest(), ctx(audit_chain_root=SHA_B), store())
    assert r.result == OverallResult.MISMATCH
    assert r.fields_verified.decision_trace == FieldResult.MISMATCH

def test_mismatch_detail_contains_both_hashes():
    r = verify_manifest(manifest(), ctx(system_prompt_hash=SHA_B), store())
    detail = next(d for d in r.mismatch_details if d.field == "system_prompt")
    assert detail.expected_hash == SHA_A
    assert detail.actual_hash == SHA_B

def test_mismatch_detail_has_timestamp():
    r = verify_manifest(manifest(), ctx(system_prompt_hash=SHA_B), store())
    assert any(d.delta_detected_at for d in r.mismatch_details)

def test_mismatch_multiple_fields():
    r = verify_manifest(
        manifest(),
        ctx(system_prompt_hash=SHA_C, policy_bundle_hash=SHA_C),
        store(),
    )
    assert len(r.mismatch_details) == 2

def test_mismatch_supply_chain():
    m = manifest()
    m["artifacts"]["supply_chain"] = {"container_image_digest": SHA_A}
    r = verify_manifest(m, ctx(container_image_digest=SHA_B), store())
    assert r.fields_verified.supply_chain == FieldResult.MISMATCH

def test_mismatch_rag_corpus():
    m = manifest()
    m["artifacts"]["rag_corpus"] = {"merkle_root": SHA_A}
    r = verify_manifest(m, ctx(rag_corpus_merkle_root=SHA_B), store())
    assert r.fields_verified.rag_corpus == FieldResult.MISMATCH

def test_mismatch_memory_snapshot():
    m = manifest()
    m["artifacts"]["memory_baseline"] = {
        "snapshot_hash": SHA_A,
        "approved_at": NOW.isoformat().replace("+00:00", "Z"),
        "ttl_seconds": 86400,
    }
    r = verify_manifest(m, ctx(memory_snapshot_hash=SHA_B), store())
    assert r.fields_verified.memory_baseline == FieldResult.MISMATCH

def test_mismatch_tool_catalog():
    m = manifest()
    m["artifacts"]["tool_manifest"] = {"catalog_hash": SHA_A}
    r = verify_manifest(m, ctx(tool_catalog_hash=SHA_B), store())
    assert r.fields_verified.tool_manifest == FieldResult.MISMATCH


# ---------------------------------------------------------------------------
# EXPIRED (AM-VERIFY-21 to 23)
# ---------------------------------------------------------------------------

def test_expired_result():
    r = verify_manifest(manifest(expires_at=TS_PAST), ctx(), store())
    assert r.result == OverallResult.EXPIRED

def test_expired_returns_early_no_field_checks():
    r = verify_manifest(manifest(expires_at=TS_PAST), ctx(system_prompt_hash=SHA_B), store())
    assert r.result == OverallResult.EXPIRED
    assert r.mismatch_details == []

def test_memory_baseline_expired():
    m = manifest()
    m["artifacts"]["memory_baseline"] = {
        "snapshot_hash": SHA_A,
        "approved_at": TS_PAST,
        "ttl_seconds": 60,
    }
    r = verify_manifest(m, ctx(memory_snapshot_hash=SHA_A), store())
    assert r.fields_verified.memory_baseline == FieldResult.EXPIRED


# ---------------------------------------------------------------------------
# REVOKED (AM-VERIFY-24 to 26)
# ---------------------------------------------------------------------------

def test_revoked_result():
    s = store()
    s.revoke(RevocationRecord(manifest_id=MID, revoked_at=NOW, reason="test", revoked_by="admin"))
    r = verify_manifest(manifest(), ctx(), s)
    assert r.result == OverallResult.REVOKED

def test_revoked_before_expiry_check():
    s = store()
    s.revoke(RevocationRecord(manifest_id=MID, revoked_at=NOW, reason="test", revoked_by="admin"))
    r = verify_manifest(manifest(expires_at=TS_PAST), ctx(), s)
    assert r.result == OverallResult.REVOKED

def test_different_manifest_not_revoked():
    s = store()
    s.revoke(RevocationRecord(manifest_id="018aaaaa-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
                               revoked_at=NOW, reason="t", revoked_by="a"))
    r = verify_manifest(manifest(), ctx(), s)
    assert r.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# Delegation chain (AM-VERIFY-27 to 29)
# ---------------------------------------------------------------------------

def test_delegation_chain_present():
    m = manifest(delegation_chain=[{
        "hop": 0, "principal_type": "human",
        "principal_id": "did:web:example", "delegated_at": NOW.isoformat(),
        "scope_grant": {"max_delegation_depth": 3, "ttl_seconds": 3600},
        "delegation_signature": "sig",
    }])
    r = verify_manifest(m, ctx(), store())
    assert r.fields_verified.delegation_chain == DelegationResult.VALID

def test_delegation_chain_absent():
    r = verify_manifest(manifest(), ctx(), store())
    assert r.fields_verified.delegation_chain == DelegationResult.NOT_PRESENT


# ---------------------------------------------------------------------------
# HITL (AM-VERIFY-30 to 36)
# ---------------------------------------------------------------------------

def test_hitl_not_required():
    m = manifest(hitl_record={"required": False, "approvals": []})
    r = verify_manifest(m, ctx(), store())
    assert r.fields_verified.hitl_record == HitlResult.NOT_REQUIRED

def test_hitl_approved():
    ago = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    m = manifest(hitl_record={"required": True, "approvals": [
        {"approved_at": ago, "approved_scope": {"approval_duration_seconds": 3600}}
    ]})
    r = verify_manifest(m, ctx(), store())
    assert r.fields_verified.hitl_record == HitlResult.APPROVED

def test_hitl_missing():
    m = manifest(hitl_record={"required": True, "approvals": []})
    r = verify_manifest(m, ctx(), store())
    assert r.fields_verified.hitl_record == HitlResult.MISSING

def test_hitl_expired():
    ago = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    m = manifest(hitl_record={"required": True, "approvals": [
        {"approved_at": ago, "approved_scope": {"approval_duration_seconds": 3600}}
    ]})
    r = verify_manifest(m, ctx(), store())
    assert r.fields_verified.hitl_record == HitlResult.EXPIRED


# ---------------------------------------------------------------------------
# Error response schema (AM-VERIFY-37 to 40)
# ---------------------------------------------------------------------------

def test_error_response_has_error_code():
    e = ErrorResponse(error_code="INVALID_MANIFEST_ID", error_message="bad id")
    assert e.error_code == "INVALID_MANIFEST_ID"

def test_error_response_has_request_id():
    e = ErrorResponse(error_code="X", error_message="y")
    assert e.request_id and len(e.request_id) > 0

def test_error_response_retry_after_optional():
    e = ErrorResponse(error_code="X", error_message="y")
    assert e.retry_after_seconds is None

def test_error_response_retry_after_set():
    e = ErrorResponse(error_code="RATE_LIMITED", error_message="slow down", retry_after_seconds=60)
    assert e.retry_after_seconds == 60


# ---------------------------------------------------------------------------
# FastAPI endpoint HTTP contract (AM-VERIFY-41 to 52, skipped without fastapi)
# ---------------------------------------------------------------------------

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from agent_manifest._verify import create_router
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

require_fastapi = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="fastapi not installed")


def _client(manifests=None):
    app = FastAPI()
    s = RevocationStore()
    store_dict = manifests or {MID: manifest()}
    app.include_router(create_router(store_dict, s))
    return TestClient(app), s


@require_fastapi
def test_http_verify_valid():
    client, _ = _client()
    r = client.get(f"/verify?manifest_id={MID}")
    assert r.status_code == 200
    assert r.json()["result"] == "VALID"


@require_fastapi
def test_http_verify_not_found():
    client, _ = _client({})
    r = client.get(f"/verify?manifest_id={MID}")
    assert r.status_code == 404


@require_fastapi
def test_http_verify_invalid_manifest_id():
    client, _ = _client()
    r = client.get("/verify?manifest_id=not-a-uuid")
    assert r.status_code == 400


@require_fastapi
def test_http_revocation_status_not_revoked():
    client, _ = _client()
    r = client.get(f"/revocation-status?manifest_id={MID}")
    assert r.status_code == 404


@require_fastapi
def test_http_revocation_status_revoked():
    client, s = _client()
    s.revoke(RevocationRecord(manifest_id=MID, revoked_at=NOW, reason="test", revoked_by="admin"))
    r = client.get(f"/revocation-status?manifest_id={MID}")
    assert r.status_code == 200
    assert r.json()["manifest_id"] == MID


@require_fastapi
def test_http_verify_missing_manifest_id():
    client, _ = _client()
    r = client.get("/verify")
    assert r.status_code == 422  # FastAPI unprocessable entity


@require_fastapi
def test_http_result_schema_has_all_fields():
    client, _ = _client()
    r = client.get(f"/verify?manifest_id={MID}")
    body = r.json()
    for field in ("verification_id", "manifest_id", "result", "fields_verified",
                  "mismatch_details", "verified_at"):
        assert field in body, f"Missing field: {field}"
