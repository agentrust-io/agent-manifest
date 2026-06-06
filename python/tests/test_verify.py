"""Tests for the verification engine — issue #10."""
from datetime import datetime, timedelta, timezone

from agent_manifest._verify import (
    FieldResult,
    HitlResult,
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
PAST = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
SHA = "sha256:" + "a" * 64


def base_manifest(**overrides):
    m = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {"model_hash": None, "version": "claude-3", "deployment_type": "api"},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    m.update(overrides)
    return m


def base_context(**overrides):
    ctx = VerificationContext(
        system_prompt_hash=SHA,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="claude-3",
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def store():
    return RevocationStore()


# ---------------------------------------------------------------------------
# VALID result
# ---------------------------------------------------------------------------


def test_valid_all_match():
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.result == OverallResult.VALID
    assert result.fields_verified.system_prompt == FieldResult.MATCH
    assert result.fields_verified.policy_bundle == FieldResult.MATCH
    assert result.mismatch_details == []


def test_valid_unbound_fields_not_mismatch():
    # rag_corpus not in manifest and not in context — should be NOT_BOUND not MISMATCH
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.fields_verified.rag_corpus == FieldResult.NOT_BOUND
    assert result.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# MISMATCH
# ---------------------------------------------------------------------------


def test_mismatch_system_prompt():
    ctx = base_context(system_prompt_hash="sha256:" + "z" * 64)
    result = verify_manifest(base_manifest(), ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert result.fields_verified.system_prompt == FieldResult.MISMATCH
    assert any(d.field == "system_prompt" for d in result.mismatch_details)


def test_mismatch_policy_bundle():
    ctx = base_context(policy_bundle_hash="sha256:" + "0" * 64)
    result = verify_manifest(base_manifest(), ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert result.fields_verified.policy_bundle == FieldResult.MISMATCH


def test_mismatch_includes_all_failing_fields():
    ctx = base_context(
        system_prompt_hash="sha256:" + "0" * 64,
        policy_bundle_hash="sha256:" + "0" * 64,
    )
    result = verify_manifest(base_manifest(), ctx, store())
    assert len(result.mismatch_details) == 2


# ---------------------------------------------------------------------------
# EXPIRED
# ---------------------------------------------------------------------------


def test_expired_manifest():
    m = base_manifest(expires_at=PAST)
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.EXPIRED


def test_memory_baseline_ttl_expired():
    m = base_manifest()
    m["artifacts"]["memory_baseline"] = {
        "snapshot_hash": SHA,
        "approved_at": PAST,
        "ttl_seconds": 60,
    }
    ctx = base_context(memory_snapshot_hash=SHA)
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.memory_baseline == FieldResult.EXPIRED


# ---------------------------------------------------------------------------
# REVOKED
# ---------------------------------------------------------------------------


def test_revoked_manifest():
    s = store()
    s.revoke(RevocationRecord(
        manifest_id="018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        revoked_at=NOW,
        reason="Key compromise",
        revoked_by="security@example.com",
    ))
    result = verify_manifest(base_manifest(), base_context(), s)
    assert result.result == OverallResult.REVOKED


def test_revocation_checked_before_expiry():
    """Revoked must take precedence over expired."""
    s = store()
    s.revoke(RevocationRecord(
        manifest_id="018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        revoked_at=NOW,
        reason="test",
        revoked_by="test",
    ))
    m = base_manifest(expires_at=PAST)
    result = verify_manifest(m, base_context(), s)
    assert result.result == OverallResult.REVOKED


# ---------------------------------------------------------------------------
# HITL
# ---------------------------------------------------------------------------


def test_hitl_not_required():
    m = base_manifest(hitl_record={"required": False, "approvals": []})
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.NOT_REQUIRED


def test_hitl_approved():
    approval_time = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": approval_time,
            "approved_scope": {"approval_duration_seconds": 7200},
        }],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED


def test_hitl_missing_when_required():
    m = base_manifest(hitl_record={"required": True, "approvals": []})
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.MISSING


def test_hitl_approval_expired():
    approval_time = (NOW - timedelta(hours=3)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": approval_time,
            "approved_scope": {"approval_duration_seconds": 3600},  # 1h, now expired
        }],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.EXPIRED


# ---------------------------------------------------------------------------
# Decision trace
# ---------------------------------------------------------------------------


def test_decision_trace_match():
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": "sha256:" + "c" * 64}
    ctx = base_context(audit_chain_root="sha256:" + "c" * 64)
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.decision_trace == FieldResult.MATCH


def test_decision_trace_mismatch():
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": "sha256:" + "c" * 64}
    ctx = base_context(audit_chain_root="sha256:" + "d" * 64)
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.decision_trace == FieldResult.MISMATCH
    assert result.result == OverallResult.MISMATCH


# ---------------------------------------------------------------------------
# RevocationStore
# ---------------------------------------------------------------------------


def test_revocation_store_not_revoked():
    s = store()
    assert not s.is_revoked("some-id")


def test_revocation_store_get_record():
    s = store()
    rec = RevocationRecord(
        manifest_id="test-id", revoked_at=NOW, reason="test", revoked_by="admin"
    )
    s.revoke(rec)
    assert s.get_record("test-id") == rec
    assert s.get_record("other") is None


# ---------------------------------------------------------------------------
# Attestation verification (HW-010)
# ---------------------------------------------------------------------------


def _manifest_hash(manifest: dict) -> str:
    import hashlib
    from agent_manifest._canonicalize import canonicalize
    subset = {k: v for k, v in manifest.items() if k != "attestation"}
    return "sha256:" + hashlib.sha256(canonicalize(subset)).hexdigest()


def test_attestation_verified_true_when_hash_matches():
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": _manifest_hash(m)}
    result = verify_manifest(m, base_context(), store())
    assert result.attestation_verified is True


def test_attestation_verified_false_when_no_attestation():
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.attestation_verified is False


def test_attestation_hash_mismatch_with_enforce_raises_mismatch():
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": "sha256:" + "00" * 32}
    ctx = base_context(enforce_attestation=True)
    result = verify_manifest(m, ctx, store())
    assert result.attestation_verified is False
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "attestation" for d in result.mismatch_details)


def test_attestation_hash_mismatch_without_enforce_is_valid():
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": "sha256:" + "00" * 32}
    result = verify_manifest(m, base_context(), store())
    assert result.attestation_verified is False
    assert result.result == OverallResult.VALID
