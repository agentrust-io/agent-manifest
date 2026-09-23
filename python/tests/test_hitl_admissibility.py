"""HITL-001/002/004: present applicability is not earned by legacy approval checks."""
from datetime import timedelta

import pytest

from agent_manifest._verify import OverallResult, VerificationResult, verify_manifest
from tests.test_verify import NOW, base_context, base_manifest, hitl_approval, store


def approval_manifest(*, expired=False, **overrides):
    age = timedelta(hours=3 if expired else 1)
    approval = hitl_approval(
        (NOW - age).isoformat(), {"approval_duration_seconds": 7200}, **overrides
    )
    return base_manifest(hitl_record={"required": True, "approvals": [approval]})


def test_valid_approval_does_not_establish_current_applicability():
    """HITL-001: authenticated, unexpired evidence does not prove current standing."""
    result = verify_manifest(approval_manifest(), base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == "APPROVED"
    assert result.result == OverallResult.VALID
    assert result.hitl_admissibility.status == "UNDECIDABLE"
    assert result.hitl_admissibility.reason == "current_state_evidence_unavailable"
    payload = result.model_dump(mode="json")
    assert payload["hitl_admissibility"] == {
        "status": "UNDECIDABLE", "reason": "current_state_evidence_unavailable"
    }
    assert VerificationResult.model_validate(payload).hitl_admissibility == result.hitl_admissibility


@pytest.mark.parametrize("case", ["expired", "bad_timestamp", "bad_signature", "missing", "unknown_key"])
def test_failed_approval_checks_stay_failed_and_do_not_become_applicability_proof(case):
    """HITL-002: EXPIRED includes unauthenticated and malformed input, not historical proof."""
    manifest = approval_manifest(expired=case == "expired")
    context = base_context(enforce_hitl=True)
    expected = "EXPIRED"
    if case == "bad_timestamp":
        manifest["hitl_record"]["approvals"][0]["approved_at"] = "2026-09-16T10:00:00"
    elif case == "bad_signature":
        manifest["hitl_record"]["approvals"][0]["approval_signature"] = "bad"
        expected = "INVALID"
    elif case == "missing":
        manifest = base_manifest(hitl_record={"required": True, "approvals": []})
        expected = "MISSING"
    elif case == "unknown_key":
        context.approver_public_keys = {}
        expected = "UNVERIFIABLE"
    result = verify_manifest(manifest, context, store())
    assert result.fields_verified.hitl_record == expected
    assert result.result != OverallResult.VALID
    assert result.hitl_admissibility.status == "UNDECIDABLE"
    assert result.hitl_admissibility.reason == "approval_checks_not_satisfied"


@pytest.mark.parametrize("hitl", [None, {"required": False, "approvals": []}])
def test_not_required_is_distinct_from_a_positive_applicability_verdict(hitl):
    """HITL-001: absence of a requirement is not an admissible approval."""
    result = verify_manifest(base_manifest(hitl_record=hitl), base_context(), store())
    assert result.hitl_admissibility.status == "NOT_REQUIRED"
    assert result.hitl_admissibility.reason == "approval_not_required"


def test_enforcement_overrides_not_required():
    """HITL-002: caller enforcement still fails closed for an omitted record."""
    result = verify_manifest(base_manifest(), base_context(enforce_hitl=True), store())
    assert result.result != OverallResult.VALID
    assert result.hitl_admissibility.status == "UNDECIDABLE"
    assert result.hitl_admissibility.reason == "approval_checks_not_satisfied"


def test_early_return_does_not_claim_hitl_was_evaluated():
    """HITL-001: failed version negotiation cannot establish applicability or exemption."""
    result = verify_manifest(base_manifest(version="99.0"), base_context(), store())
    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.hitl_admissibility.status == "UNDECIDABLE"
    assert result.hitl_admissibility.reason == "verification_incomplete"


def test_old_serialized_result_gets_unknown_not_an_approval():
    """HITL-001: missing new metadata in a historical result cannot imply applicability."""
    result = VerificationResult(manifest_id="old-result", result=OverallResult.VALID)
    assert result.hitl_admissibility.status == "UNDECIDABLE"
    assert result.hitl_admissibility.reason == "verification_incomplete"
