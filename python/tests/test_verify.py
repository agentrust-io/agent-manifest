"""Tests for the verification engine - issue #10."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest import _signing
from agent_manifest._delegation import HitlApprovalSigner
from agent_manifest._signing import Ed25519Signer, _b64url_encode, generate_ed25519
from agent_manifest._verify import (
    DelegationResult,
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
TRANSPARENCY_ENTRY_ID = "rekor-entry-123"

# Module-level signing key - the verifier is fail-closed, so VALID results
# require a signed manifest and the matching trusted key in the context.
KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}
APPROVER_KP = generate_ed25519()
APPROVER_ID = "mailto:alice@example.com"
ISSUER_A = "spiffe://trust.example/issuer/a"
ISSUER_B = "spiffe://trust.example/issuer/b"


def sign_with(m, kp):
    """(Re-)sign a manifest dict with the supplied key in place and return it."""
    m["signature"] = Ed25519Signer(kp).sign(m)
    return m


def sign(m):
    """(Re-)sign a manifest dict in place and return it."""
    return sign_with(m, KP)


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
    return sign(m)


def base_context(**overrides):
    ctx = VerificationContext(
        system_prompt_hash=SHA,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
        approver_public_keys={APPROVER_ID: APPROVER_KP.public_b64url()},
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def store():
    return RevocationStore()


def attach_transparency_entry(manifest):
    """Attach a structurally valid post-signing Rekor entry."""
    manifest["transparency_log_entry"] = {
        "log_id": "0" * 64,
        "log_index": 1,
        "entry_uuid": TRANSPARENCY_ENTRY_ID,
        "integrated_time": int(NOW.timestamp()),
        "inclusion_proof": {
            "checkpoint": "signed-checkpoint",
            "hashes": [],
            "tree_size": 1,
        },
    }
    return manifest


def hitl_approval(approved_at, approved_scope, **overrides):
    approval = {
        "approver_id": APPROVER_ID,
        "approved_at": approved_at,
        "approved_scope": approved_scope,
    }
    approval.update(overrides)
    approval["approval_signature"] = HitlApprovalSigner(APPROVER_KP).sign_approval(
        manifest_id=base_manifest()["manifest_id"],
        approved_at=approval["approved_at"],
        approved_scope=approval["approved_scope"],
        approver_id=approval["approver_id"],
        approval_method=approval.get("approval_method"),
    )
    return approval


# ---------------------------------------------------------------------------
# VALID result
# ---------------------------------------------------------------------------


def test_valid_all_match():
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.result == OverallResult.VALID
    assert result.fields_verified.system_prompt == FieldResult.MATCH
    assert result.fields_verified.policy_bundle == FieldResult.MATCH
    assert result.mismatch_details == []


def test_required_transparency_missing_is_incomplete():
    result = verify_manifest(
        base_manifest(), base_context(require_transparency=True), store()
    )
    assert result.result == OverallResult.INCOMPLETE
    assert result.transparency_verified is False


def test_present_but_untrusted_transparency_entry_is_unverifiable():
    result = verify_manifest(
        attach_transparency_entry(base_manifest()),
        base_context(require_transparency=True),
        store(),
    )
    assert result.result == OverallResult.UNVERIFIABLE
    assert result.transparency_verified is False


def test_independently_verified_transparency_entry_satisfies_requirement():
    result = verify_manifest(
        attach_transparency_entry(base_manifest()),
        base_context(
            require_transparency=True,
            verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
            transparency_evidence_manifest_id=base_manifest()["manifest_id"],
        ),
        store(),
    )
    assert result.result == OverallResult.VALID
    assert result.transparency_verified is True


def test_verified_transparency_entry_cannot_be_replayed_to_another_manifest():
    result = verify_manifest(
        attach_transparency_entry(base_manifest()),
        base_context(
            require_transparency=True,
            verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
            transparency_evidence_manifest_id="018f4a3b-2c1d-7e5f-a8b9-ffffffffffff",
        ),
        store(),
    )
    assert result.result == OverallResult.UNVERIFIABLE
    assert result.transparency_verified is False


@pytest.mark.parametrize(
    "required_field",
    ["manifest_id", "agent_id", "issued_at", "expires_at", "artifacts"],
)
def test_signed_manifest_missing_required_claim_is_not_valid(required_field):
    manifest = base_manifest()
    manifest.pop(required_field)
    sign(manifest)

    result = verify_manifest(manifest, base_context(), store())

    assert result.result == OverallResult.MISMATCH
    assert any(
        detail.field == f"schema:{required_field}"
        for detail in result.mismatch_details
    )


def test_valid_unbound_fields_not_mismatch():
    # rag_corpus not in manifest and not in context - should be NOT_BOUND not MISMATCH
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
# ENFORCEMENT MODE (spec 6.2) — agentrust-io/cmcp#576
# ---------------------------------------------------------------------------


def test_enforcement_mode_match_is_unaffected():
    """A manifest that declares a mode, matched by the runtime, still MATCHes."""
    manifest = base_manifest(artifacts={
        "system_prompt": {"hash": SHA},
        "policy_bundle": {"hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "model_identity": {"model_hash": None, "version": "claude-3", "deployment_type": "api"},
    })
    ctx = base_context(enforcement_mode="enforce")
    result = verify_manifest(manifest, ctx, store())
    assert result.result == OverallResult.VALID
    assert result.fields_verified.policy_bundle == FieldResult.MATCH


def test_enforcement_mode_mismatch_fails_policy_bundle():
    """Hash matches, but the runtime is attested in a different mode than the
    manifest declares -- this must fail, not silently pass on the hash alone.
    """
    manifest = base_manifest(artifacts={
        "system_prompt": {"hash": SHA},
        "policy_bundle": {"hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "model_identity": {"model_hash": None, "version": "claude-3", "deployment_type": "api"},
    })
    ctx = base_context(enforcement_mode="advisory")
    result = verify_manifest(manifest, ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert result.fields_verified.policy_bundle == FieldResult.MISMATCH
    assert any(d.field == "policy_bundle.enforcement_mode" for d in result.mismatch_details)


def test_enforcement_mode_declared_but_not_provided_fails_closed():
    """The manifest declares a required mode; the caller didn't pass one.

    Fail closed rather than silently skipping the check -- an unattested mode
    is not evidence the runtime is in the declared mode.
    """
    manifest = base_manifest(artifacts={
        "system_prompt": {"hash": SHA},
        "policy_bundle": {"hash": "sha256:" + "b" * 64, "enforcement_mode": "enforce"},
        "model_identity": {"model_hash": None, "version": "claude-3", "deployment_type": "api"},
    })
    ctx = base_context()  # enforcement_mode left unset
    result = verify_manifest(manifest, ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert result.fields_verified.policy_bundle == FieldResult.MISMATCH


def test_enforcement_mode_absent_from_manifest_is_backward_compatible():
    """A manifest that never declares enforcement_mode is unaffected, even if
    the caller happens to pass one -- there is nothing to cross-check against.
    """
    ctx = base_context(enforcement_mode="enforce")
    result = verify_manifest(base_manifest(), ctx, store())  # base_manifest has no enforcement_mode
    assert result.result == OverallResult.VALID
    assert result.fields_verified.policy_bundle == FieldResult.MATCH


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
        "approved_at": PAST,  # 1 day ago, so a 1h TTL is well past expiry
        "ttl_seconds": 3600,  # schema minimum (1 hour)
    }
    ctx = base_context(memory_snapshot_hash=SHA)
    result = verify_manifest(sign(m), ctx, store())
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
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": 7200}
        )],
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


def test_hitl_approval_naive_timestamp_fails_closed_not_crash():
    """A tz-naive approved_at ("2026-09-16T10:00:00", no offset/"Z") parses
    fine with a bare datetime.fromisoformat() and passes schema validation
    (pydantic's `datetime` field doesn't require tzinfo), so it reaches the
    integrated HITL loop. There, comparing it against the aware `now` used
    for expiry must not raise TypeError out of verify_manifest() - it must
    fail closed as EXPIRED, the same as any other unparseable timestamp."""
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": "2026-09-16T10:00:00",
            "approved_scope": {"approval_duration_seconds": 3600},
        }],
    })
    result = verify_manifest(m, base_context(), store())  # must not raise
    assert result.fields_verified.hitl_record == HitlResult.EXPIRED


def test_hitl_approval_non_dict_entry_fails_closed_not_crash(monkeypatch):
    """Defense in depth: a non-dict entry in hitl_record.approvals is
    already caught by schema validation on the normal path (a genuine type
    mismatch, not the "missing field" legacy carve-out), but the loop
    itself must not raise AttributeError out of verify_manifest() if it
    were ever reached - it must fail closed as INVALID, same bucket as any
    other concretely-broken approval."""
    import agent_manifest._verify as verify_mod

    monkeypatch.setattr(verify_mod, "_strict_schema_violations", lambda m: [])
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": ["not-an-approval-object"],
    })
    result = verify_manifest(m, base_context(), store())  # must not raise
    assert result.fields_verified.hitl_record == HitlResult.INVALID


def test_hitl_approval_non_dict_approved_scope_fails_closed_not_crash(monkeypatch):
    """Defense in depth: a non-dict approved_scope is already caught by
    schema validation on the normal path, but the loop itself must not
    raise AttributeError out of verify_manifest() when it calls .get() on
    it if that guard were ever bypassed - it must fail closed as INVALID."""
    import agent_manifest._verify as verify_mod

    monkeypatch.setattr(verify_mod, "_strict_schema_violations", lambda m: [])
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "approved_scope": "not-a-scope-object",
        }],
    })
    result = verify_manifest(m, base_context(), store())  # must not raise
    assert result.fields_verified.hitl_record == HitlResult.INVALID


def test_hitl_approval_missing_duration_rejected_by_schema():
    """approval_duration_seconds is required (models.ApprovedScope). Omitting
    it must fail closed like setting it to 0 does, not be waved through as
    an approval that never expires."""
    approval_time = (NOW - timedelta(days=365)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(approval_time, {})],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(
        "approval_duration_seconds" in d.field
        for d in result.mismatch_details
    )


def test_hitl_approval_explicit_zero_duration_rejected_by_schema():
    """Setting approval_duration_seconds: 0 fails the same schema check as
    omitting it - both mean "no expiry", and both must be rejected."""
    approval_time = (NOW - timedelta(days=365)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": 0}
        )],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(
        "approval_duration_seconds" in d.field
        for d in result.mismatch_details
    )


def test_hitl_approval_negative_duration_rejected_by_schema():
    """A negative approval_duration_seconds fails the same schema check as
    0, through the normal (non-bypassed) verify_manifest() path."""
    approval_time = (NOW - timedelta(days=365)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": -100}
        )],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(
        "approval_duration_seconds" in d.field
        for d in result.mismatch_details
    )


def test_hitl_approval_fractional_duration_rejected_by_schema():
    """A fractional approval_duration_seconds (e.g. 1.5) fails the schema's
    int coercion, which accepts a float only when it has no fractional
    part, through the normal (non-bypassed) verify_manifest() path."""
    approval_time = (NOW - timedelta(days=365)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": 1.5}
        )],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(
        "approval_duration_seconds" in d.field
        for d in result.mismatch_details
    )


def test_hitl_approval_whole_number_float_duration_is_approved():
    """A whole-number float (e.g. 3600.0) is accepted end-to-end through
    verify_manifest() - the schema coerces it to int 3600, the same as
    passing 3600 directly. Not stricter than the schema."""
    approval_time = (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": 3600.0}
        )],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED


@pytest.mark.parametrize("bad_scope", [
    {},                                      # missing entirely
    {"approval_duration_seconds": 0},        # zero
    {"approval_duration_seconds": -100},     # negative
    {"approval_duration_seconds": 1.5},      # fractional (not an integer)
])
def test_hitl_loop_fails_closed_on_bad_duration_even_if_schema_bypassed(monkeypatch, bad_scope):
    """Defense in depth: even if schema validation were bypassed, a missing,
    zero, negative, or fractional duration must never resolve to APPROVED."""
    import agent_manifest._verify as verify_mod

    monkeypatch.setattr(verify_mod, "_strict_schema_violations", lambda m: [])
    approval_time = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(approval_time, bad_scope)],
    })
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.hitl_record == HitlResult.INVALID


# ---------------------------------------------------------------------------
# Decision trace
# ---------------------------------------------------------------------------


def test_decision_trace_match():
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": "sha256:" + "c" * 64}
    ctx = base_context(audit_chain_root="sha256:" + "c" * 64)
    result = verify_manifest(sign(m), ctx, store())
    assert result.fields_verified.decision_trace == FieldResult.MATCH


def test_decision_trace_mismatch():
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": "sha256:" + "c" * 64}
    ctx = base_context(audit_chain_root="sha256:" + "d" * 64)
    result = verify_manifest(sign(m), ctx, store())
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


# GHSA-85fc-3g4g-fjjc / GHSA-qvg2-j8c5-5x3w: a matching manifest_hash_in_report
# proves the report is about this manifest. It is not evidence that any hardware
# produced it. For v0.1 the attestation block is outside the signing pre-image
# (spec 3.3), so a party holding any validly signed manifest can append a digest
# it computed itself; for v0.2 COSE the block rides in the unprotected header.
# attestation_verified therefore needs an independent appraisal as well.

def test_attestation_hash_binding_alone_does_not_verify_attestation():
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": _manifest_hash(m)}

    result = verify_manifest(m, base_context(), store())

    assert result.attestation_verified is False
    assert any("no independent hardware appraisal" in w for w in result.warnings)


def test_attestation_verified_true_with_an_independent_appraisal():
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": _manifest_hash(m)}
    ctx = base_context(
        verified_attestation_manifest_hashes={_manifest_hash(m)},
        attestation_evidence_manifest_id=m["manifest_id"],
    )

    result = verify_manifest(m, ctx, store())

    assert result.attestation_verified is True


def test_appraisal_bound_to_another_manifest_does_not_transfer():
    """A passing appraisal is not a bearer token for every manifest."""
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": _manifest_hash(m)}
    ctx = base_context(
        verified_attestation_manifest_hashes={_manifest_hash(m)},
        attestation_evidence_manifest_id="018f4a3b-0000-7e5f-a8b9-000000000000",
    )

    result = verify_manifest(m, ctx, store())

    assert result.attestation_verified is False


def test_software_only_manifest_cannot_satisfy_enforce_attestation():
    """The reported impact: a self-asserted digest reaching VALID under enforcement."""
    m = base_manifest()
    m["attestation"] = {
        "platform": "tpm",
        "manifest_hash_in_report": _manifest_hash(m),
        "audit_key_sealed": True,
    }

    result = verify_manifest(m, base_context(enforce_attestation=True), store())

    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


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


def test_attestation_hash_mismatch_is_fatal_without_enforce():
    """Issue #265: a present attestation that binds a different manifest is
    a report about some other document. enforce_attestation governs whether
    an attestation is required, not whether a wrong one counts."""
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": "sha256:" + "00" * 32}
    result = verify_manifest(m, base_context(), store())
    assert result.attestation_verified is False
    assert result.result == OverallResult.MISMATCH
    assert [d for d in result.mismatch_details if d.field == "attestation"]


# ---------------------------------------------------------------------------
# Fail-closed signature verification (spec 5.3)
# ---------------------------------------------------------------------------


def test_unsigned_manifest_is_not_valid():
    m = base_manifest()
    del m["signature"]
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.SIGNATURE_MISSING
    assert result.signature_verified is False


def test_signed_manifest_without_trusted_keys_is_unverifiable():
    result = verify_manifest(base_manifest(), base_context(trusted_keys={}), store())
    assert result.result == OverallResult.UNVERIFIABLE
    assert result.signature_verified is False


def test_valid_result_implies_signature_verified():
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.result == OverallResult.VALID
    assert result.signature_verified is True


def test_trusted_key_authorized_for_manifest_issuer_is_valid():
    ctx = base_context(trusted_key_issuers={KP.key_id: [ISSUER_A]})
    result = verify_manifest(base_manifest(issuer=ISSUER_A), ctx, store())
    assert result.result == OverallResult.VALID
    assert result.signature_verified is True


def test_trusted_key_not_authorized_for_claimed_issuer_is_mismatch():
    other = generate_ed25519()
    trusted_keys = dict(TRUSTED_KEYS)
    trusted_keys[other.key_id] = other.public_b64url()
    ctx = base_context(
        trusted_keys=trusted_keys,
        trusted_key_issuers={
            KP.key_id: [ISSUER_A],
            other.key_id: [ISSUER_B],
        },
    )

    result = verify_manifest(base_manifest(issuer=ISSUER_B), ctx, store())

    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(d.field == "signature.issuer" for d in result.mismatch_details)


def test_trusted_key_without_issuer_authorization_is_mismatch():
    other = generate_ed25519()
    ctx = base_context(trusted_key_issuers={other.key_id: [ISSUER_A]})

    result = verify_manifest(base_manifest(issuer=ISSUER_A), ctx, store())

    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(d.field == "signature.issuer" for d in result.mismatch_details)


def test_trusted_key_issuer_authorization_requires_manifest_issuer():
    ctx = base_context(trusted_key_issuers={KP.key_id: [ISSUER_A]})

    result = verify_manifest(base_manifest(), ctx, store())

    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(d.field == "signature.issuer" for d in result.mismatch_details)


def test_tampered_manifest_signature_is_mismatch():
    m = base_manifest()
    m["agent_id"] = "spiffe://evil.example/agent/impostor"  # invalidates signature
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "signature" for d in result.mismatch_details)


def test_unknown_key_id_is_mismatch():
    other = generate_ed25519()
    ctx = base_context(trusted_keys={other.key_id: other.public_b64url()})
    result = verify_manifest(base_manifest(), ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False


def _hybrid_manifest(key_id: str):
    m = base_manifest()
    m["signature"] = {
        "algorithm": "hybrid-Ed25519-ML-DSA-65",
        "key_id": key_id,
        "key_type": "software",
        "signed_at": NOW.isoformat().replace("+00:00", "Z"),
        "classical_signature": "AA",
        "pq_signature": "AA",
        "signature_value": "",
    }
    return m


def test_hybrid_signature_uses_combined_trusted_key(monkeypatch):
    ed_pub = b"e" * 32
    pq_pub = b"p" * 1952
    combined_pub = ed_pub + pq_pub
    key_id = hashlib.sha256(combined_pub).hexdigest()
    seen = {}

    class FakeHybridVerifier:
        def __init__(self, ed25519_public_bytes, ml_dsa65_public_bytes):
            seen["ed"] = ed25519_public_bytes
            seen["pq"] = ml_dsa65_public_bytes

        def verify(self, manifest_dict, signature_block):
            seen["verified"] = True

    monkeypatch.setattr(_signing, "HybridVerifier", FakeHybridVerifier)
    ctx = base_context(trusted_keys={key_id: _b64url_encode(combined_pub)})

    result = verify_manifest(_hybrid_manifest(key_id), ctx, store())

    assert result.result == OverallResult.VALID
    assert result.signature_verified is True
    assert seen == {"ed": ed_pub, "pq": pq_pub, "verified": True}


def test_hybrid_trusted_key_must_match_combined_key_id():
    ed_pub = b"e" * 32
    pq_pub = b"p" * 1952
    key_id = hashlib.sha256(ed_pub + pq_pub).hexdigest()
    wrong_combined_pub = ed_pub + (b"q" * 1952)
    ctx = base_context(trusted_keys={key_id: _b64url_encode(wrong_combined_pub)})

    result = verify_manifest(_hybrid_manifest(key_id), ctx, store())

    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(
        d.field == "signature"
        and "Hybrid public key bytes do not match signature.key_id" in d.actual_hash
        for d in result.mismatch_details
    )


# ---------------------------------------------------------------------------
# _split_hybrid_public_key rejects a wrong-length key instead of only
# checking it's longer than 32 bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pq_len",
    [0, 1, 1951, 1953, 3000],
    ids=["no_pq_bytes", "one_pq_byte", "pq_too_short", "pq_too_long", "pq_way_too_long"],
)
def test_split_hybrid_public_key_rejects_wrong_total_length(pq_len):
    from agent_manifest._verify import _split_hybrid_public_key

    pub = b"e" * 32 + b"p" * pq_len
    key_id = hashlib.sha256(pub).hexdigest()
    with pytest.raises(ValueError, match="1984"):
        _split_hybrid_public_key(key_id, pub)


def test_split_hybrid_public_key_accepts_exact_length():
    from agent_manifest._verify import _split_hybrid_public_key

    pub = b"e" * 32 + b"p" * 1952
    key_id = hashlib.sha256(pub).hexdigest()
    ed_bytes, pq_bytes = _split_hybrid_public_key(key_id, pub)
    assert ed_bytes == b"e" * 32
    assert pq_bytes == b"p" * 1952


def test_hybrid_trusted_key_wrong_length_is_mismatch_not_a_crash():
    """A wrong-length combined key in trusted_keys must be a MISMATCH,
    not an unhandled exception."""
    ed_pub = b"e" * 32
    short_pq_pub = b"p" * 100  # not 1952
    combined_pub = ed_pub + short_pq_pub
    key_id = hashlib.sha256(combined_pub).hexdigest()
    ctx = base_context(trusted_keys={key_id: _b64url_encode(combined_pub)})

    result = verify_manifest(_hybrid_manifest(key_id), ctx, store())

    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(
        d.field == "signature" and "1984" in d.actual_hash
        for d in result.mismatch_details
    )


# ---------------------------------------------------------------------------
# Unsupported algorithm: capability gap, not a bad manifest (spec 4.2)
# ---------------------------------------------------------------------------


def _pq_manifest_with_algorithm(algorithm):
    m = base_manifest(crypto_profile="post-quantum")
    m["signature"]["algorithm"] = algorithm
    return m


def _raise_unavailable(*args, **kwargs):
    from agent_manifest._signing import AlgorithmUnavailableError

    raise AlgorithmUnavailableError(
        "ML-DSA-65 is unavailable in this build. It needs cryptography >= 47 "
        '(install with: pip install "agent-manifest[pq]") or the liboqs '
        "Python bindings importable as `oqs`."
    )


def test_ml_dsa_without_pq_extra_is_unverifiable_not_an_exception(monkeypatch):
    # A build can lack an ML-DSA-65 backend entirely (cryptography < 47 and no
    # liboqs), so it cannot appraise an ML-DSA-65 signature. A manifest is
    # untrusted input: verify_manifest must
    # return a verdict rather than raise, and the verdict must not be MISMATCH,
    # which would accuse a manifest that may be perfectly valid.
    monkeypatch.setattr(_signing, "MlDsa65Verifier", _raise_unavailable)

    result = verify_manifest(
        _pq_manifest_with_algorithm("ML-DSA-65"), base_context(), store()
    )

    assert result.result == OverallResult.UNVERIFIABLE
    assert result.signature_verified is False
    assert not any(d.field.startswith("signature") for d in result.mismatch_details)
    assert any("not supported by this build" in w for w in result.warnings)


def test_hybrid_without_pq_extra_is_unverifiable(monkeypatch):
    ed_pub = b"e" * 32
    pq_pub = b"p" * 1952
    combined_pub = ed_pub + pq_pub
    key_id = hashlib.sha256(combined_pub).hexdigest()
    monkeypatch.setattr(_signing, "HybridVerifier", _raise_unavailable)

    m = _hybrid_manifest(key_id)
    ctx = base_context(trusted_keys={key_id: _b64url_encode(combined_pub)})
    result = verify_manifest(m, ctx, store())

    assert result.result == OverallResult.UNVERIFIABLE
    assert result.signature_verified is False
    assert any("not supported by this build" in w for w in result.warnings)


def test_unavailable_algorithm_is_distinct_from_unknown_algorithm():
    # An algorithm outside the registry is a malformed manifest: the schema
    # enum rejects it before signature verification runs. A registered
    # algorithm this build cannot run is UNVERIFIABLE. The two must not
    # collapse into one result, because only the first accuses the manifest.
    m = base_manifest()
    m["signature"]["algorithm"] = "Ed25519-but-made-up"
    result = verify_manifest(m, base_context(), store())

    assert result.result == OverallResult.MISMATCH
    assert any(
        d.field == "schema:signature.algorithm" for d in result.mismatch_details
    )


# ---------------------------------------------------------------------------
# Crypto profile downgrade (spec 4.2)
# ---------------------------------------------------------------------------


def test_pq_profile_with_classical_signature_is_mismatch():
    # crypto_profile is signed, signature.algorithm is not: this manifest carries
    # a genuine Ed25519 signature over a pre-image declaring the post-quantum
    # profile. Only the profile-to-algorithm relationship is wrong.
    m = base_manifest(crypto_profile="post-quantum")
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(d.field == "signature.algorithm" for d in result.mismatch_details)


def test_pq_profile_downgrade_detected_without_trusted_keys():
    # The downgrade is a property of the manifest, not of the verifier's keys.
    m = base_manifest(crypto_profile="post-quantum")
    result = verify_manifest(m, base_context(trusted_keys={}), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "signature.algorithm" for d in result.mismatch_details)


def test_absent_algorithm_does_not_default_to_ed25519():
    m = base_manifest()
    del m["signature"]["algorithm"]
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert any(d.field == "signature.algorithm" for d in result.mismatch_details)


def test_standard_profile_with_ed25519_is_valid():
    result = verify_manifest(base_manifest(crypto_profile="standard"), base_context(), store())
    assert result.result == OverallResult.VALID
    assert result.mismatch_details == []


def test_standard_profile_with_stronger_signature_is_not_a_downgrade(monkeypatch):
    # Dual-signing ahead of the profile flip provides more than the declared
    # profile requires, so it must not be reported as a downgrade.
    ed_pub = b"e" * 32
    pq_pub = b"p" * 1952
    combined_pub = ed_pub + pq_pub
    key_id = hashlib.sha256(combined_pub).hexdigest()

    class FakeHybridVerifier:
        def __init__(self, ed25519_public_bytes, ml_dsa65_public_bytes):
            pass

        def verify(self, manifest_dict, signature_block):
            pass

    monkeypatch.setattr(_signing, "HybridVerifier", FakeHybridVerifier)
    ctx = base_context(trusted_keys={key_id: _b64url_encode(combined_pub)})

    result = verify_manifest(_hybrid_manifest(key_id), ctx, store())

    assert result.result == OverallResult.VALID
    assert not any(d.field == "signature.algorithm" for d in result.mismatch_details)


# ---------------------------------------------------------------------------
# Fail-closed HITL enforcement
# ---------------------------------------------------------------------------


def test_enforce_hitl_missing_record_fails():
    m = base_manifest(hitl_record=None)
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.MISSING
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "hitl_record" for d in result.mismatch_details)


def test_enforce_hitl_not_required_record_without_approvals_fails():
    m = base_manifest(hitl_record={"required": False, "approvals": []})
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.MISSING
    assert result.result == OverallResult.MISMATCH


def test_enforce_hitl_with_valid_approval_passes():
    approval_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {"approval_duration_seconds": 7200}
        )],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID


def test_level_2_rejects_software_key_for_high_risk_approval():
    approval_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": approval_time,
            "approved_scope": {
                "approval_duration_seconds": 7200,
                "risk_tier": "high",
            },
            "approval_method": "software-key",
        }],
    })
    result = verify_manifest(
        m,
        base_context(enforce_hitl=True, conformance_level=2),
        store(),
    )
    assert result.fields_verified.hitl_record == HitlResult.APPROVAL_INSUFFICIENT
    assert result.result == OverallResult.MISMATCH


def test_level_2_accepts_hardware_key_for_high_risk_approval():
    approval_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [hitl_approval(
            approval_time, {
                "approval_duration_seconds": 7200,
                "risk_tier": "high",
            },
            approval_method="hardware-key",
        )],
    })
    attach_transparency_entry(m)
    result = verify_manifest(
        m,
        base_context(
            enforce_hitl=True,
            conformance_level=2,
            verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
            transparency_evidence_manifest_id=m["manifest_id"],
        ),
        store(),
    )
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# HITL: at least one approval must satisfy every requirement, not every
# approval (spec 5.3: "at least one HITL approval is present, valid, not
# expired, and meets the approval_method requirement"). A verifier MUST NOT
# reject the whole record because *some other* approval in the array is
# expired, malformed, unverifiable, or insufficient. See HITL-004.
# ---------------------------------------------------------------------------


def test_hitl_valid_approval_after_expired_approval_is_approved():
    expired_time = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    valid_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [
            hitl_approval(expired_time, {"approval_duration_seconds": 3600}),
            hitl_approval(valid_time, {"approval_duration_seconds": 7200}),
        ],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID
    assert result.mismatch_details == []


def test_hitl_valid_approval_after_invalid_signature_approval_is_approved():
    valid_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    valid_approval = hitl_approval(valid_time, {"approval_duration_seconds": 7200})
    tampered_approval = dict(valid_approval)
    tampered_approval["approval_signature"] = "not-a-real-signature"
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [tampered_approval, valid_approval],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID


def test_hitl_valid_approval_after_unverifiable_approval_is_approved():
    valid_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    valid_approval = hitl_approval(valid_time, {"approval_duration_seconds": 7200})
    unverifiable_approval = dict(valid_approval)
    unverifiable_approval["approver_id"] = "mailto:unknown@example.com"
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [unverifiable_approval, valid_approval],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID


def test_hitl_valid_approval_after_insufficient_approval_is_approved():
    valid_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    software_key_approval = {
        "approver_id": APPROVER_ID,
        "approved_at": valid_time,
        "approved_scope": {
            "approval_duration_seconds": 7200,
            "risk_tier": "high",
        },
        "approval_method": "software-key",
    }
    hardware_key_approval = hitl_approval(
        valid_time,
        {"approval_duration_seconds": 7200, "risk_tier": "high"},
        approval_method="hardware-key",
    )
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [software_key_approval, hardware_key_approval],
    })
    attach_transparency_entry(m)
    result = verify_manifest(
        m,
        base_context(
            enforce_hitl=True,
            conformance_level=2,
            verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
            transparency_evidence_manifest_id=m["manifest_id"],
        ),
        store(),
    )
    assert result.fields_verified.hitl_record == HitlResult.APPROVED
    assert result.result == OverallResult.VALID


def test_hitl_all_approvals_expired_is_still_expired():
    expired_time = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [
            hitl_approval(expired_time, {"approval_duration_seconds": 3600}),
            hitl_approval(expired_time, {"approval_duration_seconds": 60}),
        ],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.EXPIRED
    assert result.result == OverallResult.MISMATCH


def test_hitl_all_approvals_invalid_is_still_invalid():
    valid_time = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    valid_approval = hitl_approval(valid_time, {"approval_duration_seconds": 7200})
    tampered_1 = dict(valid_approval)
    tampered_1["approval_signature"] = "not-a-real-signature-1"
    tampered_2 = dict(valid_approval)
    tampered_2["approval_signature"] = "not-a-real-signature-2"
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [tampered_1, tampered_2],
    })
    result = verify_manifest(m, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.INVALID
    assert result.result == OverallResult.MISMATCH


# ---------------------------------------------------------------------------
# HITL: precedence when approvals fail for *different* reasons and none is
# valid. No approval in the array is fully valid in any of the pairs below,
# so `any_approved` is never true; the result is a deliberate, order-
# independent precedence, not the position of the first bad approval in the
# array (that was the pre-fix behavior and was never a documented contract -
# see HITL-004 changelog entry). The precedence is:
#
#   INVALID > APPROVAL_INSUFFICIENT > EXPIRED > UNVERIFIABLE
#
# INVALID, APPROVAL_INSUFFICIENT, and EXPIRED are all positive, concrete
# evidence of a problem and always add a MismatchDetail, so their relative
# order does not change the overall result (always MISMATCH either way) -
# INVALID is ranked highest among them because a broken/tampered signature
# is the strongest evidence of active tampering. UNVERIFIABLE is ranked
# last and deliberately excluded from that ordering question: it means
# "this verifier lacks the key to even check," not proof of a problem, and
# it adds no MismatchDetail. Letting it outrank a concrete finding would
# silently drop that finding from `mismatch_details` and downgrade the
# overall result from MISMATCH to UNVERIFIABLE - so it only wins when it is
# the *only* thing wrong with the array.
# ---------------------------------------------------------------------------

_HITL_FAILURE_BUILDERS = {}


def _hitl_precedence_case(label):
    def register(fn):
        _HITL_FAILURE_BUILDERS[label] = fn
        return fn
    return register


@_hitl_precedence_case("INVALID")
def _mk_invalid():
    t = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    a = dict(hitl_approval(t, {"approval_duration_seconds": 7200}))
    a["approval_signature"] = "not-a-real-signature"
    return a


@_hitl_precedence_case("UNVERIFIABLE")
def _mk_unverifiable():
    t = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    a = dict(hitl_approval(t, {"approval_duration_seconds": 7200}))
    a["approver_id"] = "mailto:unknown@example.com"
    return a


@_hitl_precedence_case("EXPIRED")
def _mk_expired():
    t = (NOW - timedelta(hours=5)).isoformat().replace("+00:00", "Z")
    return hitl_approval(t, {"approval_duration_seconds": 3600})


@_hitl_precedence_case("APPROVAL_INSUFFICIENT")
def _mk_insufficient():
    t = (NOW - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    return {
        "approver_id": APPROVER_ID,
        "approved_at": t,
        "approved_scope": {"approval_duration_seconds": 7200, "risk_tier": "high"},
        "approval_method": "software-key",
    }


_HITL_PRECEDENCE_RANK = ["INVALID", "APPROVAL_INSUFFICIENT", "EXPIRED", "UNVERIFIABLE"]


@pytest.mark.parametrize("first", _HITL_PRECEDENCE_RANK)
@pytest.mark.parametrize("second", _HITL_PRECEDENCE_RANK)
def test_hitl_mixed_failure_precedence_is_order_independent(first, second):
    if first == second:
        pytest.skip("covered by the homogeneous-failure tests above")
    approvals = [_HITL_FAILURE_BUILDERS[first](), _HITL_FAILURE_BUILDERS[second]()]
    m = base_manifest(hitl_record={"required": True, "approvals": approvals})
    result = verify_manifest(
        m, base_context(enforce_hitl=True, conformance_level=2), store()
    )
    expected = min((first, second), key=_HITL_PRECEDENCE_RANK.index)
    assert result.fields_verified.hitl_record.name == expected, (
        f"[{first}, {second}] should resolve to {expected} regardless of "
        f"array order, got {result.fields_verified.hitl_record.name}"
    )
    if expected == "UNVERIFIABLE":
        assert result.result == OverallResult.UNVERIFIABLE
        assert result.mismatch_details == []
    else:
        assert result.result == OverallResult.MISMATCH
        # A concrete failure elsewhere must never be dropped just because
        # an unrelated approval in the same array was unverifiable.
        assert result.mismatch_details != []


# ---------------------------------------------------------------------------
# Fail-closed delegation chain verification (spec 3.4.1 / 5.2)
# ---------------------------------------------------------------------------


def test_delegation_chain_without_keys_is_unverifiable():
    m = base_manifest(delegation_chain=[{
        "hop": 0, "principal_type": "human",
        "principal_id": "did:web:example",
        "delegated_at": NOW.isoformat(),
        "scope_grant": {"max_delegation_depth": 3, "ttl_seconds": 3600},
        "delegation_signature": "sig",
    }])
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.delegation_chain == DelegationResult.UNVERIFIABLE
    assert result.result == OverallResult.UNVERIFIABLE


# ---------------------------------------------------------------------------
# Version negotiation (spec 2.2 / 2.4)
# ---------------------------------------------------------------------------


def test_unsupported_version_is_incompatible():
    # 0.2 is supported (the COSE envelope); 0.3 does not exist.
    m = base_manifest(version="0.3")
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.INCOMPATIBLE_VERSION


def test_missing_version_is_incompatible():
    m = base_manifest()
    del m["version"]
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.INCOMPATIBLE_VERSION


def test_supported_version_passes_version_gate():
    result = verify_manifest(base_manifest(version="0.1"), base_context(), store())
    assert result.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# Fix #3: schema validation on the verify path (fail-closed)
# ---------------------------------------------------------------------------


def test_unknown_top_level_field_fails_schema():
    m = base_manifest(rogue_field="injected")
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field.startswith("schema") for d in result.mismatch_details)


def test_unknown_nested_field_fails_schema():
    m = base_manifest()
    m["artifacts"]["system_prompt"]["rogue_field"] = "injected"
    result = verify_manifest(sign(m), base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field.startswith("schema") for d in result.mismatch_details)


def test_malformed_expires_at_fails_schema_not_silently_valid():
    # A malformed expires_at must be a failure, not a silently non-expiring
    # manifest. Re-sign so the signature itself is not the failure.
    m = base_manifest()
    m["expires_at"] = "not-a-real-timestamp"
    result = verify_manifest(sign(m), base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field.startswith("schema") for d in result.mismatch_details)


def test_bad_enum_value_fails_schema():
    m = base_manifest(crypto_profile="totally-not-a-profile")
    result = verify_manifest(m, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert any(d.field.startswith("schema") for d in result.mismatch_details)


# GHSA-mqqg-9mpc-mpg7: spec v0.2 5.3 requires audit_key_sealed=true under
# enforce_attestation. The engine read audit_chain_root but never this flag, so
# true and false produced the same VALID.

def _appraised_ctx(m, **overrides):
    return base_context(
        enforce_attestation=True,
        verified_attestation_manifest_hashes={_manifest_hash(m)},
        attestation_evidence_manifest_id=m["manifest_id"],
        **overrides,
    )


def test_audit_key_sealed_true_is_accepted_under_enforcement():
    m = base_manifest()
    m["attestation"] = {
        "platform": "tpm",
        "manifest_hash_in_report": _manifest_hash(m),
        "audit_key_sealed": True,
    }

    result = verify_manifest(m, _appraised_ctx(m), store())

    assert result.result == OverallResult.VALID


def test_audit_key_sealed_false_is_rejected_under_enforcement():
    m = base_manifest()
    m["attestation"] = {
        "platform": "tpm",
        "manifest_hash_in_report": _manifest_hash(m),
        "audit_key_sealed": False,
    }

    result = verify_manifest(m, _appraised_ctx(m), store())

    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_audit_key_sealed_absent_is_rejected_under_enforcement():
    """Absent is not sealed. Spec 5.3 requires the flag to be present and true."""
    m = base_manifest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": _manifest_hash(m)}

    result = verify_manifest(m, _appraised_ctx(m), store())

    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


# ---------------------------------------------------------------------------
# GHSA-6hjj-gh3c-r6wv: an extra omission must not improve the verdict.
#
# models._validate_manifest_profile enforces the full-binding requirement, but
# it is a mode="after" model validator, so Pydantic runs it only once every
# field has validated. Deleting a nested required field stopped it running, and
# _strict_schema_violations then filtered that nested "missing" error away for
# legacy compatibility. Nothing survived: the manifest missing a required
# binding AND a nested field returned VALID, while the one missing only the
# required binding returned MISMATCH.
# ---------------------------------------------------------------------------

def _without_model_identity():
    m = base_manifest()
    m["artifacts"] = {k: v for k, v in m["artifacts"].items() if k != "model_identity"}
    return m


def test_full_binding_manifest_without_model_identity_is_a_mismatch():
    """The B1 baseline: the independent failure on its own."""
    result = verify_manifest(sign(_without_model_identity()), base_context(), store())

    assert result.result == OverallResult.MISMATCH


def test_a_further_nested_omission_does_not_rescue_the_verdict():
    """The B3 case: removing more must never verify better."""
    m = _without_model_identity()
    m["artifacts"]["system_prompt"] = {
        k: v for k, v in m["artifacts"]["system_prompt"].items() if k != "hash"
    }

    result = verify_manifest(sign(m), base_context(), store())

    assert result.result == OverallResult.MISMATCH
    assert any(
        "full-binding manifest is missing required artifacts" in d.actual_hash
        for d in result.mismatch_details
    )


def test_nested_omissions_alone_are_still_tolerated():
    """The legacy compatibility this filter exists for is unchanged.

    An incomplete artifact binding is appraised as NOT_BOUND, not rejected.
    Only the top-level full-binding requirement stopped being maskable.
    """
    m = base_manifest()
    m["artifacts"]["system_prompt"] = {
        k: v for k, v in m["artifacts"]["system_prompt"].items() if k != "hash"
    }

    result = verify_manifest(sign(m), base_context(), store())

    assert result.result != OverallResult.MISMATCH
