"""Integration tests for delegation chain verification via verify_manifest.

Covers the full path: manifest dict → verify_manifest → VerificationResult,
exercising DelegationResult states and the require_delegation enforcement.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest
from agent_manifest._delegation import (
    DelegationHopSigner,
    _validate_hop_structure,
)
from agent_manifest._signing import Ed25519Signer, generate_ed25519
from agent_manifest._verify import (
    DelegationResult,
    OverallResult,
    RevocationStore,
    VerificationContext,
    VerifyRequest,
    verify_manifest,
)

NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
SHA = "sha256:" + "a" * 64
# The manifest signing identity (agent_id) the chain root MUST be bound to.
AGENT_ID = "spiffe://trust.example/agent/kyc/prod"

SCOPE = {
    "tools": ["com.example.read"],
    "data_classifications": ["internal"],
    "max_delegation_depth": 3,
    "ttl_seconds": 3600,
    "constraints": [],
}

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}


def sign(m: dict) -> dict:
    m["signature"] = Ed25519Signer(KP).sign(m)
    return m


def base_manifest(delegation_chain=None, **overrides) -> dict:
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW,
        "expires_at": "2099-01-01T00:00:00Z",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {"model_hash": None, "version": "claude-3", "deployment_type": "api"},
        },
        "delegation_chain": delegation_chain if delegation_chain is not None else [],
        "hitl_record": None,
    }
    m.update(overrides)
    return sign(m)


def base_context(**overrides) -> VerificationContext:
    ctx = VerificationContext(
        system_prompt_hash=SHA,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def store() -> RevocationStore:
    return RevocationStore()


def _make_chain(kp, principal_id="spiffe://trust.example/agent/root", n_hops=1) -> list:
    chain = []
    for i in range(n_hops):
        hop_kp = kp if i == 0 else generate_ed25519()
        sig = DelegationHopSigner(keypair=kp if i == 0 else hop_kp).sign_hop(
            hop=i,
            principal_id=principal_id if i == 0 else f"spiffe://trust.example/agent/sub{i}",
            principal_type="agent",
            delegated_at=NOW,
            scope_grant=SCOPE,
            manifest_id=MID,
        )
        chain.append({
            "hop": i,
            "principal_id": principal_id if i == 0 else f"spiffe://trust.example/agent/sub{i}",
            "principal_type": "agent",
            "delegated_at": NOW,
            "scope_grant": SCOPE,
            "delegation_signature": sig,
        })
    return chain


# ---------------------------------------------------------------------------
# VALID - chain present and verified
# ---------------------------------------------------------------------------


def test_valid_chain_single_hop():
    kp = generate_ed25519()
    pid = AGENT_ID  # chain root must be bound to the manifest signing identity
    chain = _make_chain(kp, principal_id=pid)
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.VALID
    assert result.result == OverallResult.VALID


def test_valid_chain_multi_hop():
    root_kp = generate_ed25519()
    sub_kp = generate_ed25519()
    root_pid = AGENT_ID  # root bound to manifest signing identity
    sub_pid = "spiffe://trust.example/sub"
    narrow_scope = {**SCOPE, "tools": ["com.example.read"]}

    root_sig = DelegationHopSigner(root_kp).sign_hop(
        hop=0, principal_id=root_pid, principal_type="human",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    sub_sig = DelegationHopSigner(sub_kp).sign_hop(
        hop=1, principal_id=sub_pid, principal_type="agent",
        delegated_at=NOW, scope_grant=narrow_scope, manifest_id=MID,
    )
    chain = [
        {"hop": 0, "principal_id": root_pid, "principal_type": "human",
         "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": root_sig},
        {"hop": 1, "principal_id": sub_pid, "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": narrow_scope, "delegation_signature": sub_sig},
    ]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={
        root_pid: root_kp.public_b64url(),
        sub_pid: sub_kp.public_b64url(),
    })
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.VALID
    assert result.result == OverallResult.VALID


def test_valid_chain_agent_principal_type():
    # principal_type must be a schema-valid PrincipalType (human/system/agent);
    # the manifest schema gate rejects out-of-enum values such as "service".
    kp = generate_ed25519()
    pid = AGENT_ID  # root bound to manifest signing identity
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id=pid, principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{"hop": 0, "principal_id": pid, "principal_type": "agent",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.VALID


# ---------------------------------------------------------------------------
# UNVERIFIABLE - chain present but no keys supplied
# ---------------------------------------------------------------------------


def test_chain_root_not_bound_to_issuer_is_mismatch():
    """Fix #1: a verifiable chain whose root != manifest signing identity fails."""
    kp = generate_ed25519()
    rogue_pid = "spiffe://trust.example/attacker"  # not the manifest agent_id
    chain = _make_chain(kp, principal_id=rogue_pid)
    m = base_manifest(delegation_chain=chain)  # agent_id is AGENT_ID, not rogue_pid
    ctx = base_context(delegation_public_keys={rogue_pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.INVALID
    assert result.result == OverallResult.MISMATCH
    assert any(
        "does not match the manifest" in d.actual_hash
        for d in result.mismatch_details
    )


def test_chain_root_bound_to_issuer_field_is_valid():
    """When issuer is set, a chain rooted at the issuer verifies."""
    kp = generate_ed25519()
    issuer = "spiffe://trust.example/signing-authority"
    chain = _make_chain(kp, principal_id=issuer)
    m = base_manifest(delegation_chain=chain, issuer=issuer)
    ctx = base_context(delegation_public_keys={issuer: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.VALID
    assert result.result == OverallResult.VALID


def test_chain_without_keys_is_unverifiable():
    kp = generate_ed25519()
    pid = "spiffe://trust.example/agent/root"
    chain = _make_chain(kp, principal_id=pid)
    m = base_manifest(delegation_chain=chain)
    # No delegation_public_keys - must fail closed
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.delegation_chain == DelegationResult.UNVERIFIABLE
    assert result.result == OverallResult.UNVERIFIABLE


# ---------------------------------------------------------------------------
# INVALID - bad signature surfaces as MISMATCH
# ---------------------------------------------------------------------------


def test_invalid_chain_signature_is_mismatch():
    kp = generate_ed25519()
    pid = "spiffe://trust.example/agent/root"
    chain = _make_chain(kp, principal_id=pid)
    # Tamper the signature
    chain[0]["delegation_signature"] = base64.urlsafe_b64encode(b"\x00" * 64).rstrip(b"=").decode()

    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.INVALID
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "delegation_chain" for d in result.mismatch_details)


def test_cross_manifest_replay_is_mismatch():
    """Signature from a different manifest_id must not verify."""
    kp = generate_ed25519()
    pid = "spiffe://trust.example/agent/root"
    # Sign for a different manifest_id
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id=pid, principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id="wrong-manifest-id",
    )
    chain = [{"hop": 0, "principal_id": pid, "principal_type": "agent",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.INVALID
    assert result.result == OverallResult.MISMATCH


def test_scope_laundering_is_mismatch():
    root_kp = generate_ed25519()
    sub_kp = generate_ed25519()
    root_pid = "spiffe://trust.example/root"
    sub_pid = "spiffe://trust.example/sub"

    root_scope = {"tools": ["com.example.read"], "max_delegation_depth": 3, "ttl_seconds": 3600}
    expanded_scope = {"tools": ["com.example.read", "com.example.delete"],
                      "max_delegation_depth": 2, "ttl_seconds": 3600}

    root_sig = DelegationHopSigner(root_kp).sign_hop(
        hop=0, principal_id=root_pid, principal_type="human",
        delegated_at=NOW, scope_grant=root_scope, manifest_id=MID,
    )
    sub_sig = DelegationHopSigner(sub_kp).sign_hop(
        hop=1, principal_id=sub_pid, principal_type="agent",
        delegated_at=NOW, scope_grant=expanded_scope, manifest_id=MID,
    )
    chain = [
        {"hop": 0, "principal_id": root_pid, "principal_type": "human",
         "delegated_at": NOW, "scope_grant": root_scope, "delegation_signature": root_sig},
        {"hop": 1, "principal_id": sub_pid, "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": expanded_scope, "delegation_signature": sub_sig},
    ]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={
        root_pid: root_kp.public_b64url(),
        sub_pid: sub_kp.public_b64url(),
    })
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.INVALID
    assert result.result == OverallResult.MISMATCH


def test_depth_exceeded_is_mismatch():
    """Chain exceeding root's max_delegation_depth should surface as MISMATCH."""
    kp = generate_ed25519()
    pid = "spiffe://trust.example/root"
    # Root allows depth=1 (at most 2 hops); we build 3 hops → depth=2 > 1
    shallow_scope = {**SCOPE, "max_delegation_depth": 1}
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id=pid, principal_type="human",
        delegated_at=NOW, scope_grant=shallow_scope, manifest_id=MID,
    )
    # Build extra hops with dummy sigs - depth check fires before sig check
    chain = [
        {"hop": 0, "principal_id": pid, "principal_type": "human",
         "delegated_at": NOW, "scope_grant": shallow_scope, "delegation_signature": sig},
        {"hop": 1, "principal_id": "spiffe://x/a1", "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": shallow_scope, "delegation_signature": "a" * 86},
        {"hop": 2, "principal_id": "spiffe://x/a2", "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": shallow_scope, "delegation_signature": "a" * 86},
    ]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.INVALID
    assert result.result == OverallResult.MISMATCH


# ---------------------------------------------------------------------------
# NOT_PRESENT
# ---------------------------------------------------------------------------


def test_no_chain_is_not_present():
    m = base_manifest(delegation_chain=[])
    result = verify_manifest(m, base_context(), store())
    assert result.fields_verified.delegation_chain == DelegationResult.NOT_PRESENT
    assert result.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# require_delegation enforcement
# ---------------------------------------------------------------------------


def test_require_delegation_with_no_chain_is_mismatch():
    m = base_manifest(delegation_chain=[])
    ctx = base_context(require_delegation=True)
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.NOT_PRESENT
    assert result.result == OverallResult.MISMATCH
    assert any(d.field == "delegation_chain" for d in result.mismatch_details)


def test_require_delegation_with_valid_chain_is_valid():
    kp = generate_ed25519()
    pid = AGENT_ID  # root bound to manifest signing identity
    chain = _make_chain(kp, principal_id=pid)
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(
        require_delegation=True,
        delegation_public_keys={pid: kp.public_b64url()},
    )
    result = verify_manifest(m, ctx, store())
    assert result.fields_verified.delegation_chain == DelegationResult.VALID
    assert result.result == OverallResult.VALID


def test_require_delegation_exposed_in_verify_request():
    req = VerifyRequest(manifest_id=MID, require_delegation=True)
    assert req.require_delegation is True


def test_require_delegation_defaults_to_false_in_verify_request():
    req = VerifyRequest(manifest_id=MID)
    assert req.require_delegation is False


# ---------------------------------------------------------------------------
# A2A structural validation (_validate_hop_structure)
# ---------------------------------------------------------------------------


def test_invalid_principal_type_raises():
    bad_hop = {
        "hop": 0, "principal_id": "spiffe://x/agent",
        "principal_type": "robot",  # not in VALID_PRINCIPAL_TYPES
        "delegated_at": NOW, "scope_grant": SCOPE,
        "delegation_signature": "sig",
    }
    with pytest.raises(ValueError, match="invalid principal_type"):
        _validate_hop_structure(bad_hop, 0)


def test_missing_required_hop_field_raises():
    incomplete_hop = {
        "hop": 0, "principal_id": "spiffe://x/agent",
        # missing principal_type, delegated_at, scope_grant, delegation_signature
    }
    with pytest.raises(ValueError, match="missing required fields"):
        _validate_hop_structure(incomplete_hop, 0)


def test_empty_principal_id_raises():
    bad_hop = {
        "hop": 0, "principal_id": "",
        "principal_type": "agent",
        "delegated_at": NOW, "scope_grant": SCOPE,
        "delegation_signature": "sig",
    }
    with pytest.raises(ValueError, match="empty"):
        _validate_hop_structure(bad_hop, 0)


def test_invalid_principal_type_via_verify_manifest():
    """Structural violation in chain must surface as MISMATCH via full verify path."""
    kp = generate_ed25519()
    pid = AGENT_ID  # root bound to manifest signing identity
    # Build valid sig but inject invalid principal_type
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id=pid, principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{"hop": 0, "principal_id": pid, "principal_type": "robot",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    m = base_manifest(delegation_chain=chain)
    ctx = base_context(delegation_public_keys={pid: kp.public_b64url()})
    result = verify_manifest(m, ctx, store())
    # An out-of-enum principal_type is now caught fail-closed by the manifest
    # schema gate, which runs before delegation processing.
    assert result.result == OverallResult.MISMATCH
    assert any(d.field.startswith("schema") for d in result.mismatch_details)
