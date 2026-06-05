"""Tests for A2A delegation chain and HITL approval signing — issues #12 and #13."""
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidSignature

from agent_manifest._delegation import (
    DelegationHopSigner,
    HitlApprovalSigner,
    _approval_pre_image,
    _hop_pre_image,
    verify_delegation_chain,
    verify_hitl_approval,
)
from agent_manifest._signing import generate_ed25519

NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
SCOPE = {"tools": ["com.example.read"], "data_classifications": ["internal"],
         "max_delegation_depth": 3, "ttl_seconds": 3600, "constraints": []}


# ---------------------------------------------------------------------------
# Delegation chain signing
# ---------------------------------------------------------------------------

def test_hop_pre_image_includes_manifest_id():
    pre = _hop_pre_image(0, "spiffe://x/agent", "agent", NOW, SCOPE, MID)
    assert MID.encode() in pre

def test_hop_pre_image_includes_scope():
    pre = _hop_pre_image(0, "spiffe://x/agent", "agent", NOW, SCOPE, MID)
    assert b"com.example.read" in pre

def test_hop_pre_image_deterministic():
    p1 = _hop_pre_image(0, "spiffe://x/a", "agent", NOW, SCOPE, MID)
    p2 = _hop_pre_image(0, "spiffe://x/a", "agent", NOW, SCOPE, MID)
    assert p1 == p2

def test_hop_pre_image_different_hops():
    p0 = _hop_pre_image(0, "spiffe://x/a", "agent", NOW, SCOPE, MID)
    p1 = _hop_pre_image(1, "spiffe://x/a", "agent", NOW, SCOPE, MID)
    assert p0 != p1

def test_delegation_sign_verify_single_hop():
    kp = generate_ed25519()
    signer = DelegationHopSigner(keypair=kp)
    sig = signer.sign_hop(
        hop=0, principal_id="spiffe://x/orchestrator", principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{
        "hop": 0, "principal_id": "spiffe://x/orchestrator", "principal_type": "agent",
        "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig,
    }]
    verify_delegation_chain(chain, {"spiffe://x/orchestrator": kp.public_bytes}, MID)

def test_delegation_wrong_key_fails():
    kp1, kp2 = generate_ed25519(), generate_ed25519()
    sig = DelegationHopSigner(kp1).sign_hop(
        hop=0, principal_id="spiffe://x/o", principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{"hop": 0, "principal_id": "spiffe://x/o", "principal_type": "agent",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    with pytest.raises(InvalidSignature):
        verify_delegation_chain(chain, {"spiffe://x/o": kp2.public_bytes}, MID)

def test_delegation_wrong_manifest_id_fails():
    kp = generate_ed25519()
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id="spiffe://x/o", principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{"hop": 0, "principal_id": "spiffe://x/o", "principal_type": "agent",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    with pytest.raises(InvalidSignature):
        verify_delegation_chain(chain, {"spiffe://x/o": kp.public_bytes}, "wrong-id")

def test_scope_laundering_detected():
    kp = generate_ed25519()
    root_scope = {"tools": ["com.example.read"], "max_delegation_depth": 3, "ttl_seconds": 3600}
    expanded_scope = {"tools": ["com.example.read", "com.example.delete"],
                      "max_delegation_depth": 2, "ttl_seconds": 3600}

    sig0 = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id="spiffe://x/root", principal_type="human",
        delegated_at=NOW, scope_grant=root_scope, manifest_id=MID,
    )
    kp2 = generate_ed25519()
    sig1 = DelegationHopSigner(kp2).sign_hop(
        hop=1, principal_id="spiffe://x/agent", principal_type="agent",
        delegated_at=NOW, scope_grant=expanded_scope, manifest_id=MID,
    )
    chain = [
        {"hop": 0, "principal_id": "spiffe://x/root", "principal_type": "human",
         "delegated_at": NOW, "scope_grant": root_scope, "delegation_signature": sig0},
        {"hop": 1, "principal_id": "spiffe://x/agent", "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": expanded_scope, "delegation_signature": sig1},
    ]
    with pytest.raises(ValueError, match="Scope laundering"):
        verify_delegation_chain(
            chain,
            {"spiffe://x/root": kp.public_bytes, "spiffe://x/agent": kp2.public_bytes},
            MID,
        )

def test_depth_exceeded_raises():
    narrow_scope = {**SCOPE, "max_delegation_depth": 1}
    chain = [
        {"hop": i, "principal_id": f"spiffe://x/{i}", "principal_type": "agent",
         "delegated_at": NOW, "scope_grant": narrow_scope, "delegation_signature": "sig"}
        for i in range(2)  # depth 2 > max 1
    ]
    with pytest.raises(ValueError, match="max_delegation_depth"):
        verify_delegation_chain(chain, {}, MID)

def test_empty_chain_passes():
    verify_delegation_chain([], {}, MID)

def test_missing_public_key_raises():
    kp = generate_ed25519()
    sig = DelegationHopSigner(kp).sign_hop(
        hop=0, principal_id="spiffe://x/o", principal_type="agent",
        delegated_at=NOW, scope_grant=SCOPE, manifest_id=MID,
    )
    chain = [{"hop": 0, "principal_id": "spiffe://x/o", "principal_type": "agent",
               "delegated_at": NOW, "scope_grant": SCOPE, "delegation_signature": sig}]
    with pytest.raises(ValueError, match="No public key"):
        verify_delegation_chain(chain, {}, MID)


# ---------------------------------------------------------------------------
# HITL approval signing
# ---------------------------------------------------------------------------

APPROVAL_SCOPE = {"artifacts": ["system_prompt", "policy_bundle"],
                  "risk_tier": "high", "approval_duration_seconds": 3600}

def test_approval_pre_image_includes_manifest_id():
    pre = _approval_pre_image(MID, NOW, APPROVAL_SCOPE, "did:web:approver")
    assert MID.encode() in pre

def test_approval_pre_image_includes_scope():
    pre = _approval_pre_image(MID, NOW, APPROVAL_SCOPE, "did:web:approver")
    assert b"system_prompt" in pre

def test_approval_sign_verify():
    kp = generate_ed25519()
    signer = HitlApprovalSigner(keypair=kp)
    sig = signer.sign_approval(
        manifest_id=MID, approved_at=NOW,
        approved_scope=APPROVAL_SCOPE, approver_id="did:web:ciso",
    )
    approval = {
        "manifest_id": MID, "approved_at": NOW,
        "approved_scope": APPROVAL_SCOPE, "approver_id": "did:web:ciso",
        "approval_signature": sig,
    }
    verify_hitl_approval(approval, MID, kp.public_bytes)

def test_approval_wrong_key_fails():
    kp1, kp2 = generate_ed25519(), generate_ed25519()
    sig = HitlApprovalSigner(kp1).sign_approval(
        manifest_id=MID, approved_at=NOW,
        approved_scope=APPROVAL_SCOPE, approver_id="did:web:approver",
    )
    approval = {"manifest_id": MID, "approved_at": NOW,
                "approved_scope": APPROVAL_SCOPE, "approver_id": "did:web:approver",
                "approval_signature": sig}
    with pytest.raises(InvalidSignature):
        verify_hitl_approval(approval, MID, kp2.public_bytes)

def test_approval_wrong_manifest_id_fails():
    kp = generate_ed25519()
    sig = HitlApprovalSigner(kp).sign_approval(
        manifest_id=MID, approved_at=NOW,
        approved_scope=APPROVAL_SCOPE, approver_id="did:web:approver",
    )
    approval = {"manifest_id": "wrong-id", "approved_at": NOW,
                "approved_scope": APPROVAL_SCOPE, "approver_id": "did:web:approver",
                "approval_signature": sig}
    with pytest.raises(InvalidSignature):
        verify_hitl_approval(approval, "wrong-id", kp.public_bytes)

def test_approval_scope_change_fails():
    kp = generate_ed25519()
    sig = HitlApprovalSigner(kp).sign_approval(
        manifest_id=MID, approved_at=NOW,
        approved_scope=APPROVAL_SCOPE, approver_id="did:web:approver",
    )
    modified_scope = {**APPROVAL_SCOPE, "risk_tier": "critical"}
    approval = {"manifest_id": MID, "approved_at": NOW,
                "approved_scope": modified_scope, "approver_id": "did:web:approver",
                "approval_signature": sig}
    with pytest.raises(InvalidSignature):
        verify_hitl_approval(approval, MID, kp.public_bytes)
