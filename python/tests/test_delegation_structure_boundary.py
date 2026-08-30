from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_manifest import DelegationHopSigner, generate_ed25519, verify_delegation_chain

MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
NOW = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
SCOPE = {
    "tools": ["com.example.read"],
    "data_classifications": ["internal"],
    "max_delegation_depth": 3,
    "ttl_seconds": 3600,
    "constraints": [],
}


def _signed_hop(*, principal_id: str = "spiffe://x/root"):
    key = generate_ed25519()
    signature = DelegationHopSigner(key).sign_hop(
        hop=0,
        principal_id=principal_id,
        principal_type="agent",
        delegated_at=NOW,
        scope_grant=SCOPE,
        manifest_id=MID,
    )
    hop = {
        "hop": 0,
        "principal_id": principal_id,
        "principal_type": "agent",
        "delegated_at": NOW,
        "scope_grant": dict(SCOPE),
        "delegation_signature": signature,
    }
    return hop, {principal_id: key.public_bytes}


def _minimal_hop() -> dict:
    hop, _ = _signed_hop()
    return hop


def test_valid_single_hop_control_is_unchanged() -> None:
    hop, keys = _signed_hop()
    verify_delegation_chain([hop], keys, MID, manifest_issuer=hop["principal_id"])


@pytest.mark.parametrize("chain", ["bad", 1, True, {}])
def test_non_list_chain_uses_documented_value_error(chain) -> None:
    with pytest.raises(ValueError, match="delegation_chain must be a list"):
        verify_delegation_chain(chain, {}, MID)  # type: ignore[arg-type]


@pytest.mark.parametrize("root", ["bad", ["bad"], 1, True])
def test_non_object_root_uses_documented_value_error(root) -> None:
    with pytest.raises(ValueError, match="Delegation hop 0 must be an object"):
        verify_delegation_chain([root], {}, MID, manifest_issuer="spiffe://x/root")


def test_missing_scope_grant_is_reported_before_root_interpretation() -> None:
    root = _minimal_hop()
    del root["scope_grant"]
    with pytest.raises(ValueError, match="missing required fields.*scope_grant"):
        verify_delegation_chain([root], {}, MID, manifest_issuer="spiffe://x/root")


@pytest.mark.parametrize("scope", ["bad", ["bad"], 1, True])
def test_non_object_scope_grant_uses_documented_value_error(scope) -> None:
    root = _minimal_hop()
    root["scope_grant"] = scope
    with pytest.raises(ValueError, match="scope_grant must be an object"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("principal_type", [["agent"], {"agent": True}])
def test_unhashable_principal_type_does_not_escape_type_error(principal_type) -> None:
    root = _minimal_hop()
    root["principal_type"] = principal_type
    with pytest.raises(ValueError, match="invalid principal_type"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("principal_manifest_id", [["manifest"], {"id": "manifest"}])
def test_unhashable_principal_manifest_id_is_refused_before_root_binding(
    principal_manifest_id,
) -> None:
    root = _minimal_hop()
    root["principal_manifest_id"] = principal_manifest_id
    with pytest.raises(ValueError, match="principal_manifest_id must be a string"):
        verify_delegation_chain([root], {}, MID, manifest_issuer="manifest")


@pytest.mark.parametrize("field", ["tools", "data_classifications", "constraints"])
@pytest.mark.parametrize("value", [1, {"x": 1}, [{"x": 1}]])
def test_scope_collection_types_are_established_before_set_operations(field, value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, field: value}
    with pytest.raises(ValueError, match=rf"scope_grant\.{field} must be a list of strings"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("value", [True, "3", []])
def test_max_delegation_depth_type_is_established_before_comparison(value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, "max_delegation_depth": value}
    with pytest.raises(ValueError, match="max_delegation_depth must be a non-negative integer"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("value", [True, "60", []])
def test_ttl_type_is_established_before_comparison(value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, "ttl_seconds": value}
    with pytest.raises(ValueError, match="ttl_seconds must be a positive integer or null"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("signature", [1, []])
def test_signature_type_is_established_before_len(signature) -> None:
    root = _minimal_hop()
    root["delegation_signature"] = signature
    with pytest.raises(ValueError, match="delegation_signature must be a string"):
        verify_delegation_chain([root], {}, MID)


def test_malformed_later_hop_is_rejected_before_crypto_interpretation() -> None:
    root = _minimal_hop()
    later = _minimal_hop()
    later["hop"] = 1
    later["scope_grant"] = "bad"
    with pytest.raises(ValueError, match="Delegation hop 1 scope_grant must be an object"):
        verify_delegation_chain([root, later], {}, MID)


def test_structurally_valid_root_mismatch_keeps_existing_binding_failure() -> None:
    root = _minimal_hop()
    with pytest.raises(ValueError, match="does not match the manifest"):
        verify_delegation_chain([root], {}, MID, manifest_issuer="spiffe://x/other")
