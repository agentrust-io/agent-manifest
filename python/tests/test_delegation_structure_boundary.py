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


def _resigned_hop_with_delegated_at(delegated_at):
    """Build a cryptographically valid hop over the supplied JSON primitive.

    The malformed value is deliberately included in both the record and signed
    preimage so a rejection proves the structural guard is load-bearing rather
    than an incidental signature failure.
    """
    principal_id = "spiffe://x/root"
    key = generate_ed25519()
    signature = DelegationHopSigner(key).sign_hop(
        hop=0,
        principal_id=principal_id,
        principal_type="agent",
        delegated_at=delegated_at,  # type: ignore[arg-type]
        scope_grant=SCOPE,
        manifest_id=MID,
    )
    hop = {
        "hop": 0,
        "principal_id": principal_id,
        "principal_type": "agent",
        "delegated_at": delegated_at,
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


def test_valid_delegated_at_timestamp_string_remains_accepted() -> None:
    hop, keys = _signed_hop()
    assert isinstance(hop["delegated_at"], str)
    verify_delegation_chain([hop], keys, MID)


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


def test_false_hop_is_rejected_before_bool_int_equivalence_can_apply() -> None:
    root, keys = _signed_hop()
    # Keep the valid signature over integer hop 0. Before this guard, False == 0
    # let the record pass the index check and the verifier rebuilt the signed
    # preimage with integer i=0, so this malformed record verified successfully.
    root["hop"] = False
    with pytest.raises(ValueError, match="hop must be a JSON integer"):
        verify_delegation_chain([root], keys, MID)


@pytest.mark.parametrize("hop_value", [True, "0", [], {}, 0.5])
def test_non_json_integer_hop_primitives_are_refused_before_comparison(hop_value) -> None:
    root = _minimal_hop()
    root["hop"] = hop_value
    with pytest.raises(ValueError, match="hop must be a JSON integer"):
        verify_delegation_chain([root], {}, MID)


def test_zero_fraction_hop_keeps_json_integer_semantics() -> None:
    root, keys = _signed_hop()
    root["hop"] = 0.0
    # RFC 8785 canonicalizes 0 and 0.0 identically, matching the intentional
    # JSON-Schema integer semantics already used by the scope integer guards.
    verify_delegation_chain([root], keys, MID)


@pytest.mark.parametrize("delegated_at", [None, False, 0, [], {}])
def test_resigned_non_string_delegated_at_is_refused_before_preimage(delegated_at) -> None:
    root, keys = _resigned_hop_with_delegated_at(delegated_at)
    with pytest.raises(ValueError, match="delegated_at must be a string"):
        verify_delegation_chain([root], keys, MID)


@pytest.mark.parametrize("field", ["tools", "data_classifications", "constraints"])
@pytest.mark.parametrize("value", [1, {"x": 1}, [{"x": 1}]])
def test_scope_collection_types_are_established_before_set_operations(field, value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, field: value}
    with pytest.raises(ValueError, match=rf"scope_grant\.{field} must be a list of strings"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("value", [True, "3", [], 3.5])
def test_max_delegation_depth_type_is_established_before_comparison(value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, "max_delegation_depth": value}
    with pytest.raises(ValueError, match="max_delegation_depth must be a non-negative integer"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize("value", [True, "60", [], 60.5])
def test_ttl_type_is_established_before_comparison(value) -> None:
    root = _minimal_hop()
    root["scope_grant"] = {**SCOPE, "ttl_seconds": value}
    with pytest.raises(ValueError, match="ttl_seconds must be a positive integer or null"):
        verify_delegation_chain([root], {}, MID)


@pytest.mark.parametrize(
    ("field", "value"),
    [("max_delegation_depth", 3.0), ("ttl_seconds", 3600.0)],
)
def test_zero_fraction_numbers_keep_json_integer_semantics(field, value) -> None:
    root, keys = _signed_hop()
    root["scope_grant"] = {**SCOPE, field: value}
    # RFC 8785 serializes 3 and 3.0 (likewise 3600 and 3600.0) identically,
    # so the original signature remains valid and the verifier must not
    # over-discriminate on Python's host-language representation.
    verify_delegation_chain([root], keys, MID)


@pytest.mark.parametrize("signature", [1, []])
def test_signature_type_is_established_before_len(signature) -> None:
    root = _minimal_hop()
    root["delegation_signature"] = signature
    with pytest.raises(ValueError, match="delegation_signature must be a string"):
        verify_delegation_chain([root], {}, MID)


def test_malformed_later_hop_is_rejected_before_its_crypto_interpretation() -> None:
    root, keys = _signed_hop()
    later = _minimal_hop()
    later["hop"] = 1
    later["scope_grant"] = "bad"
    with pytest.raises(ValueError, match="Delegation hop 1 scope_grant must be an object"):
        verify_delegation_chain([root, later], keys, MID)


def test_structurally_valid_root_mismatch_keeps_existing_binding_failure() -> None:
    root = _minimal_hop()
    with pytest.raises(ValueError, match="does not match the manifest"):
        verify_delegation_chain([root], {}, MID, manifest_issuer="spiffe://x/other")
