"""Composition-only manifest profile conformance and security tests (#256)."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_manifest import Manifest, SIGNED_FIELDS
from agent_manifest._signing import Ed25519Signer, generate_ed25519, signing_pre_image
from agent_manifest._verify import (
    FieldResult,
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)


NOW = datetime.now(timezone.utc)
SHA = "sha256:" + "a" * 64
UNBOUND = [
    "tool_manifest",
    "model_identity",
    "rag_corpus",
    "memory_baseline",
    "decision_trace",
    "delegation_chain",
    "supply_chain",
    "hitl_record",
]


def composition_manifest() -> dict:
    return {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/composition/repository",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer/ci",
        "crypto_profile": "standard",
        "profile": "composition-only",
        "unbound_artifacts": list(UNBOUND),
        "artifacts": {
            "system_prompt": {
                "hash": SHA,
                "version": "repo-head",
                "classification": "internal",
                "bound_at": NOW.isoformat().replace("+00:00", "Z"),
            },
            "policy_bundle": {
                "hash": "sha256:" + "b" * 64,
                "policy_language": "cedar",
                "version": "repo-head",
                "enforcement_mode": "enforce",
                "bound_at": NOW.isoformat().replace("+00:00", "Z"),
            },
        },
    }


def test_composition_only_accepts_an_explicitly_declared_subset() -> None:
    parsed = Manifest.model_validate(composition_manifest())
    assert parsed.profile.value == "composition-only"
    assert parsed.artifacts.model_identity is None


@pytest.mark.parametrize("mutation", ["empty", "overlap", "undeclared"])
def test_composition_only_rejects_ambiguous_coverage(mutation: str) -> None:
    manifest = composition_manifest()
    if mutation == "empty":
        manifest["unbound_artifacts"] = []
    elif mutation == "overlap":
        manifest["unbound_artifacts"].append("system_prompt")
    else:
        manifest["unbound_artifacts"].remove("model_identity")

    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest)


def test_full_binding_default_still_rejects_a_missing_model() -> None:
    manifest = composition_manifest()
    manifest.pop("profile")
    manifest.pop("unbound_artifacts")
    with pytest.raises(ValidationError, match="model_identity"):
        Manifest.model_validate(manifest)


def test_profile_limitations_are_signature_covered() -> None:
    manifest = composition_manifest()
    assert "profile" in SIGNED_FIELDS
    assert "unbound_artifacts" in SIGNED_FIELDS
    original = signing_pre_image(manifest)
    manifest["unbound_artifacts"].remove("model_identity")
    assert signing_pre_image(manifest) != original


def test_absent_profile_preserves_legacy_signing_bytes() -> None:
    manifest = composition_manifest()
    manifest.pop("profile")
    manifest.pop("unbound_artifacts")
    with_explicit_nulls = dict(manifest, profile=None, unbound_artifacts=None)
    assert signing_pre_image(with_explicit_nulls) == signing_pre_image(manifest)


def test_reordering_signed_unbound_declaration_invalidates_signature() -> None:
    manifest = composition_manifest()
    key = generate_ed25519()
    manifest["signature"] = Ed25519Signer(key).sign(manifest)
    manifest["unbound_artifacts"] = list(reversed(manifest["unbound_artifacts"]))

    result = verify_manifest(
        manifest,
        VerificationContext(trusted_keys={key.key_id: key.public_b64url()}),
        RevocationStore(),
    )
    assert result.result == OverallResult.MISMATCH
    assert any(detail.field == "signature" for detail in result.mismatch_details)


def test_composition_only_verifies_as_incomplete_with_declared_not_bound_fields() -> None:
    manifest = composition_manifest()
    key = generate_ed25519()
    manifest["signature"] = Ed25519Signer(key).sign(manifest)
    result = verify_manifest(
        manifest,
        VerificationContext(
            system_prompt_hash=SHA,
            policy_bundle_hash="sha256:" + "b" * 64,
            enforcement_mode="enforce",
            trusted_keys={key.key_id: key.public_b64url()},
        ),
        RevocationStore(),
    )
    assert result.result == OverallResult.INCOMPLETE
    assert result.signature_verified is True
    assert result.fields_verified.system_prompt == FieldResult.MATCH
    assert result.fields_verified.model_identity == FieldResult.NOT_BOUND
    assert result.mismatch_details == []
