"""Agent identity correlation (spec 3.1 / 6.4.2 - issue #269).

`agent_id` was serving two lifetimes at once: OCSF's stable `uid` and its
session-scoped `instance_uid`. These cover the split - the new signed
`agent_instance_id`, the `correlation` block in the verification result, and
the compatibility claim that a manifest without the field signs and verifies
exactly as it did before the field existed.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest import AgentCorrelation, Manifest
from agent_manifest._signing import SIGNED_FIELDS, signing_pre_image
from agent_manifest._verify import (
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

UTC = timezone.utc
AGENT = "spiffe://trust.example/agent/kyc/prod"
INSTANCE = "01926b4c-1234-7abc-9def-000000000001"


def _manifest(**overrides):
    now = datetime.now(UTC)
    doc = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": AGENT,
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {},
    }
    doc.update(overrides)
    return doc


def _verify(doc):
    return verify_manifest(doc, VerificationContext(), RevocationStore())


# ---------------------------------------------------------------------------
# The field
# ---------------------------------------------------------------------------


def _model_manifest(**overrides):
    """A manifest the Pydantic model accepts: the three artifacts a
    full-binding document must carry, and nothing else."""
    now = datetime.now(UTC)
    sha = "sha256:" + "a" * 64
    base = dict(
        manifest_id="018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        agent_id=AGENT,
        issued_at=now,
        expires_at=now + timedelta(days=90),
        issuer="spiffe://trust.example/issuer",
        artifacts=dict(
            system_prompt=dict(hash=sha, version="1.0.0",
                               classification="internal", bound_at=now),
            policy_bundle=dict(hash=sha, policy_language="cedar", version="1.0",
                               enforcement_mode="enforce", bound_at=now),
            model_identity=dict(provider="anthropic", model_id="claude",
                                version="3", deployment_type="api",
                                model_attestation_type="provider-asserted",
                                bound_at=now),
        ),
    )
    base.update(overrides)
    return base


def test_agent_instance_id_is_optional():
    assert Manifest.model_validate(_model_manifest()).agent_instance_id is None


def test_agent_instance_id_roundtrips():
    parsed = Manifest.model_validate(_model_manifest(agent_instance_id=INSTANCE))
    assert parsed.agent_instance_id == INSTANCE


def test_agent_instance_id_must_be_a_uuid_v7():
    """A v4 here would let a producer mint instance identities that carry no
    ordering, which is half of what makes the join key useful."""
    with pytest.raises(ValueError, match="(?i)uuid"):
        Manifest.model_validate(
            _model_manifest(agent_instance_id="01926b4c-1234-4abc-9def-000000000001")
        )


def test_agent_instance_id_is_signed():
    """An instance identity the signature does not cover is one the operator
    can retarget after the fact, which is the whole point of the join key."""
    assert "agent_instance_id" in SIGNED_FIELDS


def test_adding_the_field_does_not_change_an_existing_pre_image():
    """The compatibility claim: absent fields are omitted, so every manifest
    issued before this field existed still verifies under its old signature."""
    doc = _manifest()
    pre_image = signing_pre_image(doc)
    assert b"agent_instance_id" not in pre_image


def test_declaring_the_field_changes_the_pre_image():
    """The other half: it is not decorative. Two manifests that differ only in
    the instance they name must not share a signature."""
    stable = signing_pre_image(_manifest())
    scoped = signing_pre_image(_manifest(agent_instance_id=INSTANCE))
    assert stable != scoped
    assert b"agent_instance_id" in scoped


# ---------------------------------------------------------------------------
# The correlation block in the verification result
# ---------------------------------------------------------------------------


def test_result_carries_the_stable_uid():
    result = _verify(_manifest())
    assert result.correlation == AgentCorrelation(
        agent_uid=AGENT,
        agent_instance_uid=None,
        manifest_id="018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    )


def test_result_carries_both_identities_when_the_manifest_is_instance_scoped():
    result = _verify(_manifest(agent_instance_id=INSTANCE))
    assert result.correlation is not None
    assert result.correlation.agent_uid == AGENT
    assert result.correlation.agent_instance_uid == INSTANCE


def test_the_two_identities_are_never_the_same_value():
    """Rule 3 of spec 6.4.2 read from the result side: whatever a producer puts
    in instance_uid, this object never hands it agent_id to use."""
    for doc in (_manifest(), _manifest(agent_instance_id=INSTANCE)):
        correlation = _verify(doc).correlation
        assert correlation is not None
        assert correlation.agent_instance_uid != correlation.agent_uid


def test_correlation_is_absent_only_for_malformed_input_without_agent_id():
    doc = _manifest()
    del doc["agent_id"]
    assert _verify(doc).correlation is None


def test_correlation_survives_a_failing_verification():
    """An auditor investigating a MISMATCH needs the join key most, so it is
    populated from the document rather than earned by passing."""
    doc = _manifest(expires_at=(datetime.now(UTC) - timedelta(days=1))
                    .isoformat().replace("+00:00", "Z"))
    result = _verify(doc)
    assert result.result.value != "VALID"
    assert result.correlation is not None
    assert result.correlation.agent_uid == AGENT
