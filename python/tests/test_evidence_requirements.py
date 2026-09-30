"""Experimental evidence-requirements profile: signing, fail-closed validation, disclosure."""

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta

import agent_manifest as am
import cbor2
import pytest
from agent_manifest.evidence_requirements import (
    EXPERIMENTAL_PROFILE,
    manifest_digest,
    verify_evidence_manifest,
)
from pydantic import ValidationError


@pytest.fixture
def packet():
    now = datetime.now(UTC)
    key = am.generate_ed25519()
    kid = key.key_id
    manifest = {
        "manifest_id": "01993f2c-8000-7000-8000-000000000001",
        "agent_id": "spiffe://example.test/agent/one",
        "version": "0.2",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "issuer": "spiffe://example.test/issuer",
        "crypto_profile": "standard",
        "profile": EXPERIMENTAL_PROFILE,
        "artifacts": {
            "system_prompt": {
                "hash": "sha256:" + "a" * 64,
                "version": "1",
                "classification": "public",
                "bound_at": now.isoformat(),
            },
            "policy_bundle": {
                "hash": "sha256:" + "b" * 64,
                "version": "1",
                "policy_language": "cedar",
                "enforcement_mode": "enforce",
                "bound_at": now.isoformat(),
            },
            "model_identity": {
                "provider": "test",
                "model_id": "test",
                "version": "test-model",
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now.isoformat(),
            },
        },
        "evidence_requirements": {
            "components": [
                {
                    "component_id": "runtime.cpu",
                    "component_type": "runtime",
                    "required": True,
                    "accepted_profiles": ["urn:example:snp:v1"],
                    "accepted_appraisal_authorities": ["https://verifier.example"],
                    "maximum_age_seconds": 120,
                }
            ],
            "required_bindings": [],
            "combination_policy_ref": "urn:example:policy:v1",
        },
    }
    context = am.VerificationContext(
        system_prompt_hash="sha256:" + "a" * 64,
        policy_bundle_hash="sha256:" + "b" * 64,
        model_version="test-model",
        enforcement_mode="enforce",
        trusted_keys={
            kid: base64.urlsafe_b64encode(key.public_bytes).decode().rstrip("=")
        },
        trusted_key_issuers={kid: [manifest["issuer"]]},
    )
    return manifest, key, context


def test_signed_requirements_and_exact_projection(packet):
    manifest, key, context = packet
    am.Manifest.model_validate(manifest)
    raw = am.sign_cose_sign1(manifest, key)
    verified = verify_evidence_manifest(raw, context, am.RevocationStore())
    assert verified.requirements.components[0].required is True
    assert verified.manifest_digest == manifest_digest(
        raw, media_type="application/agent-manifest+cose"
    )
    assert dict(verified.artifact_results)["system_prompt"] == "MATCH"
    assert all(
        value not in repr(verified)
        for value in ["private_key", "expected_hash", "actual_hash"]
    )


def test_requirements_change_invalidates_signature(packet):
    manifest, key, context = packet
    raw = am.sign_cose_sign1(manifest, key)
    body = list(cbor2.loads(raw).value)
    payload = json.loads(body[2])
    payload["evidence_requirements"]["components"][0]["required"] = False
    body[2] = am.canonicalize(payload)
    changed = cbor2.dumps(cbor2.CBORTag(18, body), canonical=True)
    with pytest.raises(ValueError, match="manifest appraisal not valid"):
        verify_evidence_manifest(changed, context, am.RevocationStore())
    assert manifest_digest(
        raw, media_type="application/agent-manifest+cose"
    ) != manifest_digest(changed, media_type="application/agent-manifest+cose")


@pytest.mark.parametrize(
    "change",
    [
        "profile",
        "version",
        "missing",
        "ref",
        "duplicate",
        "boolean",
        "endpoint",
        "self",
        "method",
        "critical",
    ],
)
def test_requirements_fail_closed(packet, change):
    manifest, key, context = packet
    manifest = copy.deepcopy(manifest)
    block = manifest["evidence_requirements"]
    if change == "profile":
        manifest.pop("profile")
    elif change == "version":
        manifest["version"] = "0.1"
    elif change == "missing":
        manifest.pop("evidence_requirements")
    elif change == "ref":
        block["components"][0]["artifact_ref"] = "artifacts.tool_manifest"
    elif change == "duplicate":
        block["components"].append(copy.deepcopy(block["components"][0]))
    elif change == "boolean":
        block["components"][0]["required"] = "true"
    elif change in ("endpoint", "self", "method"):
        block["required_bindings"] = [
            {
                "source": "runtime.cpu",
                "target": "missing" if change == "endpoint" else "runtime.cpu",
                "relationship": "same-workload",
                "accepted_methods": [
                    "unknown" if change == "method" else "same-instance-v1"
                ],
            }
        ]
    else:
        block["components"][0]["critical"] = "unknown-mechanism"
    with pytest.raises(ValidationError):
        am.Manifest.model_validate(manifest)
    if manifest["version"] == "0.2":
        raw = am.sign_cose_sign1(manifest, key)
        with pytest.raises(ValueError):
            verify_evidence_manifest(raw, context, am.RevocationStore())


def test_legacy_profiles_cannot_smuggle_signed_block(packet):
    manifest, key, context = packet
    manifest.pop("profile")
    manifest.pop("evidence_requirements")
    before = am.signing_pre_image(manifest)
    assert am.Manifest.model_validate(manifest).evidence_requirements is None
    assert (
        am.signing_pre_image(
            am.Manifest.model_validate(manifest).model_dump(
                mode="json", exclude_none=True, by_alias=True
            )
        )
        != b""
    )
    assert b"evidence_requirements" not in before
    raw = am.sign_cose_sign1(manifest, key)
    assert (
        am.verify_manifest(raw, context, am.RevocationStore()).result.value == "VALID"
    )
    with pytest.raises(ValueError, match="profile required"):
        verify_evidence_manifest(raw, context, am.RevocationStore())


@pytest.mark.parametrize(
    "media_type,value",
    [
        ("unknown", b"x"),
        ("application/agent-manifest+cose", {}),
        ("application/agent-manifest+cose", b""),
        ("application/agent-manifest+json", b'{"duplicate":1,"duplicate":2}'),
    ],
)
def test_digest_does_not_guess_formats(media_type, value):
    with pytest.raises(ValueError):
        manifest_digest(value, media_type=media_type)


def test_unprofiled_block_rejected_even_with_tolerated_omission(packet):
    # The verifier tolerates a missing field inside an artifact binding as a
    # legacy omission. That must not let an unprofiled block through: the
    # result has to be the unknown-field rejection main has always given.
    manifest, key, context = packet
    manifest.pop("profile")
    del manifest["artifacts"]["system_prompt"]["classification"]
    raw = am.sign_cose_sign1(manifest, key)
    result = am.verify_manifest(raw, context, am.RevocationStore())
    assert result.result.value == "MISMATCH"
    details = result.model_dump(mode="json")["mismatch_details"]
    assert [d["field"] for d in details] == ["schema:evidence_requirements"]
    assert details[0]["actual_hash"] == "<Extra inputs are not permitted>"
    with pytest.raises(ValueError):
        verify_evidence_manifest(raw, context, am.RevocationStore())


def test_expiry_read_with_the_verifiers_parser(packet):
    # An offset-naive timestamp is UTC to the verifier, so the exported expiry
    # must be too, whatever the local timezone of the verifying host.
    manifest, key, context = packet
    now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    manifest["issued_at"] = (now - timedelta(minutes=1)).isoformat()
    manifest["expires_at"] = (now + timedelta(hours=2)).isoformat()
    raw = am.sign_cose_sign1(manifest, key)
    verified = verify_evidence_manifest(raw, context, am.RevocationStore())
    expected = (now + timedelta(hours=2)).replace(tzinfo=UTC)
    assert verified.expires_at == int(expected.timestamp())


def test_legacy_digest_is_the_whole_object_with_nulls():
    legacy = {"version": "0.1", "manifest_id": "m", "previous_manifest_id": None}
    assert manifest_digest(
        legacy, media_type="application/agent-manifest+json"
    ) == "sha256:" + hashlib.sha256(
        am.canonicalize(legacy, exclude_none=False)
    ).hexdigest()
    with pytest.raises(ValueError):
        manifest_digest(
            {**legacy, "version": "0.2"}, media_type="application/agent-manifest+json"
        )


@pytest.mark.parametrize("signed_seal", [True, False])
def test_profile_keeps_the_signed_audit_key_sealed_rule(packet, signed_seal):
    # GHSA-489r-r3g9-g24r (0.14.0). Under enforce_attestation the profile gets
    # no carve-out: the unsigned attestation-block flag alone is refused, and
    # only the signed artifact #7 copy makes the claim.
    from agent_manifest._cose import attach_attestation, cose_payload, payload_hash

    manifest, key, context = packet
    stamp = manifest["issued_at"]
    manifest["artifacts"]["decision_trace"] = {
        "trace_type": "hash-chained",
        "audit_chain_root": "sha256:" + "d" * 64,
        "audit_chain_uri": "https://audit.example/chains/one",
        "signing_key_id": "tee-sealed-audit-key",
        "audit_key_sealed": signed_seal,
        "first_entry_at": stamp,
        "last_entry_at": stamp,
        "bound_at": stamp,
    }
    bound_hash = payload_hash(cose_payload(manifest))
    raw = attach_attestation(
        am.sign_cose_sign1(manifest, key),
        {
            "platform": "amd-sev-snp",
            "manifest_hash_in_report": bound_hash,
            "audit_key_sealed": True,
        },
    )
    context.enforce_attestation = True
    context.verified_attestation_manifest_hashes = {bound_hash}
    context.attestation_evidence_manifest_id = manifest["manifest_id"]
    context.audit_chain_root = "sha256:" + "d" * 64

    result = am.verify_manifest(raw, context, am.RevocationStore())
    assert result.signature_verified is True
    assert result.attestation_verified is True
    if signed_seal:
        assert result.result.value == "VALID"
        verified = verify_evidence_manifest(raw, context, am.RevocationStore())
        assert verified.manifest_id == manifest["manifest_id"]
    else:
        assert result.result.value == "ATTESTATION_UNAVAILABLE"
        assert any("decision_trace.audit_key_sealed" in w for w in result.warnings)
        with pytest.raises(ValueError, match="ATTESTATION_UNAVAILABLE"):
            verify_evidence_manifest(raw, context, am.RevocationStore())
