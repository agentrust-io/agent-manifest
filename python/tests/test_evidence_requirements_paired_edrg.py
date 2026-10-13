"""EDRG paired acceptance/refusal fixtures for the experimental evidence profile.

Each pair first establishes that the conformant signed manifest is admitted.
The negative is then restricted to its named verification boundary.
"""

import copy
from datetime import UTC, datetime, timedelta

import pytest

import agent_manifest as am
from agent_manifest.evidence_requirements import verify_evidence_manifest
from tests.test_evidence_requirements import packet as _base_packet


@pytest.fixture
def paired_packet():
    return _base_packet.__wrapped__()


def verify_signed(manifest, key, context, *, tamper=None, revocations=None):
    signed = am.sign_cose_sign1(manifest, key)
    if tamper:
        signed = tamper(signed)
    return verify_evidence_manifest(
        signed,
        context,
        revocations if revocations is not None else am.RevocationStore(),
    )


@pytest.mark.parametrize(
    "case,expected_result",
    [
        ("policy_mismatch", "MISMATCH"),
        ("unknown_signing_key", "UNVERIFIABLE"),
        ("expired", "EXPIRED"),
        ("missing_requirements", "MISMATCH"),
        ("duplicate_component", "MISMATCH"),
        ("unknown_requirement_field", "MISMATCH"),
        ("signature_tamper", "MISMATCH"),
    ],
)
def test_paired_admission_refusal(paired_packet, case, expected_result):
    manifest, key, context = paired_packet
    accepted = verify_signed(manifest, key, context)
    assert accepted.manifest_id == manifest["manifest_id"]
    assert dict(accepted.artifact_results)["policy_bundle"] == "MATCH"

    invalid = copy.deepcopy(manifest)
    context_invalid = copy.deepcopy(context)
    if case == "policy_mismatch":
        context_invalid.policy_bundle_hash = "sha256:" + "f" * 64
    elif case == "unknown_signing_key":
        context_invalid.trusted_keys = {}
    elif case == "expired":
        invalid["issued_at"] = (datetime.now(UTC) - timedelta(hours=4)).isoformat()
        invalid["expires_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    elif case == "missing_requirements":
        invalid.pop("evidence_requirements")
    elif case == "duplicate_component":
        components = invalid["evidence_requirements"]["components"]
        components.append(copy.deepcopy(components[0]))
    elif case == "unknown_requirement_field":
        invalid["evidence_requirements"]["components"][0]["unknown_rule"] = True
    elif case == "signature_tamper":
        pass

    if case == "signature_tamper":

        def corrupt_signature(raw):
            return raw[:-1] + bytes([raw[-1] ^ 1])

        with pytest.raises(
            ValueError, match=f"manifest appraisal not valid: {expected_result}"
        ):
            verify_signed(invalid, key, context_invalid, tamper=corrupt_signature)
    else:
        with pytest.raises(
            ValueError, match=f"manifest appraisal not valid: {expected_result}"
        ):
            verify_signed(invalid, key, context_invalid)


def test_paired_authorized_vs_unauthorized_issuer_same_signed_manifest(paired_packet):
    """Retain the trusted key and signed bytes; change only issuer authorization."""
    manifest, key, context = paired_packet
    signed = am.sign_cose_sign1(manifest, key)
    accepted = verify_evidence_manifest(signed, context, am.RevocationStore())
    assert accepted.manifest_id == manifest["manifest_id"]
    assert dict(accepted.artifact_results)["policy_bundle"] == "MATCH"

    unauthorized = copy.deepcopy(context)
    unauthorized.trusted_key_issuers = {
        key.key_id: ["spiffe://example.test/other-issuer"]
    }
    assert unauthorized.trusted_keys == context.trusted_keys
    with pytest.raises(ValueError, match="manifest appraisal not valid: MISMATCH"):
        verify_evidence_manifest(signed, unauthorized, am.RevocationStore())


def test_reject_all_verifier_cannot_satisfy_positive_twins(paired_packet, monkeypatch):
    manifest, key, context = paired_packet

    def reject_all(*_args, **_kwargs):
        raise ValueError("mutant: reject-all")

    # verify_evidence_manifest resolves verify_manifest from the SDK package.
    monkeypatch.setattr(am, "verify_manifest", reject_all)
    with pytest.raises(ValueError, match="mutant: reject-all"):
        verify_signed(manifest, key, context)


def test_paired_valid_vs_revoked_same_signed_manifest(paired_packet):
    """Change only the authoritative revocation input, not the signed bytes."""
    from agent_manifest._revocation import sign_revocation

    manifest, key, context = paired_packet
    signed = am.sign_cose_sign1(manifest, key)
    empty = am.RevocationStore()
    accepted = verify_evidence_manifest(signed, context, empty)
    assert accepted.manifest_id == manifest["manifest_id"]

    revoked = am.RevocationStore()
    authority = am.generate_ed25519()
    revoked.revoke(
        sign_revocation(
            manifest["manifest_id"], "test revocation", "test-admin", authority
        )
    )
    with pytest.raises(ValueError, match="manifest appraisal not valid: REVOKED"):
        verify_evidence_manifest(signed, context, revoked)
