"""Configuration assurance for artifact #1 (spec 3.2.1.1 - issue #254).

`system_prompt.hash` proves which prompt was approved. It proves nothing about
whether the approved prompt specifies behaviour the deploying organisation would
accept, and every threat in 7.1 is an adversary substituting something. A prompt
authored in good faith, approved, signed, sealed and verified VALID is the case
the threat model had no row for.

These cover the bound assessment that closes it: the flagged rule, which mirrors
`poisoning_scan`, and the part that matters more, that absence is reported
rather than inferred as a pass.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest import AssuranceResult, AssuranceTest, ConfigurationAssurance
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

UTC = timezone.utc
SHA = "sha256:" + "a" * 64


def _assurance(result="passed", **overrides):
    block = {
        "suite_id": "caid-benchmark",
        "suite_version": "1.2",
        "harness_version": "caid-harness/1.2.0",
        "result": result,
    }
    if result != "not-assessed":
        block["assessed_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    block.update(overrides)
    return block


def _manifest(assurance_test=None):
    now = datetime.now(UTC)
    system_prompt = {
        "hash": SHA,
        "version": "1.0.0",
        "classification": "internal",
        "bound_at": now.isoformat().replace("+00:00", "Z"),
    }
    if assurance_test is not None:
        system_prompt["assurance_test"] = assurance_test
    return {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": system_prompt,
            "policy_bundle": {
                "hash": SHA,
                "policy_language": "cedar",
                "version": "1.0",
                "enforcement_mode": "enforce",
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
            "model_identity": {
                "provider": "anthropic",
                "model_id": "claude",
                "version": "3",
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
        },
    }


def _verify(assurance_test=None):
    return verify_manifest(
        _manifest(assurance_test),
        VerificationContext(system_prompt_hash=SHA),
        RevocationStore(),
    )


# ---------------------------------------------------------------------------
# The three states
# ---------------------------------------------------------------------------


def test_passed_is_reported():
    result = _verify(_assurance("passed"))
    assert result.configuration_assurance == ConfigurationAssurance.PASSED
    assert not [d for d in result.mismatch_details
                if d.field == "system_prompt.assurance_test"]


def test_flagged_cannot_be_valid():
    """The `poisoning_scan` rule from 3.2.5, applied to artifact #1: an
    assessment that ran and failed is evidence against the configuration."""
    result = _verify(_assurance("flagged"))
    assert result.configuration_assurance == ConfigurationAssurance.FLAGGED
    assert result.result == OverallResult.MISMATCH
    assert [d for d in result.mismatch_details
            if d.field == "system_prompt.assurance_test"]


def test_flagged_does_not_disturb_the_hash_result():
    """Integrity is unaffected and stays correct. The manifest *is* what was
    approved; that is the whole point of the issue."""
    from agent_manifest._verify import FieldResult

    result = _verify(_assurance("flagged"))
    assert result.fields_verified.system_prompt == FieldResult.MATCH


def test_absent_block_is_not_assessed_not_passed():
    """The half that matters most: silence must not read as a pass."""
    result = _verify(None)
    assert result.configuration_assurance == ConfigurationAssurance.NOT_ASSESSED


def test_not_assessed_is_reported_and_warned():
    result = _verify(_assurance("not-assessed"))
    assert result.configuration_assurance == ConfigurationAssurance.NOT_ASSESSED
    assert any("not-assessed" in w for w in result.warnings)


def test_not_assessed_does_not_fail_verification_in_v0_2():
    """Which conformance level requires an assessment is deliberately open, so
    an unassessed manifest is reported rather than rejected."""
    result = _verify(_assurance("not-assessed"))
    assert result.result != OverallResult.MISMATCH


def test_absent_block_produces_no_warning():
    """Absent and explicitly not-assessed are both NOT_ASSESSED, but only the
    explicit one is a claim the issuer made, so only it is worth a warning."""
    assert not [w for w in _verify(None).warnings if "assurance" in w]


# ---------------------------------------------------------------------------
# The block itself
# ---------------------------------------------------------------------------


def test_assessed_at_required_when_an_assessment_ran():
    with pytest.raises(ValueError, match="assessed_at"):
        AssuranceTest(
            suite_id="caid-benchmark",
            suite_version="1.2",
            harness_version="caid-harness/1.2.0",
            result=AssuranceResult.passed,
        )


def test_assessed_at_optional_when_not_assessed():
    block = AssuranceTest(
        suite_id="caid-benchmark",
        suite_version="1.2",
        harness_version="caid-harness/1.2.0",
        result=AssuranceResult.not_assessed,
    )
    assert block.assessed_at is None


def test_suite_identity_is_required():
    """A result whose suite cannot be identified is not reproducible and
    carries no more weight than `safety_level`."""
    for missing in ("suite_id", "suite_version", "harness_version"):
        kwargs = {
            "suite_id": "caid-benchmark",
            "suite_version": "1.2",
            "harness_version": "caid-harness/1.2.0",
            "result": AssuranceResult.not_assessed,
        }
        del kwargs[missing]
        with pytest.raises(ValueError):
            AssuranceTest(**kwargs)


def test_scenario_count_must_be_positive():
    with pytest.raises(ValueError):
        AssuranceTest(
            suite_id="s", suite_version="1", harness_version="h/1",
            result=AssuranceResult.not_assessed, scenario_count=0,
        )


def test_result_is_a_closed_vocabulary():
    with pytest.raises(ValueError):
        AssuranceTest(
            suite_id="s", suite_version="1", harness_version="h/1", result="probably-fine",
        )


def test_the_block_is_inside_the_signing_pre_image():
    """An assessment result outside the signature is one the operator can
    revise after approval."""
    from agent_manifest._signing import signing_pre_image

    pre_image = signing_pre_image(_manifest(_assurance("passed")))
    assert b"assurance_test" in pre_image
    assert b"caid-benchmark" in pre_image


def test_flipping_flagged_to_passed_changes_the_pre_image():
    flagged = signing_pre_image_of(_assurance("flagged"))
    passed = signing_pre_image_of(_assurance("passed"))
    assert flagged != passed


def signing_pre_image_of(assurance_test):
    from agent_manifest._signing import signing_pre_image

    manifest = _manifest(assurance_test)
    # Pin assessed_at so the only difference between the two pre-images is the
    # result value rather than the timestamp.
    manifest["artifacts"]["system_prompt"]["assurance_test"]["assessed_at"] = (
        "2026-08-18T00:00:00Z"
    )
    return signing_pre_image(manifest)
