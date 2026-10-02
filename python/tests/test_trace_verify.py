"""Tests for TRACE envelope and evidence pack verification (#204).

Covers the spec 6.3.2 envelope signature, the spec 5.2.1 evidence pack
``pack_signature`` and ``pack_hash``, the SCHEMA F-21 hash-conflict rule, and
the admissibility rule that MISMATCH/EXPIRED TRACEs are never evidence of a
valid tool call however good their signatures are.

Fail-closed behaviour is the point of most of these: an envelope the verifier
cannot appraise must never come back VERIFIED.
"""

import copy
import hashlib

import pytest

from agent_manifest._canonicalize import canonicalize
from agent_manifest._signing import (
    _b64url_encode,
    generate_ed25519,
)
from agent_manifest._trace import (
    INADMISSIBLE_RESULTS,
    TRACE_REQUIRED_FIELDS,
    VERIFICATION_RESULTS,
    TraceStatus,
    compute_pack_hash,
    evidence_pack_pre_image,
    trace_signing_pre_image,
    verify_evidence_pack,
    verification_result_pre_image,
    verify_trace_envelope,
)

from agent_manifest._signing import ml_dsa65_available

_OQS = ml_dsa65_available()


POLICY_HASH = f"sha256:{'a1' * 32}"
CATALOG_HASH = f"sha256:{'b2' * 32}"
MANIFEST_ID = "0192f3a0-0000-7000-8000-000000000001"


def _envelope(**overrides):
    """A spec 6.3.2 TRACE envelope with every required field present."""
    envelope = {
        "trace_id": "0192f3a0-0000-7000-8000-00000000000a",
        "agent_id": "spiffe://example.org/agent/billing",
        "agent_manifest_id": MANIFEST_ID,
        "manifest_verification_result": "VALID",
        "tool_id": "org.example.tools.invoice-lookup",
        "policy_hash": POLICY_HASH,
        "catalog_hash": CATALOG_HASH,
        "decision": "allow",
        "decision_reason": 'permit(principal, action, resource) when { context.tier == "gold" };',
        "payload_classification": "internal",
        "egress_destination": "api.example.com",
        "hitl_required": False,
        "hitl_approval_id": None,
        "timestamp": "2026-08-03T12:00:00Z",
        "tee_measurement": "sha256:" + "cd" * 32,
        "signature": "",
    }
    envelope.update(overrides)
    return envelope


def _manifest(policy_hash=POLICY_HASH, manifest_id=MANIFEST_ID):
    return {
        "manifest_id": manifest_id,
        "artifacts": {"policy_bundle": {"hash": policy_hash}},
    }


def _sign_envelope(envelope, keypair):
    """Sign *envelope* in place with Ed25519 over its canonical pre-image."""
    signed = dict(envelope)
    signed["signature"] = _b64url_encode(
        keypair.private_key.sign(trace_signing_pre_image(signed))
    )
    return signed


def _sign_pack(pack, keypair):
    signed = dict(pack)
    signed["pack_signature"] = {
        "algorithm": "Ed25519",
        "key_id": keypair.key_id,
        "key_type": "tee-sealed",
        "signed_at": "2026-08-03T12:00:00Z",
        "signature_value": _b64url_encode(
            keypair.private_key.sign(evidence_pack_pre_image(signed))
        ),
    }
    return signed


@pytest.fixture
def kp():
    return generate_ed25519()


@pytest.fixture
def trusted(kp):
    return {kp.key_id: kp.public_b64url()}


# ---------------------------------------------------------------------------
# Pre-image
# ---------------------------------------------------------------------------


def test_pre_image_excludes_only_the_signature_field():
    envelope = _envelope(signature="not-covered")
    expected = canonicalize({k: v for k, v in envelope.items() if k != "signature"})
    assert trace_signing_pre_image(envelope) == expected


def test_pre_image_is_stable_under_key_reordering():
    envelope = _envelope()
    shuffled = dict(reversed(list(envelope.items())))
    assert trace_signing_pre_image(envelope) == trace_signing_pre_image(shuffled)


def test_changing_the_signature_does_not_change_the_pre_image(kp):
    a = _envelope(signature="aaa")
    b = _envelope(signature="bbb")
    assert trace_signing_pre_image(a) == trace_signing_pre_image(b)


# ---------------------------------------------------------------------------
# Envelope signature
# ---------------------------------------------------------------------------


def test_valid_envelope_verifies_and_is_admissible(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.VERIFIED
    assert result.signature_verified is True
    assert result.admissible is True
    assert result.failures == []
    assert result.trace_id == envelope["trace_id"]


@pytest.mark.parametrize(
    "field,corrupt_value",
    [
        ("policy_hash", "sha256:" + "a1" * 32 + "\n"),
        ("catalog_hash", "sha256:" + "b2" * 32 + "\n"),
        ("agent_id", "spiffe://example.org/agent/billing\n"),
        ("trace_id", "0192f3a0-0000-7000-8000-00000000000a\n"),
    ],
)
def test_trailing_newline_on_a_formatted_field_is_rejected(kp, trusted, field, corrupt_value):
    # `_envelope_format_failures` validates trace_id/policy_hash/etc against
    # `^...$`-anchored regexes via `.fullmatch()`. Historically, if any of
    # those call sites had used `.match()` instead, Python's `$` (which
    # matches at end-of-string OR just before a single trailing '\n')
    # would have let "<valid-value>\n" through as if it were the
    # unmodified value. Sign a real envelope with the corrupted, `\n`-
    # suffixed value (so the signature is genuinely valid over the exact
    # corrupted field) and confirm the format check still catches it.
    envelope = _sign_envelope(_envelope(**{field: corrupt_value}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    # `_envelope_format_failures` runs (and short-circuits) before signature
    # verification, so a format-rejected envelope never reaches VERIFIED.
    assert result.status is TraceStatus.MALFORMED
    assert result.signature_verified is False
    assert result.admissible is False
    assert any(f.startswith(("not_a_", "illegal_")) for f in result.failures)


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision", "deny"),
        ("policy_hash", f"sha256:{'ff' * 32}"),
        ("tool_id", "org.example.tools.wire-transfer"),
        ("egress_destination", "attacker.example.net"),
        ("hitl_required", True),
        ("tee_measurement", "sha256:" + "00" * 32),
        ("timestamp", "2026-08-03T13:00:00Z"),
    ],
)
def test_tampering_any_covered_field_fails(kp, trusted, field, value):
    envelope = _sign_envelope(_envelope(), kp)
    envelope[field] = value
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.FAILED
    assert result.signature_verified is False
    assert result.admissible is False


def test_tampered_signature_fails(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    # Flip one base64url character to a different valid one.
    sig = envelope["signature"]
    envelope["signature"] = ("B" if sig[0] == "A" else "A") + sig[1:]
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.FAILED


def test_signature_from_a_different_key_fails(kp, trusted):
    attacker = generate_ed25519()
    envelope = _sign_envelope(_envelope(), attacker)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.FAILED
    assert result.admissible is False


def test_missing_signature_is_signature_missing(trusted):
    envelope = _envelope(signature="")
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.SIGNATURE_MISSING
    assert result.admissible is False


# ---------------------------------------------------------------------------
# Fail-closed: unappraisable is never VERIFIED
# ---------------------------------------------------------------------------


def test_no_trusted_keys_is_unverifiable_not_verified(kp):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(envelope, trusted_keys=None)
    assert result.status is TraceStatus.UNVERIFIABLE
    assert result.signature_verified is False
    assert result.admissible is False


def test_untrusted_key_id_is_unverifiable(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, key_id="0" * 64
    )
    assert result.status is TraceStatus.UNVERIFIABLE
    assert any("key_id_not_trusted" in f for f in result.failures)


def test_ambiguous_key_without_key_id_is_refused(kp):
    """Two trusted keys and no key_id: refuse rather than try each in turn."""
    other = generate_ed25519()
    envelope = _sign_envelope(_envelope(), kp)
    trusted_two = {
        kp.key_id: kp.public_b64url(),
        other.key_id: other.public_b64url(),
    }
    result = verify_trace_envelope(envelope, trusted_keys=trusted_two)
    assert result.status is TraceStatus.UNVERIFIABLE
    assert "ambiguous_key_id" in result.failures

    # Naming the key resolves it.
    ok = verify_trace_envelope(
        envelope, trusted_keys=trusted_two, key_id=kp.key_id
    )
    assert ok.status is TraceStatus.VERIFIED


def test_hybrid_algorithm_is_rejected_for_envelopes(kp, trusted):
    """Spec 6.3.2 types the envelope signature as a bare string."""
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, algorithm="hybrid-Ed25519-ML-DSA-65"
    )
    assert result.status is TraceStatus.UNVERIFIABLE
    assert any("unsupported_envelope_algorithm" in f for f in result.failures)


# ---------------------------------------------------------------------------
# Shape validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", TRACE_REQUIRED_FIELDS)
def test_missing_required_field_is_malformed(kp, trusted, missing):
    envelope = _sign_envelope(_envelope(), kp)
    del envelope[missing]
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert result.admissible is False


def test_illegal_verification_result_enum_is_malformed(kp, trusted):
    """Spec 6.3.2 forbids values outside the section 5.2 enum."""
    envelope = _sign_envelope(_envelope(manifest_verification_result="OK"), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


def test_sdk_only_statuses_are_not_legal_in_an_envelope(kp, trusted):
    """UNVERIFIABLE is a verifier-side outcome, not a producer-writable one."""
    envelope = _sign_envelope(
        _envelope(manifest_verification_result="UNVERIFIABLE"), kp
    )
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


def test_string_hitl_required_is_malformed(kp, trusted):
    """SCHEMA F-11: a string "false" is truthy and would read as approved."""
    envelope = _sign_envelope(_envelope(hitl_required="false"), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "hitl_required_not_a_boolean" in result.failures


def test_non_dict_envelope_is_malformed(trusted):
    result = verify_trace_envelope(["not", "an", "object"], trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


# ---------------------------------------------------------------------------
# Admissibility (spec 6.3.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("result_value", sorted(INADMISSIBLE_RESULTS))
def test_mismatch_and_expired_are_authentic_but_inadmissible(
    kp, trusted, result_value
):
    envelope = _sign_envelope(
        _envelope(manifest_verification_result=result_value), kp
    )
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    # The signature is genuine -- the runtime honestly recorded a bad state.
    assert result.status is TraceStatus.VERIFIED
    assert result.signature_verified is True
    # But it is not evidence of a valid tool call.
    assert result.admissible is False
    assert any("inadmissible" in f for f in result.failures)


@pytest.mark.parametrize(
    "result_value", ["VALID", "REVOKED", "INCOMPLETE", "ATTESTATION_UNAVAILABLE"]
)
def test_other_results_remain_admissible(kp, trusted, result_value):
    envelope = _sign_envelope(
        _envelope(manifest_verification_result=result_value), kp
    )
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.admissible is True


# ---------------------------------------------------------------------------
# Manifest binding / SCHEMA F-21
# ---------------------------------------------------------------------------


def test_matching_policy_hash_binds_cleanly(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, manifest=_manifest()
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.admissible is True


def test_policy_hash_conflict_claiming_valid_is_a_failure(kp, trusted):
    """F-21: a conflict MUST be declared as MISMATCH, not papered over."""
    envelope = _sign_envelope(_envelope(policy_hash=f"sha256:{'99' * 32}"), kp)
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, manifest=_manifest()
    )
    assert result.signature_verified is True
    assert result.admissible is False
    assert any("policy_hash_conflict_not_declared" in f for f in result.failures)


def test_policy_hash_conflict_declared_as_mismatch_is_spec_compliant(kp, trusted):
    envelope = _sign_envelope(
        _envelope(
            policy_hash=f"sha256:{'99' * 32}",
            manifest_verification_result="MISMATCH",
        ),
        kp,
    )
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, manifest=_manifest()
    )
    # Correctly declared, so no F-21 violation ...
    assert not any(
        "policy_hash_conflict_not_declared" in f for f in result.failures
    )
    # ... but still not usable as evidence of a valid call.
    assert result.admissible is False


def test_manifest_id_mismatch_is_a_failure(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest=_manifest(manifest_id="0192f3a0-0000-7000-8000-0000000000ff"),
    )
    assert result.admissible is False
    assert any("manifest_id_mismatch" in f for f in result.failures)


def test_manifest_without_policy_hash_warns(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest={"manifest_id": MANIFEST_ID, "artifacts": {}},
    )
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_has_no_policy_bundle_hash" in result.warnings


# ---------------------------------------------------------------------------
# Malformed nested manifest shapes must warn, never raise - issue #362
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_artifacts", ["not-an-object", ["a", "list"], True])
def test_non_object_manifest_artifacts_warns_not_raises(kp, trusted, bad_artifacts):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest={"manifest_id": MANIFEST_ID, "artifacts": bad_artifacts},
    )
    # The TRACE signature already verified; a malformed optional binding must
    # not retroactively make the envelope unappraisable.
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_artifacts_not_an_object" in result.warnings


@pytest.mark.parametrize("bad_policy_bundle", ["not-an-object", ["a", "list"], True])
def test_non_object_policy_bundle_warns_not_raises(kp, trusted, bad_policy_bundle):
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest={
            "manifest_id": MANIFEST_ID,
            "artifacts": {"policy_bundle": bad_policy_bundle},
        },
    )
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_policy_bundle_not_an_object" in result.warnings


@pytest.mark.parametrize("bad_artifacts", ["", [], False, 0])
def test_falsy_non_object_manifest_artifacts_warns_structurally(
    kp, trusted, bad_artifacts
):
    """`manifest.get("artifacts") or {}` folded falsy non-dicts
    ("", [], False, 0) into `{}` before the isinstance check ever ran, so
    they were reported as merely absent (`manifest_has_no_policy_bundle_hash`)
    instead of malformed. Only a genuinely missing `artifacts` (absent key or
    `None`) may fall back to `{}`; any other non-dict, falsy or not, must
    report the structural warning.
    """
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest={"manifest_id": MANIFEST_ID, "artifacts": bad_artifacts},
    )
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_artifacts_not_an_object" in result.warnings
    assert "manifest_has_no_policy_bundle_hash" not in result.warnings


@pytest.mark.parametrize("bad_policy_bundle", ["", [], False, 0])
def test_falsy_non_object_policy_bundle_warns_structurally(
    kp, trusted, bad_policy_bundle
):
    """Same bug as above, one level down: `artifacts.get("policy_bundle") or
    {}` swallowed falsy non-dict policy bundles into the no-hash warning."""
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_trace_envelope(
        envelope,
        trusted_keys=trusted,
        manifest={
            "manifest_id": MANIFEST_ID,
            "artifacts": {"policy_bundle": bad_policy_bundle},
        },
    )
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_policy_bundle_not_an_object" in result.warnings
    assert "manifest_has_no_policy_bundle_hash" not in result.warnings


@pytest.mark.parametrize(
    "manifest_extra",
    [
        {},  # artifacts key absent entirely
        {"artifacts": None},  # explicit None
        {"artifacts": {}},  # well-typed but empty
        {"artifacts": {"policy_bundle": None}},  # policy_bundle explicit None
        {"artifacts": {"policy_bundle": {}}},  # well-typed but empty
    ],
)
def test_true_missing_cases_still_use_no_hash_warning(kp, trusted, manifest_extra):
    """None, an absent key, and `{}` are genuinely missing data, not
    malformed structure, and must keep reporting
    `manifest_has_no_policy_bundle_hash` rather than a structural warning."""
    envelope = _sign_envelope(_envelope(), kp)
    manifest = {"manifest_id": MANIFEST_ID, **manifest_extra}
    result = verify_trace_envelope(
        envelope, trusted_keys=trusted, manifest=manifest
    )
    assert result.status is TraceStatus.VERIFIED
    assert "manifest_has_no_policy_bundle_hash" in result.warnings
    assert "manifest_artifacts_not_an_object" not in result.warnings
    assert "manifest_policy_bundle_not_an_object" not in result.warnings


def test_pack_with_falsy_non_object_artifacts_warns_structurally(kp, trusted):
    """Same as the falsy-artifacts test above, but through the independently
    reachable evidence-pack path (the two paths are known to be separate
    separate call sites feeding the same function)."""
    envelope = _sign_envelope(_envelope(), kp)
    malformed_manifest = {"manifest_id": MANIFEST_ID, "artifacts": ""}
    pack = _sign_pack(_pack([envelope], manifest=malformed_manifest), kp)
    result = verify_evidence_pack(pack, trusted_keys=trusted, trace_key_id=kp.key_id)
    assert len(result.envelopes) == 1
    assert result.envelopes[0].status is TraceStatus.VERIFIED
    assert "manifest_artifacts_not_an_object" in result.envelopes[0].warnings
    assert "manifest_has_no_policy_bundle_hash" not in result.envelopes[0].warnings


def test_pack_with_malformed_manifest_artifacts_warns_not_raises(kp, trusted):
    """The evidence-pack path is independently reachable (#362): it feeds its
    manifest to every contained envelope without checking artifacts/
    policy_bundle shape first."""
    envelope = _sign_envelope(_envelope(), kp)
    malformed_manifest = {"manifest_id": MANIFEST_ID, "artifacts": "not-an-object"}
    pack = _sign_pack(_pack([envelope], manifest=malformed_manifest), kp)
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert len(result.envelopes) == 1
    assert result.envelopes[0].status is TraceStatus.VERIFIED
    assert "manifest_artifacts_not_an_object" in result.envelopes[0].warnings


# ---------------------------------------------------------------------------
# Evidence pack
# ---------------------------------------------------------------------------


def _pack(envelopes, manifest=None):
    return {
        "manifest": manifest if manifest is not None else _manifest(),
        "verification_result": {"result": "VALID", "manifest_id": MANIFEST_ID},
        "trace_envelopes": envelopes,
        "attestation_report": _b64url_encode(b"raw-attestation-bytes"),
    }


def test_pack_hash_excludes_the_signature(kp):
    pack = _pack([])
    unsigned_hash = compute_pack_hash(pack)
    signed = _sign_pack(pack, kp)
    assert compute_pack_hash(signed) == unsigned_hash
    # And it is the SHA-256 of the canonical bytes, per spec 5.2.1.
    expected = hashlib.sha256(evidence_pack_pre_image(pack)).hexdigest()
    assert unsigned_hash == f"sha256:{expected}"


def test_valid_pack_verifies(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    pack = _sign_pack(_pack([envelope]), kp)
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.signature_verified is True
    assert result.failures == []
    assert len(result.envelopes) == 1
    assert result.envelopes[0].admissible is True


def test_expected_pack_hash_is_checked(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    pack = _sign_pack(_pack([envelope]), kp)
    good = verify_evidence_pack(
        pack,
        trusted_keys=trusted,
        trace_key_id=kp.key_id,
        expected_pack_hash=compute_pack_hash(pack),
    )
    assert good.pack_hash_matches is True
    assert good.status is TraceStatus.VERIFIED

    bad = verify_evidence_pack(
        pack,
        trusted_keys=trusted,
        trace_key_id=kp.key_id,
        expected_pack_hash=f"sha256:{'00' * 32}",
    )
    assert bad.pack_hash_matches is False
    assert bad.status is TraceStatus.FAILED
    assert any("pack_hash_mismatch" in f for f in bad.failures)


def test_tampering_the_pack_breaks_the_signature(kp, trusted):
    envelope = _sign_envelope(_envelope(), kp)
    pack = _sign_pack(_pack([envelope]), kp)
    pack["attestation_report"] = _b64url_encode(b"swapped-attestation")
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.FAILED
    assert result.signature_verified is False


def test_removing_an_envelope_breaks_the_pack_signature(kp, trusted):
    """The pack signature covers the envelope array, so dropping one is caught."""
    e1 = _sign_envelope(_envelope(), kp)
    e2 = _sign_envelope(_envelope(trace_id="0192f3a0-0000-7000-8000-00000000000b"), kp)
    pack = _sign_pack(_pack([e1, e2]), kp)
    pack["trace_envelopes"] = [e1]
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.FAILED


def test_pack_missing_signature(kp, trusted):
    pack = _pack([_sign_envelope(_envelope(), kp)])
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.SIGNATURE_MISSING


def test_pack_signature_as_bare_string_is_malformed(kp, trusted):
    """Spec 5.2.1 requires the detached object form of section 3.6."""
    pack = _pack([])
    pack["pack_signature"] = "just-a-string"
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


def test_pack_with_no_trusted_keys_is_unverifiable(kp):
    pack = _sign_pack(_pack([]), kp)
    result = verify_evidence_pack(pack, trusted_keys={})
    assert result.status is TraceStatus.UNVERIFIABLE
    assert result.signature_verified is False


def test_good_pack_signature_over_inadmissible_envelope_still_fails(kp, trusted):
    """A pack is not usable evidence just because the pack signature is valid."""
    envelope = _sign_envelope(
        _envelope(manifest_verification_result="EXPIRED"), kp
    )
    pack = _sign_pack(_pack([envelope]), kp)
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.signature_verified is True
    assert result.status is TraceStatus.FAILED
    assert "pack_contains_inadmissible_envelope" in result.failures


def test_envelope_check_can_be_skipped(kp, trusted):
    envelope = _sign_envelope(
        _envelope(manifest_verification_result="EXPIRED"), kp
    )
    pack = _sign_pack(_pack([envelope]), kp)
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, verify_envelopes=False
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.envelopes == []


def test_pack_envelopes_are_bound_to_the_packs_manifest(kp, trusted):
    """The manifest inside the pack drives the F-21 check on its envelopes."""
    envelope = _sign_envelope(_envelope(policy_hash=f"sha256:{'99' * 32}"), kp)
    pack = _sign_pack(_pack([envelope]), kp)
    result = verify_evidence_pack(
        pack, trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert any(
        "policy_hash_conflict_not_declared" in f
        for f in result.envelopes[0].failures
    )


def test_trace_envelopes_not_an_array_is_malformed(kp, trusted):
    pack = _sign_pack(_pack([]), kp)
    pack["trace_envelopes"] = {"not": "a list"}
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


def test_unknown_pack_algorithm_is_unverifiable(kp, trusted):
    pack = _sign_pack(_pack([]), kp)
    pack["pack_signature"]["algorithm"] = "RSA-PKCS1"
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.UNVERIFIABLE
    assert any("unknown_algorithm" in f for f in result.failures)


@pytest.mark.skipif(not _OQS, reason="no ML-DSA-65 backend available")
def test_hybrid_pack_signature_verifies():
    from agent_manifest._signing import generate_hybrid

    hybrid = generate_hybrid()
    pack = _pack([])
    pre_image = evidence_pack_pre_image(pack)
    classical = _b64url_encode(hybrid.ed25519.private_key.sign(pre_image))
    from agent_manifest._signing import _ml_dsa_sign_raw

    pq = _b64url_encode(
        _ml_dsa_sign_raw(hybrid.ml_dsa65.private_key_bytes, pre_image)
    )
    pack["pack_signature"] = {
        "algorithm": "hybrid-Ed25519-ML-DSA-65",
        "key_id": hybrid.key_id,
        "classical_signature": classical,
        "pq_signature": pq,
        "signature_value": "",
    }
    combined = hybrid.ed25519.public_bytes + hybrid.ml_dsa65.public_key_bytes
    result = verify_evidence_pack(
        pack, trusted_keys={hybrid.key_id: _b64url_encode(combined)}
    )
    assert result.status is TraceStatus.VERIFIED


@pytest.mark.skipif(not _OQS, reason="no ML-DSA-65 backend available")
def test_hybrid_pack_wrong_length_trusted_key_fails_closed():
    """The detached-signature path (_verify_detached) shares
    _split_hybrid_public_key with the manifest verifier - a wrong-length
    combined key must fail here too, not just for manifests."""
    from agent_manifest._signing import generate_hybrid

    hybrid = generate_hybrid()
    pack = _pack([])
    pre_image = evidence_pack_pre_image(pack)
    classical = _b64url_encode(hybrid.ed25519.private_key.sign(pre_image))
    from agent_manifest._signing import _ml_dsa_sign_raw

    pq = _b64url_encode(
        _ml_dsa_sign_raw(hybrid.ml_dsa65.private_key_bytes, pre_image)
    )
    pack["pack_signature"] = {
        "algorithm": "hybrid-Ed25519-ML-DSA-65",
        "key_id": hybrid.key_id,
        "classical_signature": classical,
        "pq_signature": pq,
        "signature_value": "",
    }
    truncated_pq = hybrid.ml_dsa65.public_key_bytes[:100]  # not 1952 bytes
    combined = hybrid.ed25519.public_bytes + truncated_pq
    bad_key_id = hashlib.sha256(combined).hexdigest()
    pack["pack_signature"]["key_id"] = bad_key_id
    result = verify_evidence_pack(
        pack, trusted_keys={bad_key_id: _b64url_encode(combined)}
    )
    assert result.status is TraceStatus.FAILED
    assert any("signature_malformed" in f for f in result.failures)


# ---------------------------------------------------------------------------
# Regression: the refactor that made the verifiers reusable
# ---------------------------------------------------------------------------


def test_manifest_verify_still_uses_the_manifest_pre_image(kp):
    """verify() must keep signing SIGNED_FIELDS, not the whole dict."""
    from agent_manifest._signing import Ed25519Signer, Ed25519Verifier

    manifest = {
        "manifest_id": MANIFEST_ID,
        "agent_id": "spiffe://example.org/agent/billing",
        "version": "0.1",
        "artifacts": {"policy_bundle": {"hash": POLICY_HASH}},
    }
    block = Ed25519Signer(kp).sign(manifest)
    verifier = Ed25519Verifier(kp.public_bytes)
    verifier.verify(manifest, block["signature_value"])

    # A field outside SIGNED_FIELDS must not disturb the signature.
    with_extra = copy.deepcopy(manifest)
    with_extra["transparency_log_entry"] = {"log_index": 7}
    verifier.verify(with_extra, block["signature_value"])


# ---------------------------------------------------------------------------
# Structural requirements of the pack itself (spec 5.2.1)
#
# A signature proves who assembled a document, not that the document is the
# thing it claims to be. These assert the four members exist and are the right
# shape before the signature is appraised at all.
# ---------------------------------------------------------------------------


def test_a_pack_carrying_only_its_own_signature_is_malformed(kp, trusted):
    """The case that motivated these checks.

    Every member of the pre-image is optional to the signer, so a pack
    containing nothing but `pack_signature` is signed honestly and verifies
    perfectly, while evidencing nothing at all.
    """
    pack = _sign_pack({}, kp)
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert result.signature_verified is False
    assert any("missing_required_fields" in f for f in result.failures)


@pytest.mark.parametrize(
    "missing",
    ["manifest", "verification_result", "trace_envelopes", "attestation_report"],
)
def test_each_missing_pack_member_is_malformed(kp, trusted, missing):
    pack = _pack([])
    del pack[missing]
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert result.signature_verified is False
    assert f"missing_required_fields:{missing}" in result.failures


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("manifest", "not-an-object"),
        ("verification_result", []),
        ("trace_envelopes", {}),
        ("attestation_report", 42),
    ],
)
def test_a_pack_member_of_the_wrong_type_is_malformed(kp, trusted, field, bad_value):
    pack = _pack([])
    pack[field] = bad_value
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"wrong_field_type:{field}" in result.failures


def test_an_empty_manifest_is_malformed(kp, trusted):
    """Well-typed and still useless: every binding check reads from it, so an
    empty manifest disables them all without any of them reporting a failure."""
    pack = _pack([])
    pack["manifest"] = {}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "manifest_empty" in result.failures


def test_structure_is_checked_before_the_signature(kp, trusted):
    """A malformed pack is MALFORMED even when the signature is unverifiable,
    so the two failures cannot mask one another."""
    pack = _pack([])
    del pack["manifest"]
    signed = _sign_pack(pack, kp)
    result = verify_evidence_pack(signed, trusted_keys={})  # no keys at all
    assert result.status is TraceStatus.MALFORMED
    assert "missing_required_fields:manifest" in result.failures


def test_a_well_formed_pack_still_verifies(kp, trusted):
    """The checks must not cost the happy path."""
    envelope = _sign_envelope(_envelope(), kp)
    result = verify_evidence_pack(
        _sign_pack(_pack([envelope]), kp),
        trusted_keys=trusted,
        trace_key_id=kp.key_id,
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.signature_verified is True


# ---------------------------------------------------------------------------
# Envelope fields: present is not the same as well-formed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("trace_id", 12345),
        ("agent_id", None),
        ("policy_hash", []),
        ("catalog_hash", {}),
        ("decision", 1),
        ("timestamp", 1735689600),
        ("tee_measurement", 999),
    ],
)
def test_an_envelope_field_of_the_wrong_type_is_malformed(
    kp, trusted, field, bad_value
):
    """`policy_hash: []` is the case that matters: it is present, so the
    conflict rule of section 6.3.2 runs, compares it against the manifest's
    hash, finds no match, and reports nothing because the types differ."""
    envelope = _sign_envelope(_envelope(**{field: bad_value}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"wrong_field_type:{field}" in result.failures


def test_a_manifest_without_manifest_id_cannot_disable_the_binding(kp, trusted):
    """Non-empty is not the same as usable.

    `_check_manifest_binding` skips the manifest-id comparison when the
    manifest carries no `manifest_id`, so a manifest of `{"note": "..."}` is
    well-typed, non-empty, and still lets an envelope naming a completely
    different manifest through without remark. The binding is why the manifest
    is in the pack, so the field it binds on is required.
    """
    envelope = _sign_envelope(
        _envelope(agent_manifest_id="0192f3a0-dead-7000-8000-00000000beef"), kp
    )
    pack = _pack([envelope], manifest={"note": "not really a manifest"})
    result = verify_evidence_pack(
        _sign_pack(pack, kp), trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.MALFORMED
    assert "manifest_missing_manifest_id" in result.failures


def test_the_binding_still_catches_a_mismatched_envelope(kp, trusted):
    """And with a real manifest present, the binding does its job."""
    envelope = _sign_envelope(
        _envelope(agent_manifest_id="0192f3a0-dead-7000-8000-00000000beef"), kp
    )
    result = verify_evidence_pack(
        _sign_pack(_pack([envelope]), kp),
        trusted_keys=trusted,
        trace_key_id=kp.key_id,
    )
    assert result.status is not TraceStatus.VERIFIED
    assert any("manifest_id_mismatch" in f for e in result.envelopes for f in e.failures)


# ---------------------------------------------------------------------------
# Value-level conformance, spec 6.3.2 and 5.2.1
#
# Type-correct is not the same as spec-conforming. Each of these is a signed
# record whose every field is present and of the right type, carrying a value
# the specification does not define. Labelling one admissible would call a
# non-conforming forensic record evidence of a valid tool call.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad_value,failure",
    [
        ("decision", "root", "illegal_decision:'root'"),
        ("decision", "ALLOW", "illegal_decision:'ALLOW'"),
        (
            "payload_classification",
            "cosmic",
            "illegal_payload_classification:'cosmic'",
        ),
    ],
)
def test_an_illegal_enum_value_is_malformed(kp, trusted, field, bad_value, failure):
    envelope = _sign_envelope(_envelope(**{field: bad_value}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert result.admissible is False
    assert failure in result.failures


@pytest.mark.parametrize("field", ["trace_id", "agent_manifest_id"])
def test_an_id_that_is_not_uuid_v7_is_malformed(kp, trusted, field):
    envelope = _sign_envelope(_envelope(**{field: "not-a-uuid"}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"not_a_uuid_v7:{field}" in result.failures


def test_a_uuid_v4_is_not_accepted_where_v7_is_required(kp, trusted):
    """The version nibble is the point: v7 is time-ordered, v4 is not."""
    envelope = _sign_envelope(
        _envelope(trace_id="0192f3a0-0000-4000-8000-00000000000a"), kp
    )
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "not_a_uuid_v7:trace_id" in result.failures


def test_a_present_but_malformed_hitl_approval_id_is_malformed(kp, trusted):
    """`<UUID v7> | null`: null is legal, a broken value is not."""
    envelope = _sign_envelope(_envelope(hitl_approval_id="approved-by-bob"), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "not_a_uuid_v7:hitl_approval_id" in result.failures


def test_a_null_hitl_approval_id_is_accepted(kp, trusted):
    envelope = _sign_envelope(_envelope(hitl_approval_id=None), kp)
    assert verify_trace_envelope(envelope, trusted_keys=trusted).status is (
        TraceStatus.VERIFIED
    )


@pytest.mark.parametrize(
    "bad_agent_id", ["just-a-name", "https://example.org/agent", "spiffe:/missing"]
)
def test_an_agent_id_that_is_not_a_spiffe_uri_is_malformed(kp, trusted, bad_agent_id):
    envelope = _sign_envelope(_envelope(agent_id=bad_agent_id), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "not_a_spiffe_uri:agent_id" in result.failures


@pytest.mark.parametrize("field", ["policy_hash", "catalog_hash"])
def test_a_hash_that_is_not_sha256_prefixed_is_malformed(kp, trusted, field):
    envelope = _sign_envelope(_envelope(**{field: "deadbeef"}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"not_a_sha256_hash:{field}" in result.failures


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "yesterday",
        "2026-08-03T12:00:00",          # offset-naive, time zone would be guessed
        "2026-08-03T12:00:00+02:00",    # a real offset, but not UTC
        "03/08/2026 12:00",
    ],
)
def test_a_timestamp_that_is_not_iso8601_utc_is_malformed(kp, trusted, bad_timestamp):
    envelope = _sign_envelope(_envelope(timestamp=bad_timestamp), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "not_an_iso8601_utc_timestamp:timestamp" in result.failures


@pytest.mark.parametrize("suffix", ["Z", "+00:00"])
def test_both_utc_spellings_are_accepted(kp, trusted, suffix):
    envelope = _sign_envelope(_envelope(timestamp=f"2026-08-03T12:00:00{suffix}"), kp)
    assert verify_trace_envelope(envelope, trusted_keys=trusted).status is (
        TraceStatus.VERIFIED
    )


def test_a_platform_specific_tee_measurement_is_not_forced_to_sha256(kp, trusted):
    """Spec 6.3.2 types it as `<platform-specific measurement>`, so enforcing a
    hash shape here would reject records the specification permits."""
    envelope = _sign_envelope(_envelope(tee_measurement="mrenclave:abc123"), kp)
    assert verify_trace_envelope(envelope, trusted_keys=trusted).status is (
        TraceStatus.VERIFIED
    )


@pytest.mark.parametrize("field", ["tool_id", "tee_measurement", "egress_destination"])
def test_an_empty_required_string_is_malformed(kp, trusted, field):
    envelope = _sign_envelope(_envelope(**{field: "   "}), kp)
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"empty_required_field:{field}" in result.failures


# --- pack contents ---------------------------------------------------------


def test_an_empty_verification_result_is_malformed(kp, trusted):
    pack = _pack([])
    pack["verification_result"] = {}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "verification_result_empty" in result.failures


def test_a_verification_result_without_a_result_is_malformed(kp, trusted):
    pack = _pack([])
    pack["verification_result"] = {"manifest_id": MANIFEST_ID}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "verification_result_missing_result" in result.failures


def test_an_illegal_verification_result_value_is_malformed(kp, trusted):
    pack = _pack([])
    pack["verification_result"] = {"result": "PROBABLY_FINE"}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "illegal_verification_result:'PROBABLY_FINE'" in result.failures


def test_an_empty_attestation_report_is_malformed(kp, trusted):
    pack = _pack([])
    pack["attestation_report"] = ""
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "attestation_report_empty" in result.failures


def test_an_attestation_report_that_is_not_base64url_is_malformed(kp, trusted):
    """Spec 5.2.1 carries the raw platform report base64url-encoded, so a value
    that cannot be decoded is not a report this pack could have produced."""
    pack = _pack([])
    pack["attestation_report"] = "not/valid+base64!!"
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "attestation_report_not_base64url" in result.failures


def test_pack_contents_are_checked_before_the_signature(kp, trusted):
    pack = _pack([])
    pack["attestation_report"] = ""
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys={})
    assert result.status is TraceStatus.MALFORMED
    assert result.signature_verified is False


# ---------------------------------------------------------------------------
# The embedded section 5.2 verification result
# ---------------------------------------------------------------------------
#
# The pack signature proves who assembled the pack. It says nothing about the
# verdict inside it or about the attestation service's own signature over that
# verdict, so both are appraised separately.


def _signed_result(service_kp, **overrides):
    """A section 5.2 result signed by *service_kp* over its canonical pre-image."""
    result = {"result": "VALID", "manifest_id": MANIFEST_ID}
    result.update(overrides)
    result["verification_signature"] = _b64url_encode(
        service_kp.private_key.sign(verification_result_pre_image(result))
    )
    return result


def _pack_with_result(verification_result, kp):
    pack = _pack([_sign_envelope(_envelope(), kp)])
    pack["verification_result"] = verification_result
    return _sign_pack(pack, kp)


@pytest.mark.parametrize("verdict", sorted(VERIFICATION_RESULTS - {"VALID"}))
def test_a_non_valid_embedded_verdict_is_never_verified(kp, trusted, verdict):
    """An authentic pack reporting REVOKED is authentic and still not VALID."""
    pack = _pack([_sign_envelope(_envelope(), kp)])
    pack["verification_result"] = {"result": verdict, "manifest_id": MANIFEST_ID}
    result = verify_evidence_pack(
        _sign_pack(pack, kp), trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.signature_verified is True
    assert result.status is TraceStatus.FAILED
    assert f"verification_result_not_valid:{verdict}" in result.failures


def test_the_embedded_verdict_is_checked_like_an_envelope_verdict(kp, trusted):
    """EXPIRED fails the pack whichever member carries it."""
    in_envelope = _pack(
        [_sign_envelope(_envelope(manifest_verification_result="EXPIRED"), kp)]
    )
    in_result = _pack([_sign_envelope(_envelope(), kp)])
    in_result["verification_result"] = {"result": "EXPIRED", "manifest_id": MANIFEST_ID}
    for pack in (in_envelope, in_result):
        result = verify_evidence_pack(
            _sign_pack(pack, kp), trusted_keys=trusted, trace_key_id=kp.key_id
        )
        assert result.status is TraceStatus.FAILED


def test_an_unappraised_result_signature_is_reported_as_unappraised(kp, trusted):
    """Without a key for the result signer, nothing claims it was checked."""
    service = generate_ed25519()
    signed = _signed_result(service)
    signed["verification_signature"] = signed["verification_signature"][::-1]
    result = verify_evidence_pack(
        _pack_with_result(signed, kp), trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.verification_result_signature_verified is False
    assert "verification_result_signature_not_appraised" in result.warnings


def test_a_good_result_signature_is_appraised(kp, trusted):
    service = generate_ed25519()
    keys = dict(trusted, **{service.key_id: service.public_b64url()})
    result = verify_evidence_pack(
        _pack_with_result(_signed_result(service), kp),
        trusted_keys=keys,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
    )
    assert result.status is TraceStatus.VERIFIED
    assert result.verification_result_signature_verified is True
    assert result.failures == []
    assert "verification_result_signature_not_appraised" not in result.warnings


def test_a_corrupt_result_signature_fails_under_a_good_pack_signature(kp, trusted):
    """Re-signing the outer pack does not launder a bad inner signature."""
    service = generate_ed25519()
    keys = dict(trusted, **{service.key_id: service.public_b64url()})
    signed = _signed_result(service)
    signed["verified_at"] = "2026-08-03T12:00:01Z"  # edited after signing
    result = verify_evidence_pack(
        _pack_with_result(signed, kp),
        trusted_keys=keys,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
    )
    assert result.signature_verified is True
    assert result.verification_result_signature_verified is False
    assert result.status is TraceStatus.FAILED
    assert "verification_result_signature_invalid" in result.failures


def test_a_result_signed_by_another_key_fails(kp, trusted):
    service, impostor = generate_ed25519(), generate_ed25519()
    keys = dict(trusted, **{service.key_id: service.public_b64url()})
    result = verify_evidence_pack(
        _pack_with_result(_signed_result(impostor), kp),
        trusted_keys=keys,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
    )
    assert result.status is TraceStatus.FAILED
    assert "verification_result_signature_invalid" in result.failures


def test_a_missing_result_signature_fails_when_one_is_expected(kp, trusted):
    service = generate_ed25519()
    keys = dict(trusted, **{service.key_id: service.public_b64url()})
    result = verify_evidence_pack(
        _pack_with_result({"result": "VALID", "manifest_id": MANIFEST_ID}, kp),
        trusted_keys=keys,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
    )
    assert result.status is TraceStatus.SIGNATURE_MISSING
    assert "verification_result_signature_absent" in result.failures


def test_an_untrusted_result_key_is_unverifiable(kp, trusted):
    service = generate_ed25519()
    result = verify_evidence_pack(
        _pack_with_result(_signed_result(service), kp),
        trusted_keys=trusted,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
    )
    assert result.status is TraceStatus.UNVERIFIABLE
    assert result.verification_result_signature_verified is False
    assert (
        f"verification_result_key_id_not_trusted:{service.key_id}" in result.failures
    )


def test_an_unsupported_result_algorithm_is_unverifiable(kp, trusted):
    service = generate_ed25519()
    keys = dict(trusted, **{service.key_id: service.public_b64url()})
    result = verify_evidence_pack(
        _pack_with_result(_signed_result(service), kp),
        trusted_keys=keys,
        trace_key_id=kp.key_id,
        result_key_id=service.key_id,
        result_algorithm="hybrid-Ed25519-ML-DSA-65",
    )
    assert result.status is TraceStatus.UNVERIFIABLE
    assert result.verification_result_signature_verified is False


def test_a_result_pre_image_excludes_only_its_signature():
    body = {"result": "VALID", "manifest_id": MANIFEST_ID}
    signed = dict(body, verification_signature="x")
    assert verification_result_pre_image(signed) == canonicalize(body)


def test_the_embedded_result_must_name_the_packs_manifest(kp, trusted):
    pack = _pack([_sign_envelope(_envelope(), kp)])
    pack["verification_result"] = {
        "result": "VALID",
        "manifest_id": "0192f3a0-0000-7000-8000-0000000000ff",
    }
    result = verify_evidence_pack(
        _sign_pack(pack, kp), trusted_keys=trusted, trace_key_id=kp.key_id
    )
    assert result.status is TraceStatus.FAILED
    assert any(
        f.startswith("verification_result_manifest_id_mismatch")
        for f in result.failures
    )


def test_an_embedded_result_without_manifest_id_is_malformed(kp, trusted):
    pack = _pack([])
    pack["verification_result"] = {"result": "VALID"}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert "verification_result_missing_manifest_id" in result.failures


# ---------------------------------------------------------------------------
# Untrusted input returns a status, never an exception
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_result", [[], {}, ["VALID"], 1])
def test_a_non_string_embedded_verdict_is_malformed_not_raised(kp, trusted, bad_result):
    pack = _pack([])
    pack["verification_result"] = {"result": bad_result, "manifest_id": MANIFEST_ID}
    result = verify_evidence_pack(_sign_pack(pack, kp), trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert any(f.startswith("illegal_verification_result") for f in result.failures)


@pytest.mark.parametrize("field", ["key_id", "algorithm"])
@pytest.mark.parametrize("bad_value", [["x"], {"a": 1}, 7])
def test_a_non_string_pack_signature_field_is_malformed_not_raised(
    kp, trusted, field, bad_value
):
    pack = _sign_pack(_pack([]), kp)
    pack["pack_signature"][field] = bad_value
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert f"signature_block_{field}_not_a_string" in result.failures


@pytest.mark.parametrize(
    "bad_value",
    [float("nan"), float("inf"), "\ud800", 2**53],
    ids=["nan", "inf", "lone-surrogate", "unsafe-int"],
)
def test_a_pack_that_cannot_be_canonicalized_is_malformed_not_raised(
    kp, trusted, bad_value
):
    pack = _sign_pack(_pack([]), kp)
    pack["manifest"]["extra"] = bad_value
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert any(f.startswith("pack_not_canonicalizable") for f in result.failures)


def test_a_too_deep_pack_is_malformed_not_raised(kp, trusted):
    nested = 0
    for _ in range(200):
        nested = [nested]
    pack = _sign_pack(_pack([]), kp)
    pack["manifest"]["extra"] = nested
    result = verify_evidence_pack(pack, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED


@pytest.mark.parametrize(
    "bad_value", [float("nan"), "\ud800"], ids=["nan", "lone-surrogate"]
)
def test_an_envelope_that_cannot_be_canonicalized_is_malformed_not_raised(
    kp, trusted, bad_value
):
    envelope = _sign_envelope(_envelope(), kp)
    envelope["extension"] = bad_value
    result = verify_trace_envelope(envelope, trusted_keys=trusted)
    assert result.status is TraceStatus.MALFORMED
    assert result.signature_verified is False
    assert any(f.startswith("envelope_not_canonicalizable") for f in result.failures)
