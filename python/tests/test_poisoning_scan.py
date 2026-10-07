"""Tests for poisoning_scan.result enforcement - issue #153 - and scan subject binding - issue #472.

Covers spec §3.2.5.1:
  - flagged  -> MUST NOT verify as VALID (any conformance level)
  - Level 1+ + not-scanned -> MUST NOT verify as VALID
  - Level 0  + not-scanned -> VALID but warnings non-empty
  - Level 0  + clean       -> VALID, no warnings (regression)
  - Level 1  + clean       -> VALID, no warnings (regression)

Covers spec §3.2.5 scan subject binding (issue #472):
  - subject_digest != merkle_root -> MUST NOT verify as VALID (any level); the result is not read
  - Level 1+ + clean/flagged without subject_digest -> MUST NOT verify as VALID
  - Level 0  + clean without subject_digest -> VALID (absent is permitted at Level 0)
  - vendored fixture vectors/scan-subject-binding-v0 (recompute-kit, CC0): c1 and c1b
"""
import json
import os
from datetime import datetime, timedelta, timezone

from agent_manifest._signing import Ed25519Signer, generate_ed25519
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
TRANSPARENCY_ENTRY_ID = "rekor-poisoning-suite-entry"

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}


def sign(m):
    m["signature"] = Ed25519Signer(KP).sign(m)
    return m


def attach_transparency_entry(m):
    m["transparency_log_entry"] = {
        "log_id": "0" * 64,
        "log_index": 1,
        "entry_uuid": TRANSPARENCY_ENTRY_ID,
        "integrated_time": int(NOW.timestamp()),
        "inclusion_proof": {
            "checkpoint": "signed-checkpoint",
            "hashes": [],
            "tree_size": 1,
        },
    }
    return m


def base_manifest(poisoning_result: str, subject_digest="bound"):
    """subject_digest: "bound" (default) names this corpus's merkle_root whenever a scan ran (clean / flagged),
    None omits it, any other value is used as given."""
    scan = {"result": poisoning_result}
    if subject_digest == "bound":
        if poisoning_result in ("clean", "flagged"):
            scan["subject_digest"] = SHA_A
    elif subject_digest is not None:
        scan["subject_digest"] = subject_digest
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA_A},
            "policy_bundle": {"hash": SHA_B},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
            "rag_corpus": {
                "merkle_root": SHA_A,
                "poisoning_scan": scan,
            },
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    return attach_transparency_entry(sign(m))


def base_context(conformance_level: int = 0):
    return VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        rag_corpus_merkle_root=SHA_A,
        trusted_keys=dict(TRUSTED_KEYS),
        conformance_level=conformance_level,
        verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
        transparency_evidence_manifest_id=MID,
    )


def store():
    return RevocationStore()


# ---------------------------------------------------------------------------
# flagged -> non-VALID regardless of conformance level
# ---------------------------------------------------------------------------


def test_flagged_result_is_not_valid_level0():
    result = verify_manifest(base_manifest("flagged"), base_context(0), store())
    assert result.result != OverallResult.VALID
    assert any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


def test_flagged_result_is_not_valid_level1():
    result = verify_manifest(base_manifest("flagged"), base_context(1), store())
    assert result.result != OverallResult.VALID
    assert any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


# ---------------------------------------------------------------------------
# Level 1 + not-scanned -> non-VALID
# ---------------------------------------------------------------------------


def test_not_scanned_level1_is_not_valid():
    result = verify_manifest(base_manifest("not-scanned"), base_context(1), store())
    assert result.result != OverallResult.VALID
    assert any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


def test_not_scanned_level2_is_not_valid():
    result = verify_manifest(base_manifest("not-scanned"), base_context(2), store())
    assert result.result != OverallResult.VALID


# ---------------------------------------------------------------------------
# Level 0 + not-scanned -> VALID with warning
# ---------------------------------------------------------------------------


def test_not_scanned_level0_is_valid_with_warning():
    result = verify_manifest(base_manifest("not-scanned"), base_context(0), store())
    assert result.result == OverallResult.VALID
    assert len(result.warnings) > 0
    assert any("not-scanned" in w for w in result.warnings)


def test_not_scanned_level0_no_mismatch_details():
    result = verify_manifest(base_manifest("not-scanned"), base_context(0), store())
    assert not any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


# ---------------------------------------------------------------------------
# clean -> VALID, no warnings (regression)
# ---------------------------------------------------------------------------


def test_clean_level0_is_valid_no_warnings():
    result = verify_manifest(base_manifest("clean"), base_context(0), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


def test_clean_level1_is_valid_no_warnings():
    result = verify_manifest(base_manifest("clean"), base_context(1), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


# ---------------------------------------------------------------------------
# No rag_corpus in manifest -> no poisoning scan check, no warnings
# ---------------------------------------------------------------------------


def test_no_rag_corpus_no_warnings():
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA_A},
            "policy_bundle": {"hash": SHA_B},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    sign(m)
    attach_transparency_entry(m)
    ctx = VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
        conformance_level=1,
        verified_transparency_entry_ids={TRANSPARENCY_ENTRY_ID},
        transparency_evidence_manifest_id=MID,
    )
    result = verify_manifest(m, ctx, store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


# ---------------------------------------------------------------------------
# Scan subject binding (spec §3.2.5, issue #472)
# ---------------------------------------------------------------------------


def _binding_mismatch(result):
    return [d for d in result.mismatch_details if d.field == "rag_corpus.poisoning_scan.subject_digest"]


def test_clean_scan_naming_another_corpus_is_not_valid_level0():
    result = verify_manifest(base_manifest("clean", subject_digest=SHA_B), base_context(0), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)


def test_clean_scan_naming_another_corpus_is_not_valid_level1():
    result = verify_manifest(base_manifest("clean", subject_digest=SHA_B), base_context(1), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)


def test_unbound_result_is_not_read_as_a_statement_about_the_corpus():
    """The binding is checked before the result: a flagged scan of ANOTHER corpus is reported as a
    binding failure, not as 'this corpus is flagged'."""
    result = verify_manifest(base_manifest("flagged", subject_digest=SHA_B), base_context(0), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)
    assert not any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


def test_clean_without_subject_digest_is_not_valid_level1():
    result = verify_manifest(base_manifest("clean", subject_digest=None), base_context(1), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)


def test_flagged_without_subject_digest_is_not_valid_level1():
    """Distinct from test_flagged_result_is_not_valid_level1: flagged alone already fails
    Level 1 under the older result rule, so `!= VALID` on its own would also pass with the
    binding check disabled. Assert the binding mismatch specifically fires, and that the
    binding-first guard suppresses the separate result-based mismatch (the scan is unbound,
    so its flagged result is never read as a statement about this corpus)."""
    result = verify_manifest(base_manifest("flagged", subject_digest=None), base_context(1), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)
    assert not any(d.field == "rag_corpus.poisoning_scan" for d in result.mismatch_details)


def test_clean_without_subject_digest_is_valid_level0():
    """Level 0 permits an absent subject_digest (unchanged behaviour, no new warning)."""
    result = verify_manifest(base_manifest("clean", subject_digest=None), base_context(0), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


def test_not_scanned_needs_no_subject_digest():
    result = verify_manifest(base_manifest("not-scanned"), base_context(0), store())
    assert not _binding_mismatch(result)


def test_not_scanned_with_wrong_subject_digest_is_not_valid_any_level():
    """Binding-first path: 'not-scanned' needs no subject_digest at all (the test above), but
    a PRESENT and wrong one is still a binding failure at every conformance level -- a stray
    or incorrect subject_digest on an unscanned corpus is not silently ignored just because
    the result itself carries no scan evidence to protect."""
    result = verify_manifest(base_manifest("not-scanned", subject_digest=SHA_B), base_context(0), store())
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)


# ---------------------------------------------------------------------------
# Vendored fixture: recompute-kit scan-subject-binding-v0 (CC0), cases c1 / c1b
# ---------------------------------------------------------------------------

with open(os.path.join(os.path.dirname(__file__), "vectors", "scan-subject-binding-v0", "vectors.json")) as _f:
    _VEC = json.load(_f)


def _fixture_manifest(case_id):
    """The manifest under test carries the vector's rag_corpus block (corpus B's merkle_root and the scan as given); the
    context binds the manifest to that same corpus root, so only the scan binding can decide the result."""
    rc = _VEC["cases"][case_id]["manifest"]["body"]["rag_corpus"]
    scan = {k: v for k, v in rc["poisoning_scan"].items() if k in ("scanner_version", "scanned_at", "result", "subject_digest")}
    m = json.loads(json.dumps(base_manifest("clean")))
    m.pop("signature", None)
    m.pop("transparency_log_entry", None)   # re-signed then re-attached by the caller, same order as base_manifest
    m["artifacts"]["rag_corpus"] = {"merkle_root": rc["merkle_root"], "poisoning_scan": scan}
    return m, rc["merkle_root"]


def _verify_fixture(case_id, level):
    m, root = _fixture_manifest(case_id)
    m = attach_transparency_entry(sign(m))
    ctx = base_context(level)
    ctx.rag_corpus_merkle_root = root
    return verify_manifest(m, ctx, store())


def test_fixture_c1_unbound_clean_scan_of_other_corpus_level1():
    """c1: corpus B's root carried with corpus A's clean scan and no subject_digest. A result-only verifier says VALID;
    at Level 1+ subject_digest is required, so this MUST NOT verify."""
    result = _verify_fixture("c1_scan_of_A_presented_with_B_unbound", 1)
    assert result.result != OverallResult.VALID
    assert _binding_mismatch(result)


def test_fixture_c1_unbound_is_permitted_level0():
    """c1 at Level 0: an absent subject_digest is permitted there (the residual gap the Level 1+ requirement closes)."""
    result = _verify_fixture("c1_scan_of_A_presented_with_B_unbound", 0)
    assert result.result == OverallResult.VALID


def test_fixture_c1b_scan_bound_to_other_corpus_any_level():
    """c1b: the scan names corpus A's root next to corpus B's merkle_root. Not VALID at any level."""
    for level in (0, 1, 2):
        result = _verify_fixture("c1b_scan_of_A_presented_with_B_bound", level)
        assert result.result != OverallResult.VALID, level
        assert _binding_mismatch(result), level
        assert _binding_mismatch(result)[0].actual_hash == _VEC["cases"]["c1b_scan_of_A_presented_with_B_bound"]["manifest"]["body"]["rag_corpus"]["poisoning_scan"]["subject_digest"]


def test_fixture_corpus_a_own_scan_is_valid_level1():
    """Control: corpus A's root with A's own scan (c1b's subject_digest) verifies at Level 1."""
    m, _ = _fixture_manifest("c1b_scan_of_A_presented_with_B_bound")
    a_root = m["artifacts"]["rag_corpus"]["poisoning_scan"]["subject_digest"]
    m["artifacts"]["rag_corpus"]["merkle_root"] = a_root
    m = attach_transparency_entry(sign(m))
    ctx = base_context(1)
    ctx.rag_corpus_merkle_root = a_root
    assert verify_manifest(m, ctx, store()).result == OverallResult.VALID
