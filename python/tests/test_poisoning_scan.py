"""Tests for poisoning_scan.result enforcement - issue #153.

Covers spec §3.2.5.1:
  - flagged  -> MUST NOT verify as VALID (any conformance level)
  - Level 1+ + not-scanned -> MUST NOT verify as VALID
  - Level 0  + not-scanned -> VALID but warnings non-empty
  - Level 0  + clean       -> VALID, no warnings (regression)
  - Level 1  + clean       -> VALID, no warnings (regression)
"""
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

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}


def sign(m):
    m["signature"] = Ed25519Signer(KP).sign(m)
    return m


def base_manifest(poisoning_result: str):
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
                "poisoning_scan": {"result": poisoning_result},
            },
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    return sign(m)


def base_context(conformance_level: int = 0):
    return VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        rag_corpus_merkle_root=SHA_A,
        trusted_keys=dict(TRUSTED_KEYS),
        conformance_level=conformance_level,
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
    ctx = VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
        conformance_level=1,
    )
    result = verify_manifest(m, ctx, store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []
