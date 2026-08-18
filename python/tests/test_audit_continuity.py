"""Audit-chain continuity protocol tests (spec 3.2.7.1 - issue #273).

The gap: `audit_chain_root` is fixed at signing time, decisions happen after,
and nothing let a verifier tell an append-only extension from a chain rebuilt
around the signed prefix. These cover both trace types, the published test
vectors, every fail-closed path, and the `EXTENDED` field result end to end
through `verify_manifest`.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._audit_continuity import (
    AuditCheckpoint,
    entry_leaf,
    extend_hash_chain,
    hash_chain_root,
    verify_continuity,
)
from agent_manifest._canonicalize import canonicalize
from agent_manifest._merkle import MerkleTree

UTC = timezone.utc

# The vectors published in spec 3.2.7.1.
LEAF_0 = "60254cf11420c61e878667adc185b683d261a19e9c74da5d224687758db65267"
LEAF_1 = "933612cc73106c049a8b4c4ea20103c997d26f9ff45f4eda83eac569f0c82cf5"
LEAF_2 = "d2a1bd03e6ea0d31241263f59252f5fab5f4f9a6625c8b89c90d0d116b17d441"
CHAIN_2 = "sha256:0d313a1b8e77e6f1c7a585f99ca9c877f75dd6876229c2164d25694df3f3f0ba"
CHAIN_3 = "sha256:ce399e52ed691feeb4703b1b259d4ef166350b6a23363209943e2a57276990bb"
MERKLE_2 = "sha256:478f71a93107b464fedfb132180fe3b881ee09950aaace2aeced2e4fdb59b406"
MERKLE_3 = "sha256:4974beaa3bbe693aa96414258aec1854551edcabd564108f4485e0bed4cc3ddb"


def _entries(n):
    return [{"decision": "allow", "seq": i, "tool": "kyc.lookup"} for i in range(n)]


def _leaves(n):
    return [entry_leaf(canonicalize(e)) for e in _entries(n)]


def _tree(leaves):
    tree = MerkleTree()
    for leaf in leaves:
        tree.add_prehashed_leaf(leaf)
    return tree


def _cp(root, size, seq, *, ttl=300, observed_at=None):
    return AuditCheckpoint(root, size, seq, observed_at or datetime.now(UTC), ttl)


# ---------------------------------------------------------------------------
# Published vectors
# ---------------------------------------------------------------------------


def test_entry_leaves_match_the_published_vectors():
    assert [leaf.hex() for leaf in _leaves(3)] == [LEAF_0, LEAF_1, LEAF_2]


def test_hash_chain_roots_match_the_published_vectors():
    leaves = _leaves(3)
    assert "sha256:" + hash_chain_root(leaves[:2]).hex() == CHAIN_2
    assert "sha256:" + hash_chain_root(leaves).hex() == CHAIN_3


def test_merkle_log_roots_match_the_published_vectors():
    leaves = _leaves(3)
    assert _tree(leaves[:2]).root_hex() == MERKLE_2
    assert _tree(leaves).root_hex() == MERKLE_3


def test_the_two_trace_types_never_share_a_root():
    """0x02 vs the RFC 9162 0x01: without it a left-spine tree and a chain
    over the same entries produce identical roots for n <= 3."""
    for n in (2, 3, 4):
        leaves = _leaves(n)
        assert "sha256:" + hash_chain_root(leaves).hex() != _tree(leaves).root_hex()


def test_empty_chain_is_not_a_one_entry_chain():
    assert hash_chain_root([]) != hash_chain_root(_leaves(1))


# ---------------------------------------------------------------------------
# Acceptance
# ---------------------------------------------------------------------------


def test_merkle_advance_with_a_valid_consistency_proof_is_accepted():
    leaves = _leaves(3)
    proof = _tree(leaves).consistency_proof(2)
    verdict = verify_continuity(
        _cp(MERKLE_2, 2, 1), _cp(MERKLE_3, 3, 2),
        trace_type="merkle-log", consistency_proof=proof,
    )
    assert verdict == type(verdict)(True, "accepted")


def test_hash_chained_advance_folded_forward_is_accepted():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(CHAIN_3, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2]],
    )
    assert verdict.accepted


def test_unmoved_chain_is_continuous():
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(CHAIN_2, 2, 1),
        trace_type="hash-chained", appended_entry_leaves=[],
    )
    assert verdict.accepted


def test_extend_matches_a_full_recomputation():
    leaves = _leaves(5)
    from_scratch = hash_chain_root(leaves)
    incremental = extend_hash_chain(hash_chain_root(leaves[:2]), leaves[2:])
    assert from_scratch == incremental


# ---------------------------------------------------------------------------
# Fail-closed paths
# ---------------------------------------------------------------------------


def test_absent_proof_is_discontinuity_not_acceptance():
    """The core of #273: growth with nothing proving it is not acceptable."""
    verdict = verify_continuity(
        _cp(MERKLE_2, 2, 1), _cp(MERKLE_3, 3, 2),
        trace_type="merkle-log", consistency_proof=[],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_rebuilt_chain_that_re_contains_the_signed_prefix_is_rejected():
    """A chain rebuilt with a different entry at position 1 still 'contains'
    entry 0, which is exactly what entry_count cannot catch."""
    honest = _leaves(3)
    rebuilt = [honest[0], entry_leaf(canonicalize({"decision": "deny", "seq": 1,
                                                   "tool": "kyc.lookup"})), honest[2]]
    forged_root = "sha256:" + hash_chain_root(rebuilt).hex()
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(forged_root, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=[rebuilt[2]],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_wrong_appended_leaf_count_is_discontinuity():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(CHAIN_3, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2], leaves[2]],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_truncation_below_the_signed_size_is_discontinuity():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp(CHAIN_3, 3, 1), _cp(CHAIN_2, 2, 2),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2]],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_zero_signed_size_is_not_a_provable_advance():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp("sha256:" + hash_chain_root([]).hex(), 0, 1), _cp(CHAIN_3, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=leaves,
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_algorithm_switch_is_not_an_append():
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp("shake256:" + "a" * 64, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=_leaves(3)[2:],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


@pytest.mark.parametrize("root", ["not-a-hash", "sha256:", ":abc", "sha256:zz", ""])
def test_malformed_roots_fail_closed(root):
    verdict = verify_continuity(
        _cp(root, 2, 1), _cp(CHAIN_3, 3, 2),
        trace_type="hash-chained", appended_entry_leaves=_leaves(3)[2:],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_unknown_trace_type_is_discontinuity():
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(CHAIN_3, 3, 2),
        trace_type="ledger-of-vibes", appended_entry_leaves=_leaves(3)[2:],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_declared_size_above_the_merkle_cap_is_rejected_before_any_work():
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1), _cp(CHAIN_3, 10_000_001, 2),
        trace_type="hash-chained", appended_entry_leaves=[],
    )
    assert not verdict.accepted and verdict.reason == "discontinuity"


def test_a_chain_that_moved_without_the_seq_moving_is_a_rollback():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 7), _cp(CHAIN_3, 3, 7),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2]],
    )
    assert not verdict.accepted and verdict.reason == "rollback"


def test_lower_seq_is_a_rollback():
    leaves = _leaves(3)
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 9), _cp(CHAIN_3, 3, 8),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2]],
    )
    assert not verdict.accepted and verdict.reason == "rollback"


def test_stale_checkpoint_expires():
    leaves = _leaves(3)
    stale = datetime.now(UTC) - timedelta(hours=2)
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 1, observed_at=stale),
        _cp(CHAIN_3, 3, 2, ttl=300, observed_at=stale),
        trace_type="hash-chained", appended_entry_leaves=[leaves[2]],
    )
    assert not verdict.accepted and verdict.reason == "expired"


def test_proof_stages_run_in_spec_order():
    """A bad proof AND a rolled-back seq reports the proof failure: stage 2
    before stage 3, so the strongest reason is the one surfaced."""
    verdict = verify_continuity(
        _cp(CHAIN_2, 2, 9), _cp(CHAIN_3, 3, 1),
        trace_type="merkle-log", consistency_proof=[],
    )
    assert verdict.reason == "discontinuity"


# ---------------------------------------------------------------------------
# End to end through verify_manifest
# ---------------------------------------------------------------------------


def _manifest_with_trace(root, entry_count, trace_type="hash-chained"):
    now = datetime.now(UTC)
    return {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "crypto_profile": "standard",
        "artifacts": {
            "decision_trace": {
                "trace_type": trace_type,
                "audit_chain_root": root,
                "audit_chain_uri": "https://audit.example/chain",
                "signing_key_id": "sealed-key-1",
                "audit_key_sealed": True,
                "first_entry_at": now.isoformat().replace("+00:00", "Z"),
                "last_entry_at": now.isoformat().replace("+00:00", "Z"),
                "entry_count": entry_count,
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
        },
    }


def _verify(manifest, context_kwargs):
    from agent_manifest._verify import (
        RevocationStore,
        VerificationContext,
        verify_manifest,
    )
    return verify_manifest(manifest, VerificationContext(**context_kwargs),
                           RevocationStore())


def test_verify_manifest_reports_extended_for_a_proven_advance():
    from agent_manifest._verify import FieldResult
    leaves = _leaves(3)
    result = _verify(
        _manifest_with_trace(CHAIN_2, 2),
        {
            "audit_chain_root": CHAIN_3,
            "audit_chain_continuity": {
                "signed_tree_size": 2, "current_tree_size": 3,
                "signed_seq": 1, "current_seq": 2,
                "appended_entry_leaves": [leaves[2].hex()],
            },
        },
    )
    assert result.fields_verified.decision_trace == FieldResult.EXTENDED
    assert not [m for m in result.mismatch_details if m.field == "decision_trace"]


def test_verify_manifest_still_mismatches_an_unproven_advance():
    from agent_manifest._verify import FieldResult
    result = _verify(_manifest_with_trace(CHAIN_2, 2), {"audit_chain_root": CHAIN_3})
    assert result.fields_verified.decision_trace == FieldResult.MISMATCH
    assert [m for m in result.mismatch_details if m.field == "decision_trace"]


def test_verify_manifest_matches_an_unmoved_chain():
    from agent_manifest._verify import FieldResult
    result = _verify(_manifest_with_trace(CHAIN_2, 2), {"audit_chain_root": CHAIN_2})
    assert result.fields_verified.decision_trace == FieldResult.MATCH


def test_continuity_anchored_at_a_size_the_issuer_never_signed_is_rejected():
    """entry_count is the only size the issuer signed. A runtime that anchors
    its proof at a different signed size is choosing its own baseline."""
    from agent_manifest._verify import FieldResult
    leaves = _leaves(3)
    result = _verify(
        _manifest_with_trace(CHAIN_2, 2),
        {
            "audit_chain_root": CHAIN_3,
            "audit_chain_continuity": {
                "signed_tree_size": 1, "current_tree_size": 3,
                "signed_seq": 1, "current_seq": 2,
                "appended_entry_leaves": [leaves[1].hex(), leaves[2].hex()],
            },
        },
    )
    assert result.fields_verified.decision_trace == FieldResult.MISMATCH


def test_malformed_hex_in_a_proof_does_not_raise():
    from agent_manifest._verify import FieldResult
    result = _verify(
        _manifest_with_trace(MERKLE_2, 2, trace_type="merkle-log"),
        {
            "audit_chain_root": MERKLE_3,
            "audit_chain_continuity": {
                "signed_tree_size": 2, "current_tree_size": 3,
                "signed_seq": 1, "current_seq": 2,
                "consistency_proof": ["nothexatall"],
            },
        },
    )
    assert result.fields_verified.decision_trace == FieldResult.MISMATCH


def test_audit_checkpoint_binding_roundtrips():
    from agent_manifest import AuditCheckpointBinding
    binding = AuditCheckpointBinding(
        audit_chain_root=CHAIN_3,
        tree_size=3,
        seq=2,
        observed_at=datetime.now(UTC),
        ttl_seconds=300,
    )
    assert binding.audit_chain_root == CHAIN_3
    with pytest.raises(ValueError):
        AuditCheckpointBinding(
            audit_chain_root=CHAIN_3, tree_size=3, seq=2,
            observed_at=datetime.now(UTC), ttl_seconds=30,
        )
