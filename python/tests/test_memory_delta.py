"""Memory checkpoint / delta protocol tests (Phase 2 — v0.2 AI-1).

Covers the append-only operation-log model: deterministic per-sequence roots,
KV / vector / graph leaf binding, consistency-proven delta acceptance, and the
fail-closed rejection paths (unproven=drift, mutated-prior-leaf, expired,
rollback). Per docs/plan-qor-phase1-memory-checkpoint-delta.md.
"""
from datetime import datetime, timedelta, timezone

from agent_manifest._memory_delta import (
    DeltaVerdict,
    MemoryCheckpoint,
    build_memory_tree,
    fold_kv,
    memory_merkletree,
    verify_delta,
)

UTC = timezone.utc


def _kv(seq):
    return [{"op": "PUT", "key": f"k{i}", "value": i} for i in range(seq)]


# ---------------------------------------------------------------------------
# Leaf / tree determinism per representation
# ---------------------------------------------------------------------------


def test_kv_log_root_deterministic_per_sequence():
    ops = [{"op": "PUT", "key": "a", "value": 1}, {"op": "DEL", "key": "a"}]
    assert build_memory_tree(ops, "kv") == build_memory_tree(ops, "kv")
    changed = [{"op": "PUT", "key": "a", "value": 2}, {"op": "DEL", "key": "a"}]
    assert build_memory_tree(ops, "kv") != build_memory_tree(changed, "kv")


def test_vector_leaf_binds_embedding_and_model():
    base = [{"op": "ADD", "id": "v1", "embedding": b"\x01\x02",
             "embedding_model_id": "text-embed-3", "content_hash": "sha256:ab"}]
    same = [dict(base[0])]
    diff_vec = [{**base[0], "embedding": b"\x01\x03"}]
    diff_model = [{**base[0], "embedding_model_id": "text-embed-4"}]
    assert build_memory_tree(base, "vector") == build_memory_tree(same, "vector")
    assert build_memory_tree(base, "vector") != build_memory_tree(diff_vec, "vector")
    assert build_memory_tree(base, "vector") != build_memory_tree(diff_model, "vector")


def test_graph_leaf_binds_nodes_and_edges():
    nodes = [{"op": "ADD", "kind": "node", "node_id": "n1", "props": {"t": "user"}}]
    with_edge = nodes + [{"op": "ADD", "kind": "edge", "src": "n1",
                          "rel": "knows", "dst": "n2", "props": {}}]
    assert build_memory_tree(nodes, "graph") == build_memory_tree(list(nodes), "graph")
    assert build_memory_tree(nodes, "graph") != build_memory_tree(with_edge, "graph")


# ---------------------------------------------------------------------------
# Consistency proof over ACTUAL builder output (closes the Entry #4 gap)
# ---------------------------------------------------------------------------


def test_consistency_proof_over_built_memory_tree():
    from agent_manifest._merkle import verify_consistency

    prev_ops = _kv(5)
    new_ops = _kv(5) + [{"op": "PUT", "key": "k5", "value": 99}]
    prev_tree = memory_merkletree(prev_ops, "kv")
    new_tree = memory_merkletree(new_ops, "kv")
    proof = new_tree.consistency_proof(len(prev_ops))
    assert verify_consistency(
        prev_tree.root(), new_tree.root(), len(prev_ops), len(new_ops), proof
    ) is True


# ---------------------------------------------------------------------------
# verify_delta — acceptance + fail-closed rejections
# ---------------------------------------------------------------------------


def _checkpoint(ops, seq, approved_at, ttl=3600):
    return MemoryCheckpoint.from_ops(ops, "kv", seq=seq, approved_at=approved_at,
                                     ttl_seconds=ttl, max_delta_fraction=0.5)


def test_verify_delta_accepts_proven_in_budget_advance():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev_ops, new_ops = _kv(6), _kv(6) + [{"op": "PUT", "key": "k6", "value": 1}]
    prev = _checkpoint(prev_ops, 1, now)
    new = _checkpoint(new_ops, 2, now)
    proof = memory_merkletree(new_ops, "kv").consistency_proof(len(prev_ops))
    v = verify_delta(prev, new, new_ops, proof, now=now)
    assert isinstance(v, DeltaVerdict) and v.accepted is True and v.reason == "accepted"


def test_verify_delta_rejects_unproven_delta_as_drift():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev_ops, new_ops = _kv(6), _kv(6) + [{"op": "PUT", "key": "k6", "value": 1}]
    prev, new = _checkpoint(prev_ops, 1, now), _checkpoint(new_ops, 2, now)
    v = verify_delta(prev, new, new_ops, [], now=now)  # empty/invalid proof
    assert v.accepted is False and v.reason == "drift"


def test_verify_delta_rejects_mutated_prior_leaf():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev_ops = _kv(6)
    # rewrite leaf 0 then append — NOT a pure append
    mutated = [{"op": "PUT", "key": "k0", "value": 777}] + _kv(6)[1:] + \
        [{"op": "PUT", "key": "k6", "value": 1}]
    prev, new = _checkpoint(prev_ops, 1, now), _checkpoint(mutated, 2, now)
    proof = memory_merkletree(mutated, "kv").consistency_proof(len(prev_ops))
    v = verify_delta(prev, new, mutated, proof, now=now)
    assert v.accepted is False and v.reason == "drift"


def test_verify_delta_rejects_expired_checkpoint():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    approved = now - timedelta(seconds=7200)  # ttl 3600 → expired
    prev_ops, new_ops = _kv(6), _kv(6) + [{"op": "PUT", "key": "k6", "value": 1}]
    prev = _checkpoint(prev_ops, 1, approved)
    new = _checkpoint(new_ops, 2, approved)
    proof = memory_merkletree(new_ops, "kv").consistency_proof(len(prev_ops))
    v = verify_delta(prev, new, new_ops, proof, now=now)
    assert v.accepted is False and v.reason == "expired"


def test_verify_delta_rejects_seq_rollback():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev_ops, new_ops = _kv(6), _kv(6) + [{"op": "PUT", "key": "k6", "value": 1}]
    prev = _checkpoint(prev_ops, 5, now)
    new = _checkpoint(new_ops, 5, now)  # seq not advanced
    proof = memory_merkletree(new_ops, "kv").consistency_proof(len(prev_ops))
    v = verify_delta(prev, new, new_ops, proof, now=now)
    assert v.accepted is False and v.reason == "rollback"


def test_fold_kv_last_writer_wins():
    ops = [{"op": "PUT", "key": "a", "value": 1},
           {"op": "PUT", "key": "a", "value": 2},
           {"op": "PUT", "key": "b", "value": 3},
           {"op": "DEL", "key": "b"}]
    assert fold_kv(ops) == {"a": 2}


# ---------------------------------------------------------------------------
# Code-review regression guards (correctness bugs found in full review)
# ---------------------------------------------------------------------------


def test_verify_delta_naive_approved_at_does_not_crash():
    # Bug: tz-naive approved_at (JSON-deserialized) crashed the ttl compare.
    naive = datetime(2026, 6, 15, 12, 0)  # no tzinfo
    prev = MemoryCheckpoint.from_ops(_kv(4), "kv", seq=1, approved_at=naive, ttl_seconds=3600)
    new = MemoryCheckpoint.from_ops(_kv(4) + [{"op": "PUT", "key": "k4", "value": 1}],
                                    "kv", seq=2, approved_at=naive, ttl_seconds=3600)
    proof = memory_merkletree(_kv(4) + [{"op": "PUT", "key": "k4", "value": 1}],
                              "kv").consistency_proof(4)
    v = verify_delta(prev, new, [], proof, now=datetime(2026, 6, 15, 12, 30, tzinfo=UTC))
    assert isinstance(v, DeltaVerdict) and v.accepted is True  # no TypeError


def test_verify_delta_rejects_empty_prev_checkpoint():
    # Bug: 0 -> N advance was accepted with an empty proof and no budget cap.
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    empty = MemoryCheckpoint.from_ops([], "kv", seq=1, approved_at=now, ttl_seconds=3600)
    big_ops = [{"op": "PUT", "key": f"k{i}", "value": i} for i in range(50)]
    big = MemoryCheckpoint.from_ops(big_ops, "kv", seq=2, approved_at=now, ttl_seconds=3600)
    v = verify_delta(empty, big, big_ops, [], now=now)
    assert v.accepted is False and v.reason == "drift"


def test_verify_delta_rejects_malformed_root_as_drift():
    # Bug: malformed memory_root raised KeyError instead of failing closed.
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    good = MemoryCheckpoint.from_ops(_kv(4), "kv", seq=1, approved_at=now, ttl_seconds=3600)
    bad = MemoryCheckpoint("deadbeef", 5, 2, now, 3600)  # no 'algo:' prefix
    v = verify_delta(good, bad, [], [], now=now)
    assert v.accepted is False and v.reason == "drift"


def test_verify_delta_rejects_algorithm_switch_as_drift():
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev = MemoryCheckpoint.from_ops(_kv(4), "kv", seq=1, approved_at=now, ttl_seconds=3600)
    # same hex but a different (valid) algorithm prefix is not an append
    switched = MemoryCheckpoint("shake256:" + prev.memory_root.split(":")[1],
                                5, 2, now, 3600)
    v = verify_delta(prev, switched, [], [], now=now)
    assert v.accepted is False and v.reason == "drift"


def test_vector_leaf_bytes_vs_hex_string_no_collision():
    # Bug: b"\x01\x02" and "0102" produced identical leaves.
    as_bytes = [{"op": "ADD", "id": "v1", "embedding": b"\x01\x02",
                 "embedding_model_id": "m", "content_hash": "sha256:ab"}]
    as_hexstr = [{"op": "ADD", "id": "v1", "embedding": "0102",
                  "embedding_model_id": "m", "content_hash": "sha256:ab"}]
    assert build_memory_tree(as_bytes, "vector") != build_memory_tree(as_hexstr, "vector")


def test_verify_delta_rejects_nonempty_forged_proof_as_drift():
    # Strengthen the drift gate: a non-empty but wrong proof must also be drift.
    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    prev_ops, new_ops = _kv(6), _kv(6) + [{"op": "PUT", "key": "k6", "value": 1}]
    prev = MemoryCheckpoint.from_ops(prev_ops, "kv", seq=1, approved_at=now, ttl_seconds=3600)
    new = MemoryCheckpoint.from_ops(new_ops, "kv", seq=2, approved_at=now, ttl_seconds=3600)
    forged = [b"\x00" * 32]  # structurally non-empty but bogus
    v = verify_delta(prev, new, new_ops, forged, now=now)
    assert v.accepted is False and v.reason == "drift"
