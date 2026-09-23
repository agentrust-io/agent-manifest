"""LD-5: an accepted memory delta authenticates the presented appended leaves."""
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agent_manifest._memory_delta import MemoryCheckpoint, memory_merkletree, verify_delta
from agent_manifest._merkle import MerkleTree, _consistency_ranges, verify_consistency_append

NOW = datetime(2026, 6, 15, 12, tzinfo=timezone.utc)


def operations(n, representation):
    if representation == "kv":
        return [{"op": "PUT", "key": str(i), "value": i} for i in range(n)]
    if representation == "vector":
        return [{"op": "ADD", "id": str(i), "embedding": bytes([i]),
                 "embedding_model_id": "m"} for i in range(n)]
    return [{"op": "ADD", "kind": "node", "node_id": str(i), "props": {"i": i}}
            if i % 2 == 0 else
            {"op": "ADD", "kind": "edge", "src": str(i), "rel": "next",
             "dst": str(i + 1)} for i in range(n)]


def advance(m=6, n=8, representation="kv", algorithm="sha256"):
    ops = operations(n, representation)
    options = dict(approved_at=NOW, ttl_seconds=3600, max_delta_fraction=100,
                   algorithm=algorithm)
    prev = MemoryCheckpoint.from_ops(ops[:m], representation, seq=1, **options)
    new = MemoryCheckpoint.from_ops(ops, representation, seq=2, **options)
    proof = memory_merkletree(ops, representation, algorithm=algorithm).consistency_proof(m)
    return prev, new, ops[m:], proof


@pytest.mark.parametrize("bad", [[], None, ["a", 1, None],
                                 [{"op": "PUT", "key": "x", "value": "evil"}]])
def test_unrelated_operations_cannot_borrow_a_valid_proof(bad):
    """LD-5: proof success does not authenticate an arbitrary operation list."""
    prev, new, real, proof = advance()
    assert verify_delta(prev, new, real, proof, representation="kv", now=NOW).accepted
    assert verify_delta(prev, new, bad, proof, representation="kv", now=NOW).reason == "drift"


@pytest.mark.parametrize("representation", ["kv", "vector", "graph"])
@pytest.mark.parametrize("algorithm", ["sha256", "shake256"])
def test_every_small_advance_and_every_appended_position(representation, algorithm):
    """LD-5: every 1 <= m < n <= 18 accepts its real delta and rejects substitutions."""
    for n in range(2, 19):
        for m in range(1, n):
            prev, new, delta, proof = advance(m, n, representation, algorithm)

            def verdict(ops):
                return verify_delta(prev, new, ops, proof, representation=representation, now=NOW)

            assert verdict(delta).accepted, (m, n)
            for index in range(len(delta)):
                changed = delta.copy()
                changed[index] = operations(n + 1, representation)[-1]
                assert verdict(changed).reason == "drift", (m, n, index)
                assert verdict(delta[:index] + delta[index + 1:]).reason == "drift"
            for index in range(len(delta) - 1):
                reordered = delta.copy()
                reordered[index:index + 2] = reversed(reordered[index:index + 2])
                assert verdict(reordered).reason == "drift", (m, n, index)
            assert verdict(delta + delta[:1]).reason == "drift"
            assert verdict(operations(n, representation)).reason == "drift"


@pytest.mark.parametrize("algorithm", ["sha256", "shake256"])
def test_proof_intervals_match_builder_nodes_and_partition_the_append(algorithm):
    """LD-5: independently rebuilt subtree roots match every emitted proof node."""
    for n in range(2, 41):
        leaves = [bytes([i]) for i in range(n)]
        tree = MerkleTree(algorithm)
        for leaf in leaves:
            tree.add_leaf(leaf)
        for m in range(1, n):
            ranges = _consistency_ranges(m, n)
            proof = tree.consistency_proof(m)
            assert len(ranges) == len(proof)
            appended_indices = []
            for (start, end), node in zip(ranges, proof):
                subtree = MerkleTree(algorithm)
                for leaf in leaves[start:end]:
                    subtree.add_leaf(leaf)
                assert subtree.root() == node
                assert end <= m or start >= m
                if start >= m:
                    appended_indices.extend(range(start, end))
            assert sorted(appended_indices) == list(range(m, n))


def test_literal_spec_vector_and_wrong_operation():
    """LD-5: fixed spec 3.2.6.2 roots/proof, independent of the tree builder."""
    prev = MemoryCheckpoint("sha256:f2904e572018f088488c4fbd2e5fffaa3bc5f94488eec27ca73f4d1348595b91",
                            1, 1, NOW, 3600, 1)
    new = MemoryCheckpoint("sha256:9a41dee8ec223727525f8b26685e413664190d2b82cd62d4f7c15180a9e1f5af",
                           2, 2, NOW, 3600, 1)
    proof = [bytes.fromhex("42effb8d6d6bf9904585248b30b039a5ede7a447a5f8fd21cc0a8b0b850c566f")]
    assert verify_delta(prev, new, [{"op": "PUT", "key": "b", "value": 2}], proof,
                        representation="kv", now=NOW).accepted
    assert verify_delta(prev, new, [{"op": "PUT", "key": "b", "value": 3}], proof,
                        representation="kv", now=NOW).reason == "drift"


@pytest.mark.parametrize("field,value", [
    ("tree_size", -1), ("tree_size", 6.5), ("tree_size", "6"), ("tree_size", True),
    ("tree_size", 1 << 10000), ("seq", 1.5), ("seq", "2"), ("seq", None),
    ("ttl_seconds", 3600.5), ("ttl_seconds", "3600"), ("ttl_seconds", False),
    ("approved_at", "today"), ("approved_at", None), ("max_delta_fraction", "1"),
    ("memory_root", None), ("memory_root", "sha256:ab"),
])
@pytest.mark.parametrize("side", ["prev", "new"])
def test_malformed_checkpoint_fields_fail_closed(field, value, side):
    """LD-5: untrusted field types cannot escape as exceptions or truncate silently."""
    prev, new, delta, proof = advance()
    if side == "prev":
        prev = replace(prev, **{field: value})
    else:
        new = replace(new, **{field: value})
    assert verify_delta(prev, new, delta, proof, representation="kv", now=NOW).reason == "drift"


@pytest.mark.parametrize("proof", [None, [None], [b"short"], [0], [b"x" * 32] * 100])
def test_malformed_proofs_fail_closed(proof):
    """LD-5: malformed proof nodes are drift, never exceptions."""
    prev, new, delta, _ = advance()
    assert verify_delta(prev, new, delta, proof, representation="kv", now=NOW).reason == "drift"


def test_invalid_proof_does_not_evaluate_operations(monkeypatch):
    """LD-5: do not spend encoding work on unauthenticated proof inputs."""
    from agent_manifest import _memory_delta
    prev, new, delta, _ = advance()

    def forbidden(op):
        raise AssertionError("operation encoder ran before proof verification")

    monkeypatch.setitem(_memory_delta._ENCODERS, "kv", forbidden)
    assert verify_delta(prev, new, delta, [], representation="kv", now=NOW).reason == "drift"


@pytest.mark.parametrize("delta", [[{}, {}], [{"op": "PUT", "key": "x", "value": object()}] * 2])
def test_unencodable_operations_fail_closed(delta):
    """LD-5: bad op keys and noncanonicalizable data are drift."""
    prev, new, _, proof = advance()
    assert verify_delta(prev, new, delta, proof, representation="kv", now=NOW).reason == "drift"


def test_verdict_order_nan_budget_and_ttl_overflow():
    """LD-5: invalid ops remain drift even when a later gate would also reject."""
    prev, new, delta, proof = advance()
    for changes, reason in [({"seq": 1}, "rollback"), ({"ttl_seconds": -1}, "expired"),
                            ({"ttl_seconds": 10**100}, "expired"),
                            ({"max_delta_fraction": float("nan")}, "budget"),
                            ({"max_delta_fraction": 10**1000}, "budget"),
                            ({"max_delta_fraction": 0}, "budget")]:
        altered = replace(new, **changes)
        assert verify_delta(prev, altered, delta, proof, representation="kv", now=NOW).reason == reason
        assert verify_delta(prev, altered, [{"op": "DEL", "key": "x"}] * 2, proof,
                            representation="kv", now=NOW).reason == "drift"


def test_noop_is_bound_to_exact_roots_and_empty_operations():
    """LD-5: equal tree sizes permit only an empty delta with equal valid roots."""
    prev, new, delta, proof = advance(6, 6)
    assert verify_delta(prev, new, delta, proof, representation="kv", now=NOW).accepted
    assert verify_delta(replace(prev, memory_root="sha256:ab"),
                        replace(new, memory_root="sha256:ab"), [], [],
                        representation="kv", now=NOW).reason == "drift"


def test_wrong_representation_is_not_guessed():
    """LD-5: the caller supplies the canonical representation, never inferred from ops."""
    prev, new, delta, proof = advance()
    with pytest.raises(ValueError, match="representation"):
        verify_delta(prev, new, delta, proof, representation="unknown", now=NOW)
    assert verify_delta(prev, new, delta, proof, representation="vector", now=NOW).reason == "drift"


def test_appended_iterator_is_bounded():
    """LD-5: a verified proof does not allow an unbounded appended stream."""
    tree = MerkleTree()
    old_root = tree.add_leaf(b"old")
    tree.add_leaf(b"new")
    reads = []

    def stream():
        for _ in range(3):
            reads.append(1)
            yield b"new"
        raise AssertionError("consumed past declared delta plus one")

    assert not verify_consistency_append(old_root, tree.root(), 1, 2,
                                         tree.consistency_proof(1), stream())
    assert len(reads) == 2


def test_huge_declared_tree_is_rejected_before_iteration():
    """LD-5: a forged size cannot trigger proof traversal or operation iteration."""
    def forbidden():
        raise AssertionError("iterated oversized evidence")
        yield b"unreachable"

    assert not verify_consistency_append(b"a" * 32, b"b" * 32,
                                         1, 1 << 10000, [], forbidden())
