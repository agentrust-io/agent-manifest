"""Memory checkpoint & delta binding protocol (spec Section 3.2.6.2, v0.2).

Binds *incremental* memory evolution without re-hashing/re-approving the whole
store. Memory is modelled as an **append-only operation log** (an RFC 9162
merkle-log, consistent with decision-trace ``trace_type: merkle-log``): each
mutation is an appended operation leaf — ``PUT``/``DEL`` for key-value memory,
``ADD`` for semantic/vector and graph-RAG memory — never a positional rewrite.

A checkpoint advance N -> N+1 is a governed advance iff an RFC 9162 §2.1.2
consistency proof shows checkpoint N's log is an append-only positional prefix
of N+1, the sequence number is monotonic, the checkpoint is within its TTL, and
the delta is within budget. Anything unproven falls through to drift — the
existing v0.1 ``drift_policy`` path (``_verify`` / spec §3.2.6.1) is preserved.

The three representations differ only in the leaf encoder; the tree, root,
checkpoint, and consistency proof are identical — the same primitive the RAG
corpus incremental-update protocol (B-1) will reuse.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from ._canonicalize import canonicalize
from ._merkle import _HASH_FNS, _MAX_MERKLE_LEAVES, MerkleTree, verify_consistency

# Domain-separation tags keep one representation's leaf from colliding with
# another's even for structurally identical canonical payloads.
_TAGS = {
    "kv": b"am-mem-kv\x00",
    "vector": b"am-mem-vec\x00",
    "graph-node": b"am-mem-gnode\x00",
    "graph-edge": b"am-mem-gedge\x00",
}

DeltaReason = Literal["accepted", "drift", "rollback", "expired", "budget"]


# ---------------------------------------------------------------------------
# Leaf encoders (one canonical preimage per operation)
# ---------------------------------------------------------------------------


def _kv_leaf(op: dict[str, Any]) -> bytes:
    payload = {"op": op["op"], "key": op["key"]}
    if op["op"] == "PUT":
        payload["value"] = op["value"]
    return _TAGS["kv"] + canonicalize(payload)


def _vector_leaf(op: dict[str, Any]) -> bytes:
    emb = op["embedding"]
    # Disambiguate a raw-bytes embedding from a hex-looking string, so that
    # b"\x01\x02" and "0102" can never produce the same leaf preimage.
    emb_field = {"b": emb.hex()} if isinstance(emb, (bytes, bytearray)) else {"s": emb}
    payload = {
        "op": op["op"],
        "id": op["id"],
        "embedding": emb_field,
        "embedding_model_id": op["embedding_model_id"],
        "content_hash": op.get("content_hash"),
    }
    return _TAGS["vector"] + canonicalize(payload)


def _graph_leaf(op: dict[str, Any]) -> bytes:
    if op.get("kind") == "edge":
        payload = {"op": op["op"], "src": op["src"], "rel": op["rel"],
                   "dst": op["dst"], "props": op.get("props", {})}
        return _TAGS["graph-edge"] + canonicalize(payload)
    payload = {"op": op["op"], "node_id": op["node_id"], "props": op.get("props", {})}
    return _TAGS["graph-node"] + canonicalize(payload)


_ENCODERS = {"kv": _kv_leaf, "vector": _vector_leaf, "graph": _graph_leaf}


# ---------------------------------------------------------------------------
# Memory tree (append-only operation log)
# ---------------------------------------------------------------------------


def memory_merkletree(ops: list[dict[str, Any]], representation: str, *, algorithm: str = "sha256") -> MerkleTree:
    """Build the append-only operation-log Merkle tree (NO sort — LD-4).

    Leaves are appended in operation-sequence order via ``MerkleTree.add_leaf``
    so checkpoint N is a true positional prefix of N+1.

    Raises:
        KeyError: If *representation* is not 'kv', 'vector', or 'graph'.
        ValueError: If the op count exceeds the _MAX_MERKLE_LEAVES DOS cap.
    """
    if len(ops) > _MAX_MERKLE_LEAVES:
        raise ValueError(
            f"memory_merkletree: {len(ops)} operations exceeds the "
            f"{_MAX_MERKLE_LEAVES}-leaf maximum. Re-baseline the checkpoint."
        )
    encode = _ENCODERS[representation]
    tree = MerkleTree(algorithm=algorithm)
    for op in ops:
        tree.add_leaf(encode(op))
    return tree


def build_memory_tree(ops: list[dict[str, Any]], representation: str, *, algorithm: str = "sha256") -> str:
    """Return the memory-log root in HashValue form (``"sha256:<64-hex>"``)."""
    return memory_merkletree(ops, representation, algorithm=algorithm).root_hex()


def fold_kv(ops: list[dict[str, Any]]) -> dict[str, Any]:
    """Materialise current KV state from the op log (last-writer-wins).

    The fold is the bridge to the v0.1 set-snapshot: canonicalizing this map and
    hashing it reproduces ``memory_baseline.snapshot_hash`` (spec §3.2.6.1).
    """
    state: dict[str, Any] = {}
    for op in ops:
        if op["op"] == "PUT":
            state[op["key"]] = op["value"]
        elif op["op"] == "DEL":
            state.pop(op["key"], None)
    return state


# ---------------------------------------------------------------------------
# Checkpoint + delta verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MemoryCheckpoint:
    """An approved memory state anchor over the operation log."""

    memory_root: str          # HashValue ("sha256:<hex>")
    tree_size: int            # number of operation leaves
    seq: int                  # monotonic checkpoint sequence
    approved_at: datetime
    ttl_seconds: int
    max_delta_fraction: float = 0.5

    @classmethod
    def from_ops(cls, ops: list[dict[str, Any]], representation: str, *, seq: int,
                 approved_at: datetime, ttl_seconds: int,
                 max_delta_fraction: float = 0.5,
                 algorithm: str = "sha256") -> "MemoryCheckpoint":
        tree = memory_merkletree(ops, representation, algorithm=algorithm)
        return cls(tree.root_hex(), len(ops), seq, approved_at, ttl_seconds,
                   max_delta_fraction)


@dataclass(frozen=True)
class DeltaVerdict:
    accepted: bool
    reason: DeltaReason


def _as_utc(dt: datetime) -> datetime:
    """Coerce a naive datetime to UTC so TTL comparison never raises."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _root_bytes(hashvalue: str) -> tuple[str, bytes]:
    """Parse a ``'algorithm:hex'`` HashValue. Raises ValueError if malformed."""
    algorithm, sep, hex_digest = hashvalue.partition(":")
    if not sep or algorithm not in _HASH_FNS or not hex_digest:
        raise ValueError(f"malformed memory_root: {hashvalue!r}")
    try:
        return algorithm, bytes.fromhex(hex_digest)
    except ValueError as exc:
        raise ValueError(f"malformed memory_root hex: {hashvalue!r}") from exc


def verify_delta(
    prev: MemoryCheckpoint,
    new: MemoryCheckpoint,
    ops: list[dict[str, Any]],
    consistency_proof: list[bytes],
    *,
    now: datetime | None = None,
) -> DeltaVerdict:
    """Adjudicate a checkpoint advance prev -> new.

    Order (fail-closed; LD-5): consistency proof -> seq monotonic -> ttl window
    -> delta budget. A failure at the consistency stage is ``drift`` — exactly
    the v0.1 path an unproven memory change already takes.
    """
    now = _as_utc(now) if now else datetime.now(timezone.utc)
    try:
        algorithm, prev_bytes = _root_bytes(prev.memory_root)
        new_algorithm, new_bytes = _root_bytes(new.memory_root)
    except ValueError:
        return DeltaVerdict(False, "drift")  # malformed root → fail closed
    if algorithm != new_algorithm:
        return DeltaVerdict(False, "drift")  # an algorithm switch is not an append

    # Stage 1: consistency proof (append-only positional prefix).
    if not verify_consistency(prev_bytes, new_bytes, prev.tree_size,
                              new.tree_size, consistency_proof, algorithm=algorithm):
        return DeltaVerdict(False, "drift")
    # An empty prior log has no approved state to extend; a 0 -> N jump is a
    # re-baseline (full re-approval per spec §3.2.6.1), not a governed delta.
    # verify_consistency accepts an empty proof for first_size==0, so reject here.
    if prev.tree_size == 0:
        return DeltaVerdict(False, "drift")
    if new.seq <= prev.seq:
        return DeltaVerdict(False, "rollback")
    if now > _as_utc(new.approved_at) + timedelta(seconds=new.ttl_seconds):
        return DeltaVerdict(False, "expired")
    added = new.tree_size - prev.tree_size
    if added / prev.tree_size > new.max_delta_fraction:
        return DeltaVerdict(False, "budget")
    return DeltaVerdict(True, "accepted")
