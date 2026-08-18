"""Audit-chain checkpoint & continuity protocol (spec Section 3.2.7.1, v0.2).

Section 3.2.7 binds ``audit_chain_root`` as the audit-chain state observed *at
manifest signing time*. Decisions are produced after that. Until this module,
nothing let a relying party confirm that the chain served at ``audit_chain_uri``
at T+n is an append-only extension of the root signed at T0 rather than a
rebuilt or selectively rewritten chain that happens to re-contain the signed
prefix (issue #273). ``entry_count`` detects deletion *below* the signed count;
it says nothing about the shape of growth *above* the signed root.

The fix is the mechanism the spec already uses for the other artifact that
grows after signing: memory (Section 3.2.6.2, ``_memory_delta``). A chain
advance is accepted as *continuous* iff continuity evidence proves the signed
root is an append-only prefix of the current root, the checkpoint sequence is
monotonic, and the checkpoint is within its TTL.

Two trace types, two proof shapes, one verdict:

  * ``merkle-log``   -- RFC 9162 §2.1.2 consistency proof, O(log n), verified
    from the two roots and the two tree sizes alone. Identical primitive to
    ``_memory_delta.verify_delta``.
  * ``hash-chained`` -- the ordered entry-leaf hashes appended after the signed
    position, folded forward from the signed root, O(n). A sequential chain has
    no logarithmic proof; the honest options are a linear proof or no proof, and
    silently accepting the operator's word is not a third option.

Unlike a memory delta there is no *budget* stage. An audit chain is expected to
grow without bound, so a growth ceiling would be a false constraint; the budget
verdict has no counterpart here.

Fail-closed throughout: a missing, malformed, or non-verifying proof is
``discontinuity``, never acceptance. Absence of continuity evidence never
grants acceptance -- the same guarantee Section 3.2.6.2 states for memory.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Literal

from ._merkle import _HASH_FNS, _MAX_MERKLE_LEAVES, verify_consistency

TraceKind = Literal["hash-chained", "merkle-log"]
ContinuityReason = Literal["accepted", "discontinuity", "rollback", "expired"]

# Domain separation, same construction as _merkle: a leaf can never be read as
# an internal node, and a trace entry can never collide with a memory operation
# or a corpus document that happens to canonicalize to the same bytes.
_ENTRY_TAG = b"am-trace-entry\x00"
_LEAF_PREFIX = b"\x00"
# 0x02, deliberately not the RFC 9162 internal-node byte 0x01. Over a
# left-spine tree (n <= 3) a sequential fold with 0x01 reproduces the
# merkle root exactly, so the two trace_type roots would be
# indistinguishable. The verifier is pinned to the signed trace_type
# either way, but a root that can only be read one way is worth a byte.
_CHAIN_PREFIX = b""


def entry_leaf(canonical_entry: bytes, *, algorithm: str = "sha256") -> bytes:
    """Leaf hash of one audit entry: ``H(0x00 || tag || canonical_entry)``.

    *canonical_entry* is the RFC 8785 canonical JSON of the entry (spec
    Section 4.3). The caller canonicalizes; this function does not guess at a
    representation it cannot see.
    """
    return _HASH_FNS[algorithm](_LEAF_PREFIX + _ENTRY_TAG + canonical_entry)


def hash_chain_root(entry_leaves: list[bytes], *, algorithm: str = "sha256") -> bytes:
    """Fold entry leaves into a sequential chain root.

    ``chain_0 = leaf_0``; ``chain_i = H(0x02 || chain_{i-1} || leaf_i)``. The
    empty chain is ``H(b"")``, matching ``_merkle.EMPTY_TREE``, so an empty
    chain and a one-entry chain can never share a root.
    """
    h = _HASH_FNS[algorithm]
    if not entry_leaves:
        return h(b"")
    chain = entry_leaves[0]
    for leaf in entry_leaves[1:]:
        chain = h(_CHAIN_PREFIX + chain + leaf)
    return chain


def extend_hash_chain(
    root: bytes,
    appended_leaves: list[bytes],
    *,
    algorithm: str = "sha256",
) -> bytes:
    """Fold *appended_leaves* onto an existing non-empty chain *root*."""
    h = _HASH_FNS[algorithm]
    chain = root
    for leaf in appended_leaves:
        chain = h(_CHAIN_PREFIX + chain + leaf)
    return chain


@dataclass(frozen=True)
class AuditCheckpoint:
    """An observed audit-chain anchor.

    The checkpoint signed into the manifest is the one built from
    ``decision_trace.audit_chain_root`` / ``entry_count`` at ``bound_at``; the
    current checkpoint is what the runtime serves at ``audit_chain_uri``.
    """

    audit_chain_root: str     # HashValue ("sha256:<hex>")
    tree_size: int            # entries (hash-chained) or leaves (merkle-log)
    seq: int                  # monotonic checkpoint sequence
    observed_at: datetime
    ttl_seconds: int


@dataclass(frozen=True)
class ContinuityVerdict:
    accepted: bool
    reason: ContinuityReason


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _root_bytes(hashvalue: str) -> tuple[str, bytes]:
    """Parse a ``'algorithm:hex'`` HashValue. Raises ValueError if malformed."""
    algorithm, sep, hex_digest = hashvalue.partition(":")
    if not sep or algorithm not in _HASH_FNS or not hex_digest:
        raise ValueError(f"malformed audit_chain_root: {hashvalue!r}")
    try:
        return algorithm, bytes.fromhex(hex_digest)
    except ValueError as exc:
        raise ValueError(f"malformed audit_chain_root hex: {hashvalue!r}") from exc


def verify_continuity(
    signed: AuditCheckpoint,
    current: AuditCheckpoint,
    *,
    trace_type: TraceKind,
    consistency_proof: list[bytes] | None = None,
    appended_entry_leaves: list[bytes] | None = None,
    now: datetime | None = None,
) -> ContinuityVerdict:
    """Adjudicate an audit-chain advance signed -> current.

    Order (fail-closed): shape -> continuity proof -> seq monotonic -> TTL
    window. A failure at the continuity stage is ``discontinuity``: the running
    chain is not demonstrably the one the manifest was signed against, which
    Section 3.2.7 already requires a verifier to treat as MISMATCH.

    An identical root at an identical size is continuous by inspection and
    still walks the seq and TTL stages, so a stale checkpoint cannot be
    replayed forever just because nothing was appended.
    """
    now = _as_utc(now) if now else datetime.now(timezone.utc)
    try:
        algorithm, signed_bytes = _root_bytes(signed.audit_chain_root)
        current_algorithm, current_bytes = _root_bytes(current.audit_chain_root)
    except ValueError:
        return ContinuityVerdict(False, "discontinuity")
    if algorithm != current_algorithm:
        # An algorithm switch re-bases the chain; it is not an append.
        return ContinuityVerdict(False, "discontinuity")
    if signed.tree_size < 0 or current.tree_size < 0:
        return ContinuityVerdict(False, "discontinuity")
    if current.tree_size > _MAX_MERKLE_LEAVES:
        # DOS-002: bound verifier work on an attacker-declared size.
        return ContinuityVerdict(False, "discontinuity")
    if current.tree_size < signed.tree_size:
        # Truncation below the signed position, whatever the proof claims.
        return ContinuityVerdict(False, "discontinuity")
    if signed.tree_size == 0:
        # No approved chain state to extend. A 0 -> N jump is a first binding,
        # not a proven advance; the same rule memory applies to re-baselining.
        return ContinuityVerdict(False, "discontinuity")

    # Stage 1: continuity proof.
    if trace_type == "merkle-log":
        if not verify_consistency(
            signed_bytes,
            current_bytes,
            signed.tree_size,
            current.tree_size,
            list(consistency_proof or []),
            algorithm=algorithm,
        ):
            return ContinuityVerdict(False, "discontinuity")
    elif trace_type == "hash-chained":
        appended = list(appended_entry_leaves or [])
        if len(appended) != current.tree_size - signed.tree_size:
            return ContinuityVerdict(False, "discontinuity")
        if extend_hash_chain(signed_bytes, appended, algorithm=algorithm) != current_bytes:
            return ContinuityVerdict(False, "discontinuity")
    else:
        return ContinuityVerdict(False, "discontinuity")

    # Stage 2: monotonic checkpoint sequence.
    if current.seq < signed.seq:
        return ContinuityVerdict(False, "rollback")
    if current.seq == signed.seq and current.tree_size != signed.tree_size:
        # The chain moved without the checkpoint sequence moving: the operator
        # is serving a new chain under an old checkpoint identity.
        return ContinuityVerdict(False, "rollback")

    # Stage 3: freshness.
    if now > _as_utc(current.observed_at) + timedelta(seconds=current.ttl_seconds):
        return ContinuityVerdict(False, "expired")

    return ContinuityVerdict(True, "accepted")
