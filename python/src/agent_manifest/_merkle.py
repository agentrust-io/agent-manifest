"""RFC 9162 Merkle tree with domain separation.

Reference: https://www.rfc-editor.org/rfc/rfc9162

Domain separation prevents second-preimage attacks:
  Leaf node:     H(0x00 || leaf_data)
  Internal node: H(0x01 || left_child || right_child)

Two concrete trees are defined by the spec:

  Corpus tree (Section 3.2.5):
    leaf_data = document_id_utf8 + b'\\x00' + content_bytes
    Leaves sorted lexicographically by leaf hash before construction.

  Catalog tree (Section 3.2.3):
    leaf_data = tool_id_utf8 + b'\\x00' + schema_hash_bytes + description_hash_bytes
    Both schema and description are bound (closes CRYPTO-002 / SPEC-03).
    Leaves sorted lexicographically by tool_id before construction.

Hash algorithms:
  Standard profile:      SHA-256  -> "sha256:<64-hex>"
  Post-quantum profile:  SHAKE-256 at 256-bit output -> "shake256:<64-hex>"
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Iterable, NamedTuple

from ._types import HashValue
from .models import ToolEntry


# ---------------------------------------------------------------------------
# Hash primitives
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _shake256(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(32)  # 256-bit = 32 bytes, fixed


_HASH_FNS = {
    "sha256": _sha256,
    "shake256": _shake256,
}

EMPTY_TREE: dict[str, bytes] = {
    "sha256": _sha256(b""),
    "shake256": _shake256(b""),
}


# ---------------------------------------------------------------------------
# Inclusion proof
# ---------------------------------------------------------------------------


class InclusionProof(NamedTuple):
    """Merkle inclusion proof for a single leaf.

    To verify: iteratively combine audit_path hashes with the leaf hash
    using the direction flags, and compare the resulting root.
    """

    leaf_index: int
    tree_size: int
    leaf_hash: bytes
    audit_path: list[bytes]  # sibling hashes from leaf to root


# ---------------------------------------------------------------------------
# Core Merkle tree
# ---------------------------------------------------------------------------


class MerkleTree:
    """Left-balanced RFC 9162 Merkle tree with domain-separated hashing.

    Usage::

        tree = MerkleTree(algorithm="sha256")
        tree.add_leaf(b"leaf_preimage_1")
        tree.add_leaf(b"leaf_preimage_2")
        root_hex = tree.root_hex()   # "sha256:<64-hex>"
        proof = tree.inclusion_proof(0)
    """

    def __init__(self, algorithm: str = "sha256") -> None:
        if algorithm not in _HASH_FNS:
            raise ValueError(
                f"Unsupported algorithm {algorithm!r}. Use 'sha256' or 'shake256'."
            )
        self._h = _HASH_FNS[algorithm]
        self._algorithm = algorithm
        self._leaf_hashes: list[bytes] = []

    def add_leaf(self, leaf_preimage: bytes) -> bytes:
        """Hash *leaf_preimage* with domain byte 0x00 and append to the tree.

        Returns the leaf hash (useful for sorting before tree construction).
        """
        leaf_hash = self._h(b"\x00" + leaf_preimage)
        self._leaf_hashes.append(leaf_hash)
        return leaf_hash

    def add_prehashed_leaf(self, leaf_hash: bytes) -> None:
        """Append an already-hashed leaf (used when leaves are pre-sorted)."""
        self._leaf_hashes.append(leaf_hash)

    def root(self) -> bytes:
        """Return the Merkle root as raw bytes."""
        if not self._leaf_hashes:
            return EMPTY_TREE[self._algorithm]
        return self._mth(self._leaf_hashes)

    def root_hex(self) -> str:
        """Return the root in HashValue format: ``"sha256:<64-hex>"``."""
        return f"{self._algorithm}:{self.root().hex()}"

    def inclusion_proof(self, leaf_index: int) -> InclusionProof:
        """Generate an inclusion proof for the leaf at *leaf_index*.

        Raises:
            IndexError: If *leaf_index* is out of range.
        """
        n = len(self._leaf_hashes)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError(
                f"leaf_index {leaf_index} out of range for tree with {n} leaves"
            )
        audit_path = self._audit_path(self._leaf_hashes, leaf_index)
        return InclusionProof(
            leaf_index=leaf_index,
            tree_size=n,
            leaf_hash=self._leaf_hashes[leaf_index],
            audit_path=audit_path,
        )

    def verify_inclusion(self, proof: InclusionProof) -> bool:
        """Verify *proof* against the current tree root.

        The ``tree_size`` check is what binds the proof to *this* tree:
        a correct-length ``audit_path`` for the right ``leaf_index`` can
        still exist for a different tree size, since structural depth
        alone doesn't imply the same tree. ``leaf_index`` range and
        ``audit_path`` length are checked too, as defense in depth.
        """
        n = len(self._leaf_hashes)
        if proof.tree_size != n:
            return False
        if not 0 <= proof.leaf_index < n:
            return False
        if len(proof.audit_path) != _expected_audit_path_length(n, proof.leaf_index):
            return False
        expected_root = self.root()
        computed = _compute_root_from_proof(
            proof.leaf_hash,
            proof.leaf_index,
            proof.tree_size,
            proof.audit_path,
            self._h,
        )
        return computed == expected_root

    def consistency_proof(self, first_size: int) -> list[bytes]:
        """RFC 9162 §2.1.2 consistency proof from *first_size* to current size.

        Proves the first ``first_size`` leaves of this tree are an append-only
        positional prefix of the full tree. Used to bind a memory/corpus
        checkpoint advance (see ``_memory_delta``).

        Raises:
            ValueError: If *first_size* is not in ``1..len(leaves)``.
        """
        n = len(self._leaf_hashes)
        if not 0 < first_size <= n:
            raise ValueError(
                f"first_size {first_size} out of range 1..{n}"
            )
        if first_size == n:
            return []
        return self._subproof(first_size, self._leaf_hashes, True)

    def _subproof(self, m: int, hashes: list[bytes], b: bool) -> list[bytes]:
        """RFC 9162 §2.1.2 SUBPROOF recursion over pre-hashed leaves."""
        n = len(hashes)
        if m == n:
            return [] if b else [self._mth(hashes)]
        k = _split_point(n)
        if m <= k:
            return self._subproof(m, hashes[:k], b) + [self._mth(hashes[k:])]
        return self._subproof(m - k, hashes[k:], False) + [self._mth(hashes[:k])]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _mth(self, hashes: list[bytes]) -> bytes:
        """Merkle Tree Hash (RFC 9162 §2.1) over pre-hashed leaves."""
        n = len(hashes)
        if n == 1:
            return hashes[0]
        k = _split_point(n)
        left = self._mth(hashes[:k])
        right = self._mth(hashes[k:])
        return self._h(b"\x01" + left + right)

    def _audit_path(
        self, hashes: list[bytes], index: int
    ) -> list[bytes]:
        n = len(hashes)
        if n == 1:
            return []
        k = _split_point(n)
        if index < k:
            path = self._audit_path(hashes[:k], index)
            path.append(self._mth(hashes[k:]))
        else:
            path = self._audit_path(hashes[k:], index - k)
            path.append(self._mth(hashes[:k]))
        return path


def _split_point(n: int) -> int:
    """Largest power of 2 strictly less than n (RFC 9162 §2.1)."""
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def _expected_audit_path_length(n: int, index: int) -> int:
    """Depth of *index* in an RFC 9162 tree with *n* leaves.

    Same recursion as ``MerkleTree._audit_path``, but on plain integers
    (no hashes needed), so ``verify_inclusion`` can check an external
    proof's ``audit_path`` length before trusting its contents.
    """
    if n == 1:
        return 0
    k = _split_point(n)
    if index < k:
        return 1 + _expected_audit_path_length(k, index)
    return 1 + _expected_audit_path_length(n - k, index - k)


def _compute_root_from_proof(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    audit_path: list[bytes],
    h_fn: Callable[[bytes], bytes],
) -> bytes | None:
    """Reconstruct the root from an inclusion proof (RFC 9162 §2.1.3.2).

    Returns None for any proof that's structurally invalid for
    ``(index, tree_size)`` — out-of-range index, or an audit_path
    that's too short or too long — rather than a wrong hash. That makes
    this function safe to call directly, not just through
    ``verify_inclusion`` (which validates the same things up front).

    Note: an even, non-last node index means its level has no sibling
    in the proof (it's the left child of a complete subtree), so the
    inner ``while`` loop skips that level without consuming a proof
    element. Skipping this loop breaks verification for non-power-of-2
    tree sizes, e.g. tree_size=7, leaf_index=6.
     """
    if tree_size <= 0 or index < 0 or index >= tree_size:
        return None
    node = leaf_hash
    fn = index
    sn = tree_size - 1
    for step in audit_path:
        if sn == 0:
            return None  # audit_path longer than this proof needs
        if fn % 2 == 1 or fn == sn:
            node = h_fn(b"\x01" + step + node)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            node = h_fn(b"\x01" + node + step)
        fn //= 2
        sn //= 2
    if sn != 0:
        return None
    return node


def verify_consistency(
    first_root: bytes,
    second_root: bytes,
    first_size: int,
    second_size: int,
    proof: list[bytes],
    *,
    algorithm: str = "sha256",
) -> bool:
    """Verify an RFC 9162 §2.1.4.2 consistency proof.

    Returns True iff *proof* proves the size-*first_size* tree (root
    *first_root*) is an append-only positional prefix of the size-*second_size*
    tree (root *second_root*). Uses only the two roots, sizes, and proof — never
    the leaf data — so a verifier without the store can check a checkpoint
    advance. A non-prefix, tampered, or truncated proof returns False (the
    fail-closed path for memory-delta verification).

    Shape is checked first: known algorithm, non-negative int sizes, roots
    and every proof element the right length in bytes, and the proof no
    longer than a real RFC 9162 proof for *second_size* could be (the same
    bound ``verify_consistency_append`` already used). This means a direct
    caller can't crash it with bad input, can't make it scan an oversized
    proof list before rejecting it, and two equal-but-malformed roots can't
    coincidentally "match". Any shape violation returns False, same as a
    failed proof.

    Not checked here on purpose: the ``_MAX_MERKLE_LEAVES`` cap
    ``verify_consistency_append`` applies to *second_size*. That's an
    operational limit this codebase's callers choose (and
    ``verify_continuity`` already applies it before calling in) — not a
    property of the RFC 9162 proof itself.
    """
    if algorithm not in _HASH_FNS:
        return False
    h = _HASH_FNS[algorithm]
    digest_size = len(h(b""))
    if (type(first_size) is not int or type(second_size) is not int
            or first_size < 0 or second_size < 0):
        return False
    if (not isinstance(first_root, bytes) or len(first_root) != digest_size
            or not isinstance(second_root, bytes) or len(second_root) != digest_size
            or not isinstance(proof, list)
            or len(proof) > second_size.bit_length() + 1):
        return False
    if any(not isinstance(node, bytes) or len(node) != digest_size for node in proof):
        return False
    if first_size > second_size:
        return False
    if first_size == second_size:
        return not proof and first_root == second_root
    if first_size == 0:
        return not proof
    terms = list(proof)
    if first_size & (first_size - 1) == 0:  # first_size is a power of two
        terms = [first_root] + terms
    if not terms:
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr, sr, sn = _fold_consistency_terms(terms, fn, sn, h)
    return fr is not None and fr == first_root and sr == second_root and sn == 0


def _consistency_ranges(first_size: int, second_size: int) -> list[tuple[int, int]]:
    """Leaf intervals for RFC 9162 SUBPROOF nodes, in proof order.

    Descend iteratively and reverse the pending sibling intervals on return.
    Inputs are bounded and validated by verify_consistency_append.
    """
    start, m, n, complete = 0, first_size, second_size, True
    siblings: list[tuple[int, int]] = []
    while m != n:
        split = 1 << ((n - 1).bit_length() - 1)
        if m <= split:
            siblings.append((start + split, start + n))
            n = split
        else:
            siblings.append((start, start + split))
            start += split
            m -= split
            n -= split
            complete = False
    prefix = [] if complete else [(start, start + n)]
    return prefix + list(reversed(siblings))


def verify_consistency_append(
    first_root: bytes,
    second_root: bytes,
    first_size: int,
    second_size: int,
    proof: list[bytes],
    appended_preimages: Iterable[bytes],
    *,
    algorithm: str = "sha256",
) -> bool:
    """Verify both consistency and the exact appended leaf sequence.

    Proof nodes cover intervals wholly before or after first_size. Authenticate
    the proof first, then recompute every appended interval from the supplied
    preimages. No old log is needed. The iterable is consumed only after proof
    validation, and at most the declared delta plus one elements are read.
    Empty prior trees require re-baselining rather than delta acceptance.
    """
    h = _HASH_FNS[algorithm]
    digest_size = len(h(b""))
    if (type(first_size) is not int or type(second_size) is not int
            or not 0 < first_size <= second_size <= _MAX_MERKLE_LEAVES):
        return False
    if (not isinstance(first_root, bytes) or len(first_root) != digest_size
            or not isinstance(second_root, bytes) or len(second_root) != digest_size
            or not isinstance(proof, list)
            or len(proof) > second_size.bit_length() + 1
            or any(not isinstance(node, bytes) or len(node) != digest_size for node in proof)):
        return False
    if not verify_consistency(first_root, second_root, first_size, second_size,
                              proof, algorithm=algorithm):
        return False
    ranges = _consistency_ranges(first_size, second_size)
    if len(ranges) != len(proof):
        return False
    leaves: list[bytes] = []
    count = second_size - first_size
    for preimage in appended_preimages:
        if len(leaves) == count or not isinstance(preimage, bytes):
            return False
        leaves.append(h(b"\x00" + preimage))
    if len(leaves) != count:
        return False
    tree = MerkleTree(algorithm=algorithm)
    for (start, end), node in zip(ranges, proof):
        if start >= first_size:
            if tree._mth(leaves[start - first_size:end - first_size]) != node:
                return False
    return True


def _fold_consistency_terms(
    terms: list[bytes], fn: int, sn: int, h: Callable[[bytes], bytes]
) -> tuple[bytes | None, bytes | None, int]:
    """RFC 9162 §2.1.4.2 inner loop: fold proof nodes into (old_root, new_root).

    Returns ``(None, None, -1)`` on a malformed proof (over-consumed path).
    """
    fr = sr = terms[0]
    for c in terms[1:]:
        if sn == 0:
            return None, None, -1
        if (fn & 1) or fn == sn:
            fr = h(b"\x01" + c + fr)
            sr = h(b"\x01" + c + sr)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = h(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr, sr, sn


# ---------------------------------------------------------------------------
# Corpus tree (Section 3.2.5)
# ---------------------------------------------------------------------------


@dataclass
class CorpusDocument:
    """A single document in the RAG corpus."""

    document_id: str
    content_bytes: bytes


_MAX_MERKLE_LEAVES = 1_000_000  # DOS-002: cap to prevent CPU/memory exhaustion


def build_corpus_tree(
    documents: list[CorpusDocument],
    algorithm: str = "sha256",
) -> str:
    """Build the RAG corpus Merkle tree and return the root HashValue.

    Leaf construction per spec Section 3.2.5:
      leaf_data = document_id_utf8 + 0x00 + content_bytes

    Documents are sorted lexicographically by their leaf hash before
    tree construction to ensure a deterministic root for the same content
    regardless of input order.

    Returns:
        Root in HashValue format: ``"sha256:<64-hex>"``

    Raises:
        ValueError: If the number of documents exceeds MAX_LEAVES.
    """
    if len(documents) > _MAX_MERKLE_LEAVES:
        raise ValueError(
            f"build_corpus_tree: {len(documents)} documents exceeds the "
            f"{_MAX_MERKLE_LEAVES}-leaf maximum. Split into multiple trees."
        )
    if not documents:
        return f"{algorithm}:{EMPTY_TREE[algorithm].hex()}"

    tree = MerkleTree(algorithm=algorithm)

    # Compute leaf preimages and hashes before sorting
    leaf_hashes: list[bytes] = []
    for doc in documents:
        leaf_data = doc.document_id.encode("utf-8") + b"\x00" + doc.content_bytes
        leaf_hash = tree._h(b"\x00" + leaf_data)
        leaf_hashes.append(leaf_hash)

    # Sort by leaf hash (lexicographic byte comparison)
    leaf_hashes.sort()

    # Build tree from sorted, pre-hashed leaves
    result = MerkleTree(algorithm=algorithm)
    for lh in leaf_hashes:
        result.add_prehashed_leaf(lh)
    return result.root_hex()


# ---------------------------------------------------------------------------
# Catalog tree (Section 3.2.3)
# ---------------------------------------------------------------------------


def build_catalog_tree(
    tools: list[ToolEntry],
    algorithm: str = "sha256",
) -> str:
    """Build the tool manifest Merkle tree and return the catalog_hash.

    Leaf construction per spec Section 3.2.3:
      leaf_data = tool_id_utf8 + 0x00 + schema_hash_bytes + description_hash_bytes

    Both schema_hash and description_hash are bound so that silent MCP tool
    description mutation (rug-pull) changes the catalog root.

    ``schema_hash_bytes`` / ``description_hash_bytes`` are the raw digest
    bytes of each ``HashValue`` - the algorithm prefix (``"sha256:"`` or
    ``"shake256:"``) is stripped before hashing, per the catalog-tree
    construction in spec Section 3.2.3. A manifest uses one algorithm
    throughout (spec Section 3.1; profile tables in 4.1/4.2), so each
    tool's ``schema_hash``/``description_hash`` algorithm MUST match
    *algorithm* before its raw bytes are trusted as leaf input. Otherwise
    two hashes with the same digest but different algorithm labels
    (``"sha256:aa..."`` vs. ``"shake256:aa..."``) would hash to the same
    leaf, silently dropping the algorithm each was declared under.

    Tools are sorted by tool_id (lexicographic) before tree construction.

    Returns:
        Root in HashValue format: ``"sha256:<64-hex>"`` (or ``"shake256:..."``
        when *algorithm* is ``"shake256"``).

    Raises:
        ValueError: If *algorithm* is unsupported, if the number of tools
            exceeds MAX_LEAVES, or if any tool's ``schema_hash`` or
            ``description_hash`` uses a different algorithm than *algorithm*.
    """
    if algorithm not in _HASH_FNS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. Use 'sha256' or 'shake256'."
        )

    if len(tools) > _MAX_MERKLE_LEAVES:
        raise ValueError(
            f"build_catalog_tree: {len(tools)} tools exceeds the "
            f"{_MAX_MERKLE_LEAVES}-leaf maximum."
        )
    if not tools:
        return f"{algorithm}:{EMPTY_TREE[algorithm].hex()}"

    sorted_tools = sorted(tools, key=lambda t: t.tool_id)

    tree = MerkleTree(algorithm=algorithm)
    for tool in sorted_tools:
        _require_matching_algorithm(tool, "schema_hash", tool.schema_hash, algorithm)
        _require_matching_algorithm(
            tool, "description_hash", tool.description_hash, algorithm
        )
        schema_bytes = bytes.fromhex(tool.schema_hash.hex_digest)
        desc_bytes = bytes.fromhex(tool.description_hash.hex_digest)
        leaf_data = (
            tool.tool_id.encode("utf-8")
            + b"\x00"
            + schema_bytes
            + desc_bytes
        )
        tree.add_leaf(leaf_data)

    return tree.root_hex()


def _require_matching_algorithm(
    tool: ToolEntry, field_name: str, hash_value: HashValue, algorithm: str
) -> None:
    """Reject a tool hash whose algorithm doesn't match the tree's.

    Without this, a tool's raw digest bytes get used as leaf input no
    matter what algorithm they claim to be - see build_catalog_tree's
    docstring for why that's unsafe.
    """
    tool_algorithm = hash_value.algorithm
    if tool_algorithm != algorithm:
        raise ValueError(
            f"build_catalog_tree: tool {tool.tool_id!r} has {field_name} "
            f"algorithm {tool_algorithm!r}, but the catalog tree algorithm "
            f"is {algorithm!r}. A manifest uses one hash algorithm "
            f"throughout (spec Section 3.1); mixing algorithms in one "
            f"catalog is not permitted."
        )
