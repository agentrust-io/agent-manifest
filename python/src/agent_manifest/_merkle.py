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
from typing import Callable, NamedTuple

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
        """Verify *proof* against the current tree root."""
        expected_root = self.root()
        computed = _compute_root_from_proof(
            proof.leaf_hash,
            proof.leaf_index,
            proof.tree_size,
            proof.audit_path,
            self._h,
        )
        return computed == expected_root

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


def _compute_root_from_proof(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    audit_path: list[bytes],
    h_fn: Callable[[bytes], bytes],
) -> bytes:
    """Reconstruct root from an inclusion proof (RFC 9162 §2.2).

    Audit path elements are ordered bottom-to-top (leaf sibling first).
    Direction at each level is determined by parity: odd index or rightmost
    node means sibling is on the left.
    """
    node = leaf_hash
    fn = tree_size
    fr = index
    for step in audit_path:
        if fr == fn - 1 or fr % 2 == 1:
            node = h_fn(b"\x01" + step + node)
            fr = (fr - 1) // 2
        else:
            node = h_fn(b"\x01" + node + step)
            fr = fr // 2
        fn = (fn + 1) // 2
    return node


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

    Tools are sorted by tool_id (lexicographic) before tree construction.

    Returns:
        Root in HashValue format: ``"sha256:<64-hex>"``

    Raises:
        ValueError: If the number of tools exceeds MAX_LEAVES.
    """
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
