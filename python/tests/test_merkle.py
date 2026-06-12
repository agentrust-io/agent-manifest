"""Merkle tree tests - issue #4.

Test vectors computed and verified via PowerShell SHA-256 implementation.
"""
import pytest

from agent_manifest._merkle import (
    CorpusDocument,
    InclusionProof,
    MerkleTree,
    build_catalog_tree,
    build_corpus_tree,
)
from agent_manifest._types import HashValue
from agent_manifest.models import ToolEntry

# ---------------------------------------------------------------------------
# Known test vectors (computed and verified externally)
# ---------------------------------------------------------------------------

# Two-tool catalog (sorted by tool_id: read < send)
# leaf1 = H(0x00 || "com.example.read_customer_record\x00" || aa*32 || bb*32)
# leaf2 = H(0x00 || "com.example.send_notification\x00"   || cc*32 || dd*32)
# root  = H(0x01 || leaf1 || leaf2)
CATALOG_LEAF1 = "f7af288cd917b5258bfd6322d215fb6648d0bff244c6c8893287339cfb7039e0"
CATALOG_LEAF2 = "b6b7227c3a7f64b152baf401952d55e6e844a4b9bccc963098acae963c62607a"
CATALOG_ROOT  = "afd1d90ec5aa07f31ae20ab040a04652c76f3078c4d0434de2a17b0cb61c40dd"

# Three-document corpus (leaves sorted by hash before construction)
# d1 = H(0x00 || "doc-001\x00Hello world")
# d2 = H(0x00 || "doc-002\x00Agent governance policy v1")
# d3 = H(0x00 || "doc-003\x00System configuration")
# sorted order: d1_hash < d2_hash < d3_hash
# left = H(0x01 || sorted[0] || sorted[1])
# root = H(0x01 || left || sorted[2])
CORPUS_ROOT = "b2030c6a8dd7e785368814249f39407d23e76528305d2a7e2f09efd9771e9db4"

# Empty tree
EMPTY_ROOT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# MerkleTree - structural tests
# ---------------------------------------------------------------------------


def test_empty_tree_root():
    tree = MerkleTree()
    assert tree.root_hex() == f"sha256:{EMPTY_ROOT_SHA256}"


def test_single_leaf_root_is_leaf_hash():
    tree = MerkleTree()
    leaf_hash = tree.add_leaf(b"single")
    assert tree.root() == leaf_hash


def test_two_leaf_root():
    import hashlib
    tree = MerkleTree()
    l1 = tree.add_leaf(b"left")
    l2 = tree.add_leaf(b"right")
    expected = hashlib.sha256(b"\x01" + l1 + l2).digest()
    assert tree.root() == expected


def test_domain_separation_leaf_differs_from_internal():
    """Leaf hash must differ from the same data hashed as internal node."""
    import hashlib
    data = b"test"
    leaf = hashlib.sha256(b"\x00" + data).digest()
    internal_of_same = hashlib.sha256(b"\x01" + data + data).digest()
    assert leaf != internal_of_same


def test_root_hex_prefix():
    tree = MerkleTree(algorithm="sha256")
    tree.add_leaf(b"x")
    assert tree.root_hex().startswith("sha256:")
    assert len(tree.root_hex()) == 7 + 64  # "sha256:" + 64 hex chars


def test_shake256_prefix():
    tree = MerkleTree(algorithm="shake256")
    tree.add_leaf(b"x")
    assert tree.root_hex().startswith("shake256:")
    assert len(tree.root_hex()) == 9 + 64  # "shake256:" + 64 hex chars


def test_unsupported_algorithm_raises():
    with pytest.raises(ValueError, match="Unsupported"):
        MerkleTree(algorithm="md5")


def test_deterministic_root():
    """Same leaves in same order must always produce the same root."""
    def make():
        t = MerkleTree()
        for b in [b"a", b"b", b"c"]:
            t.add_leaf(b)
        return t.root_hex()
    assert make() == make()


def test_different_leaf_order_same_content():
    """Order matters - root must differ if leaf order differs."""
    t1 = MerkleTree()
    t1.add_leaf(b"a")
    t1.add_leaf(b"b")

    t2 = MerkleTree()
    t2.add_leaf(b"b")
    t2.add_leaf(b"a")

    assert t1.root_hex() != t2.root_hex()


# ---------------------------------------------------------------------------
# Catalog tree test vectors
# ---------------------------------------------------------------------------


def _make_tool(tool_id: str, schema_hex: str, desc_hex: str) -> ToolEntry:
    return ToolEntry(
        tool_id=tool_id,
        tool_name=tool_id.split(".")[-1],
        endpoint_id="spiffe://trust.example/mcp/server",
        schema_hash=HashValue(f"sha256:{schema_hex}"),
        description_hash=HashValue(f"sha256:{desc_hex}"),
        version="1.0.0",
    )


def test_catalog_root_two_tools():
    tools = [
        _make_tool("com.example.read_customer_record", "aa" * 32, "bb" * 32),
        _make_tool("com.example.send_notification",   "cc" * 32, "dd" * 32),
    ]
    result = build_catalog_tree(tools)
    assert result == f"sha256:{CATALOG_ROOT}"


def test_catalog_sorted_by_tool_id():
    """Order of input list must not affect root - tools are sorted by tool_id."""
    t1 = _make_tool("com.example.read_customer_record", "aa" * 32, "bb" * 32)
    t2 = _make_tool("com.example.send_notification",   "cc" * 32, "dd" * 32)
    assert build_catalog_tree([t1, t2]) == build_catalog_tree([t2, t1])


def test_catalog_description_change_changes_root():
    """Changing description_hash must invalidate the catalog root (CRYPTO-002)."""
    original = _make_tool("com.example.tool", "aa" * 32, "bb" * 32)
    mutated  = _make_tool("com.example.tool", "aa" * 32, "cc" * 32)
    assert build_catalog_tree([original]) != build_catalog_tree([mutated])


def test_catalog_schema_change_changes_root():
    original = _make_tool("com.example.tool", "aa" * 32, "bb" * 32)
    mutated  = _make_tool("com.example.tool", "cc" * 32, "bb" * 32)
    assert build_catalog_tree([original]) != build_catalog_tree([mutated])


def test_catalog_empty():
    assert build_catalog_tree([]).startswith("sha256:")


# ---------------------------------------------------------------------------
# Corpus tree test vectors
# ---------------------------------------------------------------------------


def test_corpus_root_three_documents():
    docs = [
        CorpusDocument("doc-001", b"Hello world"),
        CorpusDocument("doc-002", b"Agent governance policy v1"),
        CorpusDocument("doc-003", b"System configuration"),
    ]
    result = build_corpus_tree(docs)
    assert result == f"sha256:{CORPUS_ROOT}"


def test_corpus_sorted_by_leaf_hash():
    """Document input order must not affect the root."""
    docs = [
        CorpusDocument("doc-003", b"System configuration"),
        CorpusDocument("doc-001", b"Hello world"),
        CorpusDocument("doc-002", b"Agent governance policy v1"),
    ]
    docs_sorted = sorted(docs, key=lambda d: d.document_id)
    assert build_corpus_tree(docs) == build_corpus_tree(docs_sorted)


def test_corpus_content_change_changes_root():
    docs_orig    = [CorpusDocument("doc-001", b"Original content")]
    docs_poisoned = [CorpusDocument("doc-001", b"Poisoned content")]
    assert build_corpus_tree(docs_orig) != build_corpus_tree(docs_poisoned)


def test_corpus_added_document_changes_root():
    docs1 = [CorpusDocument("doc-001", b"A")]
    docs2 = [CorpusDocument("doc-001", b"A"), CorpusDocument("doc-002", b"B")]
    assert build_corpus_tree(docs1) != build_corpus_tree(docs2)


def test_corpus_empty():
    assert build_corpus_tree([]).startswith("sha256:")


# ---------------------------------------------------------------------------
# Inclusion proof
# ---------------------------------------------------------------------------


def test_inclusion_proof_single_leaf():
    tree = MerkleTree()
    tree.add_leaf(b"only")
    proof = tree.inclusion_proof(0)
    assert proof.audit_path == []
    assert tree.verify_inclusion(proof)


def test_inclusion_proof_two_leaves():
    tree = MerkleTree()
    tree.add_leaf(b"leaf0")
    tree.add_leaf(b"leaf1")
    for i in range(2):
        proof = tree.inclusion_proof(i)
        assert tree.verify_inclusion(proof)


def test_inclusion_proof_five_leaves():
    tree = MerkleTree()
    for i in range(5):
        tree.add_leaf(f"leaf-{i}".encode())
    for i in range(5):
        assert tree.verify_inclusion(tree.inclusion_proof(i))


def test_tampered_proof_fails():
    tree = MerkleTree()
    tree.add_leaf(b"a")
    tree.add_leaf(b"b")
    tree.add_leaf(b"c")
    proof = tree.inclusion_proof(0)
    # Tamper with a sibling hash in the audit path
    bad_path = [bytes(b ^ 0xFF for b in proof.audit_path[0])] + proof.audit_path[1:]
    bad_proof = InclusionProof(
        leaf_index=proof.leaf_index,
        tree_size=proof.tree_size,
        leaf_hash=proof.leaf_hash,
        audit_path=bad_path,
    )
    assert not tree.verify_inclusion(bad_proof)


def test_inclusion_proof_out_of_range():
    tree = MerkleTree()
    tree.add_leaf(b"x")
    with pytest.raises(IndexError):
        tree.inclusion_proof(1)
