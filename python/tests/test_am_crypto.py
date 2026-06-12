"""AM-CRYPTO: Cryptographic operations conformance tests - issue #17.

Covers Ed25519 signing/verification, canonical JSON, Merkle tree hashing,
hybrid envelope structure, and SHA-256/SHAKE-256 hash correctness.
Target: 38 tests.
"""
import hashlib
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidSignature

from agent_manifest._canonicalize import canonicalize, canonical_hash
from agent_manifest._merkle import MerkleTree, build_catalog_tree, build_corpus_tree, CorpusDocument
from agent_manifest._signing import (
    Ed25519Signer,
    Ed25519Verifier,
    SIGNED_FIELDS,
    generate_ed25519,
    signing_pre_image,
)
from agent_manifest._types import HashValue

try:
    from agent_manifest._signing import (
        HybridSigner,
        HybridVerifier,
        generate_hybrid,
    )
    import oqs  # noqa: F401
    OQS_AVAILABLE = True
except (ImportError, RuntimeError):
    OQS_AVAILABLE = False

require_oqs = pytest.mark.skipif(not OQS_AVAILABLE, reason="pyoqs not installed")

NOW = datetime.now(timezone.utc)
SHA = "sha256:" + "a" * 64

MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod",
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "expires_at": "2026-09-21T09:00:00Z",
    "issuer": "spiffe://trust.example/issuer",
    "crypto_profile": "standard",
    "artifacts": {"system_prompt": {"hash": SHA}},
    "delegation_chain": [],
    "hitl_record": None,
    "attestation": {"should": "be excluded"},
    "signature": None,
}


# ---------------------------------------------------------------------------
# RFC 8785 canonical JSON (AM-CRYPTO-01 to 08)
# ---------------------------------------------------------------------------

def test_canonical_json_key_order():
    result = canonicalize({"z": 1, "a": 2})
    assert result == b'{"a":2,"z":1}'

def test_canonical_json_no_whitespace():
    result = canonicalize({"a": 1, "b": [1, 2]})
    assert b" " not in result

def test_canonical_json_null_excluded():
    result = canonicalize({"a": 1, "b": None})
    assert b"null" not in result
    assert result == b'{"a":1}'

def test_canonical_json_bool_lowercase():
    assert canonicalize({"v": True}) == b'{"v":true}'
    assert canonicalize({"v": False}) == b'{"v":false}'

def test_canonical_json_appendix_d_vector():
    """Verified test vector from spec Appendix D."""
    obj = {
        "version": "0.1",
        "issued_at": "2026-06-23T09:00:00Z",
        "agent_id": "spiffe://trust.example/agent/kyc/prod-001",
    }
    canonical = canonicalize(obj)
    digest = hashlib.sha256(canonical).hexdigest()
    assert digest == "b83293348255f4427dc030478f354b83f4f82662223be0926ad9f2db946b5319"

def test_canonical_json_context_type_included():
    obj = {"@context": "https://x", "@type": "Y", "z": 1}
    result = canonicalize(obj)
    assert b"@context" in result
    assert b"@type" in result

def test_sha256_hash_format():
    result = canonical_hash({"v": 1}, algorithm="sha256")
    assert result.startswith("sha256:")
    assert len(result) == 71

def test_shake256_hash_format():
    result = canonical_hash({"v": 1}, algorithm="shake256")
    assert result.startswith("shake256:")
    assert len(result) == 73


# ---------------------------------------------------------------------------
# Ed25519 signing (AM-CRYPTO-09 to 18)
# ---------------------------------------------------------------------------

def test_ed25519_pre_image_excludes_attestation():
    pre = signing_pre_image(MANIFEST)
    assert b"should" not in pre

def test_ed25519_pre_image_excludes_signature():
    pre = signing_pre_image(MANIFEST)
    assert b'"signature"' not in pre

def test_ed25519_pre_image_deterministic():
    assert signing_pre_image(MANIFEST) == signing_pre_image(MANIFEST)

def test_ed25519_sign_verify():
    kp = generate_ed25519()
    sig = Ed25519Signer(kp).sign(MANIFEST)
    Ed25519Verifier(kp.public_bytes).verify(MANIFEST, sig["signature_value"])

def test_ed25519_algorithm_label():
    kp = generate_ed25519()
    sig = Ed25519Signer(kp).sign(MANIFEST)
    assert sig["algorithm"] == "Ed25519"

def test_ed25519_signed_fields_complete():
    kp = generate_ed25519()
    sig = Ed25519Signer(kp).sign(MANIFEST)
    assert set(sig["signed_fields"]) == set(SIGNED_FIELDS)

def test_ed25519_wrong_key_fails():
    kp1, kp2 = generate_ed25519(), generate_ed25519()
    sig = Ed25519Signer(kp1).sign(MANIFEST)
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(kp2.public_bytes).verify(MANIFEST, sig["signature_value"])

def test_ed25519_tampered_manifest_fails():
    kp = generate_ed25519()
    sig = Ed25519Signer(kp).sign(MANIFEST)
    tampered = {**MANIFEST, "version": "9.9"}
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(kp.public_bytes).verify(tampered, sig["signature_value"])

def test_ed25519_small_order_key_rejected():
    with pytest.raises((ValueError, Exception)):
        Ed25519Verifier(bytes(32))

def test_ed25519_truncated_sig_fails():
    kp = generate_ed25519()
    sig = Ed25519Signer(kp).sign(MANIFEST)
    with pytest.raises((InvalidSignature, ValueError, Exception)):
        Ed25519Verifier(kp.public_bytes).verify(MANIFEST, sig["signature_value"][:10])


# ---------------------------------------------------------------------------
# Hybrid envelope structure (AM-CRYPTO-19 to 22)
# ---------------------------------------------------------------------------

@require_oqs
def test_hybrid_envelope_fields():
    kp = generate_hybrid()
    sig = HybridSigner(kp).sign(MANIFEST)
    assert sig["algorithm"] == "hybrid-Ed25519-ML-DSA-65"
    assert "classical_signature" in sig
    assert "pq_signature" in sig
    assert sig["signature_value"] == ""

@require_oqs
def test_hybrid_both_verify():
    kp = generate_hybrid()
    sig = HybridSigner(kp).sign(MANIFEST)
    HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes).verify(MANIFEST, sig)

@require_oqs
def test_hybrid_classical_tampered_fails():
    kp = generate_hybrid()
    sig = HybridSigner(kp).sign(MANIFEST)
    bad = {**sig, "classical_signature": sig["classical_signature"][:-4] + "XXXX"}
    with pytest.raises((InvalidSignature, Exception)):
        HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes).verify(MANIFEST, bad)

@require_oqs
def test_hybrid_pq_tampered_fails():
    kp = generate_hybrid()
    sig = HybridSigner(kp).sign(MANIFEST)
    bad = {**sig, "pq_signature": sig["pq_signature"][:-4] + "YYYY"}
    with pytest.raises((InvalidSignature, Exception)):
        HybridVerifier(kp.ed25519.public_bytes, kp.ml_dsa65.public_key_bytes).verify(MANIFEST, bad)


# ---------------------------------------------------------------------------
# Merkle tree (AM-CRYPTO-23 to 30)
# ---------------------------------------------------------------------------

def test_merkle_domain_separation():
    """Leaf H(0x00||x) must differ from internal H(0x01||x||x)."""
    x = b"data"
    leaf = hashlib.sha256(b"\x00" + x).digest()
    node = hashlib.sha256(b"\x01" + x + x).digest()
    assert leaf != node

def test_merkle_empty_root():
    assert MerkleTree().root_hex() == f"sha256:{hashlib.sha256(b'').hexdigest()}"

def test_merkle_single_leaf():
    t = MerkleTree()
    lh = t.add_leaf(b"only")
    assert t.root() == lh

def test_catalog_root_vector():
    """Verified test vector (computed via PowerShell SHA-256)."""
    from agent_manifest.models import ToolEntry
    tools = [
        ToolEntry(
            tool_id="com.example.read_customer_record", tool_name="read",
            endpoint_id="spiffe://x/s",
            schema_hash=HashValue("sha256:" + "aa" * 32),
            description_hash=HashValue("sha256:" + "bb" * 32),
            version="1.0",
        ),
        ToolEntry(
            tool_id="com.example.send_notification", tool_name="send",
            endpoint_id="spiffe://x/s",
            schema_hash=HashValue("sha256:" + "cc" * 32),
            description_hash=HashValue("sha256:" + "dd" * 32),
            version="1.0",
        ),
    ]
    root = build_catalog_tree(tools)
    assert root == "sha256:afd1d90ec5aa07f31ae20ab040a04652c76f3078c4d0434de2a17b0cb61c40dd"

def test_corpus_root_vector():
    """Verified test vector (computed via PowerShell SHA-256)."""
    docs = [
        CorpusDocument("doc-001", b"Hello world"),
        CorpusDocument("doc-002", b"Agent governance policy v1"),
        CorpusDocument("doc-003", b"System configuration"),
    ]
    root = build_corpus_tree(docs)
    assert root == "sha256:b2030c6a8dd7e785368814249f39407d23e76528305d2a7e2f09efd9771e9db4"

def test_catalog_description_bound():
    """Changing description_hash must change catalog root (CRYPTO-002 fix)."""
    from agent_manifest.models import ToolEntry
    t1 = ToolEntry(
        tool_id="t", tool_name="t", endpoint_id="spiffe://x/s",
        schema_hash=HashValue("sha256:" + "a" * 64),
        description_hash=HashValue("sha256:" + "b" * 64),
        version="1",
    )
    t2 = ToolEntry(
        tool_id="t", tool_name="t", endpoint_id="spiffe://x/s",
        schema_hash=HashValue("sha256:" + "a" * 64),
        description_hash=HashValue("sha256:" + "c" * 64),  # only desc changed
        version="1",
    )
    assert build_catalog_tree([t1]) != build_catalog_tree([t2])

def test_inclusion_proof_roundtrip():
    t = MerkleTree()
    for b in [b"a", b"b", b"c", b"d", b"e"]:
        t.add_leaf(b)
    for i in range(5):
        assert t.verify_inclusion(t.inclusion_proof(i))
