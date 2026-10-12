"""AM-CRYPTO / spec 3.6: authenticated Rekor v1 inclusion controls (#477).

All logs and keys are synthetic; no network or production credentials are used.
Fixture SETs use the independent jcs package. Merkle fixtures are built by the
RFC 6962 recursive tree definition, independently of the verifier's path fold.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import jcs
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from agent_manifest._rekor_verify import PUBLIC_REKOR_KEY_DER, verify_rekor_evidence
from agent_manifest._transparency import (
    REKOR_PUBLIC_URL, TransparencyLogEntry, verify_transparency_log_entry,
)

MANIFEST = {"manifest_id": "synthetic-transparency-control"}
KEY = ec.derive_private_key(123456789, ec.SECP256R1())


def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _tree(leaves):
    if len(leaves) == 1:
        return _leaf(leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return _node(_tree(leaves[:split]), _tree(leaves[split:]))


def _path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return _path(leaves[:split], index) + [_tree(leaves[split:]).hex()]
    return _path(leaves[split:], index - split) + [_tree(leaves[:split]).hex()]


def _sign(key, data):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    return key.sign(data)


def _fixture(size=3, index=1, key=KEY, virtual_index=None):
    public = key.public_key()
    der = public.public_bytes(serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(der).digest()
    encoded = jcs.canonicalize({
        "apiVersion": "0.0.1", "kind": "hashedrekord",
        "spec": {"data": {"hash": {"algorithm": "sha256", "value":
            hashlib.sha256(jcs.canonicalize(MANIFEST)).hexdigest()}}},
    })
    leaves = [f"other-{i}".encode() for i in range(size)]
    leaves[index] = encoded
    root = _tree(leaves)
    note = f"synthetic.rekor.test - 1\n{size}\n{base64.b64encode(root).decode()}\n"
    signature = base64.b64encode(key_id[:4] + _sign(key, note.encode())).decode()
    checkpoint = note + f"\n\u2014 synthetic.rekor.test {signature}\n"
    record = {
        "body": base64.b64encode(encoded).decode(), "logID": key_id.hex(),
        "logIndex": index if virtual_index is None else virtual_index,
        "integratedTime": 1750000000,
    }
    set_signature = base64.b64encode(_sign(key, jcs.canonicalize(record))).decode()
    record["verification"] = {
        "signedEntryTimestamp": set_signature,
        "inclusionProof": {"treeSize": size, "logIndex": index,
                           "rootHash": root.hex(), "hashes": _path(leaves, index),
                           "checkpoint": checkpoint},
    }
    entry = TransparencyLogEntry(
        log_id=key_id.hex(), entry_id=_leaf(encoded).hex(), inclusion_proof="",
        integrated_time=record["integratedTime"], log_index=record["logIndex"],
    )
    pem = public.public_bytes(serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo)
    return {entry.entry_id: record}, entry, pem


def _verify(response, entry, pem, **kwargs):
    mock = MagicMock(status_code=200)
    mock.json.return_value = response
    with patch("httpx.get", return_value=mock):
        return verify_transparency_log_entry(
            MANIFEST, entry, rekor_public_key_pem=pem, **kwargs,
        )


@pytest.mark.parametrize("size,index", [(n, i) for n in (1, 2, 3, 5, 8, 9, 17)
                                         for i in range(n)])
def test_signed_inclusion_for_each_tree_position(size, index):
    response, entry, pem = _fixture(size, index)
    assert _verify(response, entry, pem)


def test_private_ed25519_log_and_virtual_index():
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    response, entry, pem = _fixture(key=key, virtual_index=1001)
    assert _verify(response, entry, pem, rekor_url="https://synthetic.rekor.test")


def test_sharded_entry_id_and_plain_uuid_lookup():
    response, entry, pem = _fixture(virtual_index=1001)
    record = response.pop(entry.entry_id)
    sharded = "0000000000000001" + entry.entry_id
    response[sharded] = record
    assert _verify(response, entry, pem)  # UUID lookup can return a full EntryID
    entry.entry_id = sharded
    assert _verify(response, entry, pem)
    entry.entry_id = "0000000000000002" + sharded[16:]
    response = {entry.entry_id: record}
    assert not _verify(response, entry, pem)  # checkpoint names a different shard


def test_production_key_pin_has_expected_log_id():
    assert hashlib.sha256(PUBLIC_REKOR_KEY_DER).hexdigest() == (
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
    )


def test_historical_sigstore_staging_fixture_verifies_offline():
    """Independently produced SET/checkpoint/proof; explicit staging trust only."""
    fixtures = Path(__file__).with_name("fixtures") / "rekor"
    record = json.loads((fixtures / "sigstore-staging-entry.json").read_text(encoding="utf-8"))
    key = (fixtures / "sigstore-staging-key.pem").read_bytes()
    body = base64.b64decode(record["body"])
    entry_id = _leaf(body).hex()
    assert record["logIndex"] != record["verification"]["inclusionProof"]["logIndex"]
    assert verify_rekor_evidence(record, body, entry_id, record["logID"], key)
    assert not verify_rekor_evidence(record, body, entry_id, record["logID"], None)
    record["verification"]["inclusionProof"]["hashes"][0] = "0" * 64
    assert not verify_rekor_evidence(record, body, entry_id, record["logID"], key)


def test_custom_log_requires_explicit_trust_anchor_before_fetch():
    _, entry, _ = _fixture()
    with patch("httpx.get") as get:
        assert not verify_transparency_log_entry(
            MANIFEST, entry, rekor_url="https://synthetic.rekor.test",
        )
    get.assert_not_called()


def test_self_signed_log_cannot_replace_production_trust_anchor():
    response, entry, _ = _fixture()
    assert not _verify(response, entry, None, rekor_url=REKOR_PUBLIC_URL)


def test_wrong_trusted_key_rejects_otherwise_valid_record():
    response, entry, _ = _fixture()
    _, _, wrong = _fixture(key=ec.derive_private_key(987654321, ec.SECP256R1()))
    assert not _verify(response, entry, wrong)


@pytest.mark.parametrize("mutation", [
    "set_missing", "set_signature", "set_encoding", "time", "index", "body",
    "log_id", "proof_missing", "proof_sibling", "proof_short", "proof_extra",
    "root", "checkpoint_missing", "checkpoint_signature", "checkpoint_root",
    "checkpoint_size", "checkpoint_key_id", "checkpoint_no_newline",
    "proof_index", "proof_size", "proof_bool", "proof_hash_type",
    "proof_hash_encoding", "entry_id", "entry_log", "entry_time", "entry_index",
    "algorithm", "duplicate_entry", "unknown_entry", "invalid_key", "unsafe_time",
])
def test_tampered_or_missing_authenticated_evidence_is_refused(mutation):
    response, entry, pem = _fixture()
    response = copy.deepcopy(response)
    record = response[entry.entry_id]
    verification = record["verification"]
    proof = verification["inclusionProof"]
    if mutation == "set_missing":
        del verification["signedEntryTimestamp"]
    elif mutation == "set_signature":
        verification["signedEntryTimestamp"] = base64.b64encode(b"forged").decode()
    elif mutation == "set_encoding":
        verification["signedEntryTimestamp"] = "!!!!"
    elif mutation == "time":
        record["integratedTime"] += 1
        entry.integrated_time = None  # still bound by the SET
    elif mutation == "index":
        record["logIndex"] += 1
        entry.log_index = None  # still bound by the SET
    elif mutation == "unsafe_time":
        record["integratedTime"] = 2**53
        entry.integrated_time = None
    elif mutation == "body":
        # Retain the manifest hash while changing the log leaf's bytes.
        decoded = json.loads(base64.b64decode(record["body"]))
        decoded["extra"] = "untrusted"
        record["body"] = base64.b64encode(jcs.canonicalize(decoded)).decode()
    elif mutation == "log_id":
        record["logID"] = "0" * 64
    elif mutation == "proof_missing":
        del verification["inclusionProof"]
    elif mutation == "proof_sibling":
        proof["hashes"][0] = "0" * 64
    elif mutation == "proof_short":
        proof["hashes"].pop()
    elif mutation == "proof_extra":
        proof["hashes"].append("0" * 64)
    elif mutation == "root":
        proof["rootHash"] = "0" * 64
    elif mutation == "checkpoint_missing":
        del proof["checkpoint"]
    elif mutation == "checkpoint_signature":
        lines = proof["checkpoint"].splitlines()
        raw = base64.b64decode(lines[-1].split()[-1])
        lines[-1] = lines[-1].rsplit(" ", 1)[0] + " " + base64.b64encode(raw[:4] + b"bad").decode()
        proof["checkpoint"] = "\n".join(lines) + "\n"
    elif mutation == "checkpoint_key_id":
        lines = proof["checkpoint"].splitlines()
        raw = base64.b64decode(lines[-1].split()[-1])
        lines[-1] = lines[-1].rsplit(" ", 1)[0] + " " + base64.b64encode(b"nope" + raw[4:]).decode()
        proof["checkpoint"] = "\n".join(lines) + "\n"
    elif mutation == "checkpoint_root":
        proof["checkpoint"] = proof["checkpoint"].replace(
            base64.b64encode(bytes.fromhex(proof["rootHash"])).decode(),
            base64.b64encode(bytes(32)).decode(),
        )
    elif mutation == "checkpoint_size":
        proof["checkpoint"] = proof["checkpoint"].replace("\n3\n", "\n4\n")
    elif mutation == "checkpoint_no_newline":
        proof["checkpoint"] = proof["checkpoint"].rstrip("\n")
    elif mutation == "proof_index":
        proof["logIndex"] = 3
    elif mutation == "proof_size":
        proof["treeSize"] = 0
    elif mutation == "proof_bool":
        proof["logIndex"] = True
    elif mutation == "proof_hash_type":
        proof["hashes"] = "not a list"
    elif mutation == "proof_hash_encoding":
        proof["hashes"][0] = "nonhex" * 11
    elif mutation == "entry_id":
        response = {"0" * 64: record}
        entry.entry_id = "0" * 64
    elif mutation == "entry_log":
        entry.log_id = "0" * 64
    elif mutation == "entry_time":
        entry.integrated_time += 1
    elif mutation == "entry_index":
        entry.log_index += 1
    elif mutation == "algorithm":
        decoded = json.loads(base64.b64decode(record["body"]))
        decoded["spec"]["data"]["hash"]["algorithm"] = "sha512"
        record["body"] = base64.b64encode(jcs.canonicalize(decoded)).decode()
    elif mutation == "duplicate_entry":
        response["0" * 64] = record
    elif mutation == "unknown_entry":
        response = {"0" * 64: record}
    elif mutation == "invalid_key":
        pem = b"untrusted key bytes"
    assert not _verify(response, entry, pem)
