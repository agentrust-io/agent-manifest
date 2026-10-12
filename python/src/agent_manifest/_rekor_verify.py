"""Rekor v1 SET and RFC 6962 inclusion verification under a caller trust anchor.

Protocol references: sigstore/rekor pkg/verify/verify.go and RFC 6962 section 2.1.
This checks a signed checkpoint, not log consistency or checkpoint freshness.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from ._canonicalize import canonicalize

# Rekor v1's production P-256 SPKI from Sigstore's trusted root. This is a
# static trust anchor, never a key fetched from the untrusted log response.
# https://github.com/sigstore/root-signing/blob/c9bda74ad2221f938f7d2e0295ca3aad2da710a8/targets/trusted_root.json
PUBLIC_REKOR_KEY_DER = base64.b64decode(
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbm"
    "LSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
)

LogKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


def _signature(key: LogKey, signature: bytes, data: bytes) -> None:
    if isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("Rekor v1 ECDSA keys must use P-256")
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    else:
        key.verify(signature, data)


def _integer(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise ValueError("expected a nonnegative safe integer")
    return value


def _hex_hash(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("expected a SHA-256 digest")
    return bytes.fromhex(value)


def _base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected a base64 string")
    return base64.b64decode(value, validate=True)


def _checkpoint(
    text: Any, key: LogKey, key_id: bytes, size: int, root: bytes,
    tree_id: int | None,
) -> None:
    if not isinstance(text, str) or text.count("\n\n") != 1:
        raise ValueError("missing or malformed signed checkpoint")
    header, signatures = text.split("\n\n")
    lines = header.split("\n")
    if len(lines) < 3 or not lines[0] or not re.fullmatch(r"[0-9]+", lines[1]):
        raise ValueError("invalid checkpoint header")
    if int(lines[1]) != size or _base64(lines[2]) != root:
        raise ValueError("checkpoint does not bind proof root and size")
    if tree_id is not None and lines[0].rsplit(" - ", 1)[-1] != str(tree_id):
        raise ValueError("checkpoint does not bind the requested shard")
    if not signatures.endswith("\n"):
        raise ValueError("unterminated checkpoint signatures")
    verified = False
    for line in signatures.splitlines():
        match = re.fullmatch(r"\u2014 (\S+) (\S+)", line)
        if match is None:
            raise ValueError("invalid checkpoint signature line")
        raw = _base64(match[2])
        if len(raw) < 5:
            raise ValueError("short checkpoint signature")
        if raw[:4] == key_id[:4]:
            _signature(key, raw[4:], (header + "\n").encode("utf-8"))
            verified = True
    if not verified:
        raise ValueError("no signature under the trusted log key")


def _inclusion(body: bytes, proof: dict[str, Any]) -> tuple[int, bytes]:
    size = _integer(proof["treeSize"])
    index = _integer(proof["logIndex"])
    if size == 0 or index >= size:
        raise ValueError("inclusion index outside tree")
    siblings = proof["hashes"]
    if not isinstance(siblings, list):
        raise ValueError("proof hashes must be a list")
    # The right edge of a non-power-of-two tree has fewer proof nodes.
    inner = (index ^ (size - 1)).bit_length()
    border = (index >> inner).bit_count()
    if len(siblings) != inner + border:
        raise ValueError("incorrect inclusion path length")
    calculated = hashlib.sha256(b"\x00" + body).digest()
    for level, sibling in enumerate(siblings):
        node = _hex_hash(sibling)
        if level >= inner or (index >> level) & 1:
            calculated = hashlib.sha256(b"\x01" + node + calculated).digest()
        else:
            calculated = hashlib.sha256(b"\x01" + calculated + node).digest()
    root = _hex_hash(proof["rootHash"])
    if calculated != root:
        raise ValueError("inclusion proof root mismatch")
    return size, root


def verify_rekor_evidence(
    record: dict[str, Any], body: bytes, entry_id: str, log_id: str,
    trusted_key_pem: bytes | None,
) -> bool:
    """Check log identity, signed entry timestamp and authenticated inclusion."""
    try:
        if trusted_key_pem is None:
            key = serialization.load_der_public_key(PUBLIC_REKOR_KEY_DER)
        else:
            key = serialization.load_pem_public_key(trusted_key_pem)
        if not isinstance(key, (ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
            return False
        key_id = hashlib.sha256(key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
        )).digest()
        if _hex_hash(record["logID"]) != key_id or _hex_hash(log_id) != key_id:
            return False
        # Entry UUIDs are the leaf hash, optionally prefixed by a shard ID.
        if entry_id[-64:].lower() != hashlib.sha256(b"\x00" + body).hexdigest():
            return False
        timestamp = _integer(record["integratedTime"])
        index = _integer(record["logIndex"])
        verification = record["verification"]
        payload = canonicalize({
            "body": record["body"], "integratedTime": timestamp,
            "logIndex": index, "logID": record["logID"],
        }, exclude_none=False)
        _signature(key, _base64(verification["signedEntryTimestamp"]), payload)
        proof = verification["inclusionProof"]
        size, root = _inclusion(body, proof)
        # The SET logIndex is virtual across shards; proof.logIndex is local.
        # Each is checked in its own signed structure, not equated by value.
        tree_id = int(entry_id[:16], 16) if len(entry_id) == 80 else None
        _checkpoint(proof["checkpoint"], key, key_id, size, root, tree_id)
        return True
    except (InvalidSignature, UnsupportedAlgorithm, KeyError, TypeError, ValueError, OverflowError):
        return False
