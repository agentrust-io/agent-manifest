"""Conformance: the reference engine must reproduce every language-neutral vector.

The vectors in ``tests/vectors/`` are a portable contract (see
``tests/vectors/README.md``) intended to be consumed by SDKs in any language.
This test guards the Python reference implementation against them: for each
vector it loads the manifest + context, runs :func:`verify_manifest`, and
asserts the expected overall result and per-field statuses.

Conformance IDs: AM-VEC-001 .. AM-VEC-020.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_manifest._verify import (
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load_index() -> list[dict[str, Any]]:
    index = json.loads((VECTORS_DIR / "index.json").read_text())
    return index["vectors"]


def _load_vector(file_name: str) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / file_name).read_text())


VECTOR_FILES = [entry["file"] for entry in _load_index()]


def test_index_lists_every_vector_file() -> None:
    on_disk = {p.name for p in VECTORS_DIR.glob("AM-VEC-*.json")}
    in_index = set(VECTOR_FILES)
    assert on_disk == in_index, "index.json is out of sync with the vector files"


@pytest.mark.parametrize("file_name", VECTOR_FILES, ids=[f.removesuffix(".json") for f in VECTOR_FILES])
def test_vector(file_name: str) -> None:
    vector = _load_vector(file_name)

    store = RevocationStore()
    if vector.get("revoke"):
        from datetime import datetime, timezone
        store.revoke(RevocationRecord(
            manifest_id=vector["manifest"]["manifest_id"],
            revoked_at=datetime.now(timezone.utc),
            reason="conformance vector",
            revoked_by="test",
        ))

    ctx = VerificationContext(**vector["context"])
    # A vector carries either a v0.1 manifest document or a v0.2 COSE
    # envelope. The engine selects the procedure from what it is handed, so
    # both kinds go through the same call (ADR-0011).
    if "envelope_hex" in vector:
        subject: Any = bytes.fromhex(vector["envelope_hex"])
    else:
        subject = vector["manifest"]
    result = verify_manifest(subject, ctx, store)

    expected = vector["expected"]
    assert result.result.value == expected["result"], (
        f"{vector['id']}: expected {expected['result']}, got {result.result.value}"
    )

    if "signature_verified" in expected:
        assert result.signature_verified is expected["signature_verified"], vector["id"]
    if "attestation_verified" in expected:
        assert result.attestation_verified is expected["attestation_verified"], vector["id"]

    for field, want in expected.get("fields_verified", {}).items():
        got = getattr(result.fields_verified, field).value
        assert got == want, f"{vector['id']}: fields_verified.{field} expected {want}, got {got}"


# Only vectors that pin an encoding. A negative vector carries `envelope_hex`
# but no `expected.cose`, because its bytes are malformed by construction and
# pinning their decomposition would assert that a verifier can parse something
# it is being told to reject.
COSE_VECTOR_FILES = [
    f for f in VECTOR_FILES if "cose" in _load_vector(f).get("expected", {})
]

COSE_NEGATIVE_FILES = [
    f
    for f in VECTOR_FILES
    if "envelope_hex" in _load_vector(f)
    and "cose" not in _load_vector(f).get("expected", {})
]


@pytest.mark.parametrize(
    "file_name", COSE_VECTOR_FILES, ids=[f.removesuffix(".json") for f in COSE_VECTOR_FILES]
)
def test_cose_vector_encoding_is_pinned(file_name: str) -> None:
    """The COSE object must be these exact bytes, not merely self-consistent.

    This is what makes the vectors a portable contract: an implementation in
    another language, using a COSE library, has to agree with the reference
    SDK element by element. It also pins the phase 2 decision (ADR-0013) that
    an envelope with no receipt yet carries a zero-length unprotected header
    map rather than omitting it - ``unprotected_hex`` is ``a0``.
    """
    import cbor2

    from agent_manifest._cose import payload_hash

    vector = _load_vector(file_name)
    pinned = vector["expected"]["cose"]
    envelope = bytes.fromhex(vector["envelope_hex"])

    tagged = cbor2.loads(envelope)
    assert tagged.tag == pinned["tag"]
    protected, unprotected, payload, signature = tagged.value

    assert protected.hex() == pinned["protected_hex"]
    assert cbor2.dumps(dict(unprotected)).hex() == pinned["unprotected_hex"]
    assert payload.hex() == pinned["payload_hex"]
    assert signature.hex() == pinned["signature_hex"]
    assert payload_hash(payload) == pinned["manifest_hash"]

    # And the SDK reproduces the whole object from the manifest and the fixed
    # key, so the vector is a regression test on the encoder, not a snapshot
    # of whatever it happened to emit on the day it was written.
    import json

    from agent_manifest._cose import sign_cose_sign1
    from agent_manifest._signing import ed25519_from_private_bytes

    keypair = ed25519_from_private_bytes(bytes(range(32)))
    regenerated = sign_cose_sign1(json.loads(payload.decode()), keypair)
    assert regenerated == envelope


@pytest.mark.parametrize(
    "file_name",
    COSE_NEGATIVE_FILES,
    ids=[f.removesuffix(".json") for f in COSE_NEGATIVE_FILES],
)
def test_cose_negative_vector_is_not_silently_unparseable(file_name: str) -> None:
    """A negative vector must be rejected for its own reason, not by accident.

    The vector schema records that a manifest is rejected, not why, so a
    verifier could pass one of these by failing to decode the CBOR at all.
    These vectors are built by mutating a valid envelope, so the envelope must
    still decode as CBOR even where the mutation makes it inadmissible. This
    asserts that, so a vector cannot degrade into "rejected because it was
    garbage" without the suite noticing.
    """
    import cbor2

    vector = _load_vector(file_name)
    envelope = bytes.fromhex(vector["envelope_hex"])

    # Trailing-byte vectors are deliberately undecodable past the first
    # object, which is the property under test, so they are exempt.
    if "Trailing bytes" in vector["description"]:
        return

    decoded = cbor2.loads(envelope)
    body = decoded.value if isinstance(decoded, cbor2.CBORTag) else decoded
    assert isinstance(body, (list, tuple)), (
        f"{vector['id']}: the mutated envelope should still be a CBOR array, "
        f"otherwise the vector tests decoder robustness rather than the rule "
        f"it names"
    )
    assert len(body) == 4, f"{vector['id']}: should still be four elements"
