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


def test_committed_vectors_match_a_fresh_regeneration() -> None:
    """The committed JSON must be what ``generate.py`` produces today.

    The vectors are committed so a consumer in another language never has to
    run Python, which means the files and the generator can drift apart
    silently. Rebuilding them in memory and diffing closes that: a vector
    edited by hand, or a generator change made without regenerating, fails
    here rather than shipping as a contract nobody can reproduce.

    Reproducibility rests on the fixed seed and Ed25519 determinism (RFC 8032),
    so this is stable rather than merely usually true. It is also why there is
    no post-quantum vector: ML-DSA-65 signing is hedged, and a vector whose
    bytes changed on every run could not be asserted this way.
    """
    from tests.vectors.generate import build

    rebuilt = {v["id"]: v for v in build()}
    committed = {
        p.stem: json.loads(p.read_text()) for p in VECTORS_DIR.glob("AM-VEC-*.json")
    }

    assert rebuilt.keys() == committed.keys(), (
        "the set of committed vectors differs from what generate.py builds; "
        "run `python -m tests.vectors.generate`"
    )
    for vid, expected in rebuilt.items():
        assert committed[vid] == expected, (
            f"{vid} on disk differs from a fresh regeneration; run "
            f"`python -m tests.vectors.generate` and review the diff"
        )


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


@pytest.mark.parametrize(
    "file_name",
    COSE_NEGATIVE_FILES,
    ids=[f.removesuffix(".json") for f in COSE_NEGATIVE_FILES],
)
def test_cose_negative_vector_declares_whether_its_signature_is_valid(
    file_name: str,
) -> None:
    """``signature_valid`` must be present and must be true.

    It is the property that separates a vector testing the rule it names from
    one a verifier passes by rejecting a broken signature and never reaching
    that rule. Asserting it here means a vector cannot be added, or an existing
    one mutated, in a way that quietly turns it into an incidental signature
    failure.

    The two exceptions are declared rather than tolerated: AM-VEC-COSE-002
    invalidates the signature on purpose, since a tampered protected header is
    the rule under test, and AM-VEC-COSE-008 has a nil payload, so there is no
    Sig_structure to verify over in the first place.
    """
    vector = _load_vector(file_name)
    assert "signature_valid" in vector, (
        f"{vector['id']}: every negative COSE vector must declare whether its "
        f"signature verifies"
    )

    if vector["id"] in {"AM-VEC-COSE-002", "AM-VEC-COSE-008"}:
        assert vector["signature_valid"] is False
        return
    assert vector["signature_valid"] is True, (
        f"{vector['id']}: a verifier could pass this by rejecting the "
        f"signature and never applying the rule the vector names"
    )


@pytest.mark.parametrize(
    "file_name",
    COSE_NEGATIVE_FILES,
    ids=[f.removesuffix(".json") for f in COSE_NEGATIVE_FILES],
)
def test_cose_negative_vector_signature_claim_is_true(file_name: str) -> None:
    """Re-derive ``signature_valid`` the way a foreign implementation would.

    Using only the public key published in ``keys.json`` and the RFC 9052
    Sig_structure, so the claim is checked against the bytes on disk rather
    than trusted from the generator that wrote them.
    """
    import base64

    import cbor2
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from agent_manifest._cose import _sig_structure_sign1

    vector = _load_vector(file_name)
    keys = json.loads((VECTORS_DIR / "keys.json").read_text())
    raw = base64.urlsafe_b64decode(keys["public_key_b64url"] + "=" * 4)
    public_key = Ed25519PublicKey.from_public_bytes(raw)

    decoded = cbor2.loads(bytes.fromhex(vector["envelope_hex"]))
    body = decoded.value if isinstance(decoded, cbor2.CBORTag) else decoded
    protected, _unprotected, payload, signature = body

    if payload is None:
        assert vector["signature_valid"] is False, vector["id"]
        return

    try:
        public_key.verify(signature, _sig_structure_sign1(protected, payload))
        verifies = True
    except InvalidSignature:
        verifies = False

    assert verifies is vector["signature_valid"], (
        f"{vector['id']}: signature_valid says {vector['signature_valid']} but "
        f"the signature on disk {'verifies' if verifies else 'does not verify'}"
    )


def _repaired_envelopes() -> dict[str, tuple[bytes, dict[str, Any]]]:
    """Each phase 3 vector with its named defect removed and nothing else.

    Built from the same helpers that build the vectors, so a repair cannot
    silently diverge from the thing it is repairing.
    """
    from agent_manifest._canonicalize import canonicalize
    from agent_manifest._cose import sign_cose_sign1

    from tests.vectors.generate import KP, _sign_payload, base_context, cose_manifest

    context = base_context()
    valid_payload = canonicalize(cose_manifest())
    # The carrier 010, 011 and 013 hang their defect on. Asserted below to be
    # benign on its own, so those three cannot be passing on the carrier.
    carrier = canonicalize(cose_manifest(attestation={"placeholder": 0}))

    return {
        # 009's defect is entirely in the context, so the repair is to drop
        # the issuer binding and leave the envelope untouched.
        "AM-VEC-COSE-009": (sign_cose_sign1(cose_manifest(), KP), context),
        "AM-VEC-COSE-010": (_sign_payload(valid_payload), context),
        "AM-VEC-COSE-011": (
            _sign_payload(
                carrier.replace(b'{"placeholder":0}', b'{"nonce_skew_seconds":0}')
            ),
            context,
        ),
        "AM-VEC-COSE-012": (_sign_payload(valid_payload), context),
        "AM-VEC-COSE-013": (_sign_payload(carrier), context),
    }


@pytest.mark.parametrize("vector_id", sorted(_repaired_envelopes()))
def test_cose_negative_vector_isolates_its_named_defect(vector_id: str) -> None:
    """Remove only the defect a vector names, and it must verify VALID.

    This is what separates a vector that tests its rule from one that happens
    to be rejected for some other reason it also contains. ``signature_valid``
    rules out an incidental signature failure; this rules out everything else,
    by showing the named defect is the sole thing standing between the
    envelope and a VALID result.

    It matters most for AM-VEC-COSE-011 and 013, which hang their defect on an
    ``attestation`` object. If that carrier were not itself benign the vectors
    would have two defects, and an implementation could pass them without
    implementing the rule under test.
    """
    envelope, context = _repaired_envelopes()[vector_id]
    result = verify_manifest(envelope, VerificationContext(**context), RevocationStore())

    assert result.result.value == "VALID", (
        f"{vector_id}: with its named defect removed the envelope still does "
        f"not verify ({result.result.value}), so the vector carries a second "
        f"defect and does not isolate the rule it names"
    )
    assert result.signature_verified is True, vector_id
