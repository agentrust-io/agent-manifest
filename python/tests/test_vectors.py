"""Conformance: the reference engine must reproduce every language-neutral vector.

The vectors in ``tests/vectors/`` are a portable contract (see
``tests/vectors/README.md``) intended to be consumed by SDKs in any language.
This test guards the Python reference implementation against them: for each
vector it loads the manifest + context, runs :func:`verify_manifest`, and
asserts the expected overall result and per-field statuses.

Conformance IDs: AM-VEC-001 .. AM-VEC-015.
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
    result = verify_manifest(vector["manifest"], ctx, store)

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
