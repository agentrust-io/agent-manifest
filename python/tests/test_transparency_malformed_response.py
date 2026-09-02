"""Regression vectors for malformed Rekor verification responses (#358)."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from agent_manifest._canonicalize import canonicalize
from agent_manifest._transparency import (
    TransparencyLogEntry,
    verify_transparency_log_entry,
)


ENTRY = TransparencyLogEntry(
    log_id="test-log",
    entry_id="test-entry",
    inclusion_proof="proof",
)
MANIFEST: dict = {}


def _response_with_json(value) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = value
    return response


def _encoded(value) -> str:
    return base64.b64encode(json.dumps(value).encode()).decode()


def _verify(response: MagicMock) -> bool:
    with patch("httpx.get", return_value=response):
        return verify_transparency_log_entry(MANIFEST, ENTRY)


def test_valid_matching_200_control_remains_true() -> None:
    expected_hash = hashlib.sha256(canonicalize({})).hexdigest()
    response = _response_with_json(
        {
            ENTRY.entry_id: {
                "body": _encoded(
                    {
                        "spec": {
                            "data": {
                                "hash": {
                                    "algorithm": "sha256",
                                    "value": expected_hash,
                                }
                            }
                        }
                    }
                )
            }
        }
    )

    assert _verify(response) is True


def test_invalid_response_json_returns_false() -> None:
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("invalid JSON")

    assert _verify(response) is False


@pytest.mark.parametrize("body", [[], "bad", None, 1, True])
def test_non_object_top_level_response_returns_false(body) -> None:
    assert _verify(_response_with_json(body)) is False


@pytest.mark.parametrize("entry_data", ["bad", [], None, 1, True])
def test_non_object_entry_data_returns_false(entry_data) -> None:
    assert _verify(_response_with_json({ENTRY.entry_id: entry_data})) is False


@pytest.mark.parametrize(
    "encoded_body",
    [
        "not valid base64 !!!",
        base64.b64encode(b"not-json").decode(),
    ],
)
def test_unparseable_encoded_body_returns_false(encoded_body: str) -> None:
    response = _response_with_json({ENTRY.entry_id: {"body": encoded_body}})
    assert _verify(response) is False


@pytest.mark.parametrize("decoded", [[], "bad", None, 1, True])
def test_non_object_decoded_body_returns_false(decoded) -> None:
    response = _response_with_json(
        {ENTRY.entry_id: {"body": _encoded(decoded)}}
    )
    assert _verify(response) is False


@pytest.mark.parametrize(
    "decoded",
    [
        {"spec": "bad"},
        {"spec": {"data": "bad"}},
        {"spec": {"data": {"hash": "bad"}}},
        {"spec": {"data": {"hash": []}}},
    ],
)
def test_non_object_nested_hash_containers_return_false(decoded: dict) -> None:
    response = _response_with_json(
        {ENTRY.entry_id: {"body": _encoded(decoded)}}
    )
    assert _verify(response) is False
