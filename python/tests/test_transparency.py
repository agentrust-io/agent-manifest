"""Tests for Rekor transparency log integration (_transparency.py).

Mocks httpx so no real network calls are made.
"""
from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from agent_manifest._signing import SIGNED_FIELDS, generate_ed25519, Ed25519Signer
from agent_manifest._transparency import (
    REKOR_API_PATH,
    REKOR_PUBLIC_URL,
    TransparencyLogEntry,
    publish_to_rekor,
    verify_transparency_log_entry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod-001",
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "expires_at": "2026-09-21T09:00:00Z",
    "issuer": "spiffe://trust.example/signing-authority",
    "crypto_profile": "standard",
    "artifacts": {
        "system_prompt": {
            "hash": "sha256:" + "a" * 64,
            "bound_at": "2026-06-23T09:00:00Z",
        }
    },
    "delegation_chain": [],
    "hitl_record": None,
}

# Pre-compute a fixed key pair for reuse across tests
_KP = generate_ed25519()
_SIG_BLOCK = Ed25519Signer(_KP).sign(SAMPLE_MANIFEST)
_SIG_VALUE = _SIG_BLOCK["signature_value"]
_PUB_B64URL = _KP.public_b64url()

FAKE_ENTRY_UUID = "3030303030303030303030303030303030303030303030303030303030303030"
FAKE_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"


def _make_rekor_body(entry_uuid: str, log_id: str, inclusion_proof: dict | None = None) -> dict:
    """Build a plausible Rekor POST response body."""
    if inclusion_proof is None:
        inclusion_proof = {
            "checkpoint": "checkpoint-value",
            "hashes": ["sha256:" + "a" * 64],
            "logIndex": 12345,
            "rootHash": "sha256:" + "b" * 64,
            "treeSize": 99999,
        }
    return {
        entry_uuid: {
            "logID": log_id,
            "logIndex": 12345,
            "integratedTime": 1750000000,
            "checkpoint": "checkpoint-value",
            "inclusionProof": inclusion_proof,
            "body": "",
        }
    }


def _make_get_response_body(
    entry_uuid: str,
    content_hash: str,
    log_id: str = FAKE_LOG_ID,
) -> dict:
    """Build a plausible Rekor GET response body with matching content hash."""
    spec_body = {
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": content_hash}},
            "signature": {
                "content": _SIG_VALUE,
                "publicKey": {"content": _PUB_B64URL},
            },
        }
    }
    body_b64 = base64.b64encode(json.dumps(spec_body).encode()).decode()
    return {
        entry_uuid: {
            "logID": log_id,
            "logIndex": 12345,
            "integratedTime": 1750000000,
            "body": body_b64,
        }
    }


# ---------------------------------------------------------------------------
# Helper: compute expected content hash for SAMPLE_MANIFEST
# ---------------------------------------------------------------------------

def _expected_content_hash() -> str:
    from agent_manifest._canonicalize import canonicalize

    subset = {k: SAMPLE_MANIFEST[k] for k in SIGNED_FIELDS if k in SAMPLE_MANIFEST}
    canonical_bytes = canonicalize(subset)
    return hashlib.sha256(canonical_bytes).hexdigest()


# ---------------------------------------------------------------------------
# publish_to_rekor: success path
# ---------------------------------------------------------------------------


def test_publish_to_rekor_success():
    """200 response: returns a TransparencyLogEntry with expected fields."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_rekor_body(FAKE_ENTRY_UUID, FAKE_LOG_ID)

    with patch("httpx.post", return_value=mock_response) as mock_post:
        result = publish_to_rekor(
            manifest_dict=SAMPLE_MANIFEST,
            signature_value=_SIG_VALUE,
            public_key_b64url=_PUB_B64URL,
        )

    assert isinstance(result, TransparencyLogEntry)
    assert result.entry_id == FAKE_ENTRY_UUID
    assert result.log_id == FAKE_LOG_ID
    assert result.log_index == 12345
    assert result.integrated_time == 1750000000
    assert result.checkpoint == "checkpoint-value"
    # inclusion_proof is base64url encoded, check it's non-empty
    assert result.inclusion_proof

    # Verify httpx.post was called with the correct URL
    mock_post.assert_called_once()
    call_url = mock_post.call_args[0][0]
    assert call_url == f"{REKOR_PUBLIC_URL}{REKOR_API_PATH}"


def test_publish_to_rekor_201_response_also_accepted():
    """201 Created is also a valid success code for Rekor."""
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = _make_rekor_body(FAKE_ENTRY_UUID, FAKE_LOG_ID)

    with patch("httpx.post", return_value=mock_response):
        result = publish_to_rekor(
            manifest_dict=SAMPLE_MANIFEST,
            signature_value=_SIG_VALUE,
            public_key_b64url=_PUB_B64URL,
        )

    assert result.entry_id == FAKE_ENTRY_UUID


def test_publish_to_rekor_custom_url():
    """Custom rekor_url is passed through to the HTTP call."""
    custom_url = "https://rekor.internal.example.com"
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_rekor_body(FAKE_ENTRY_UUID, custom_url)

    with patch("httpx.post", return_value=mock_response) as mock_post:
        result = publish_to_rekor(
            manifest_dict=SAMPLE_MANIFEST,
            signature_value=_SIG_VALUE,
            public_key_b64url=_PUB_B64URL,
            rekor_url=custom_url,
        )

    call_url = mock_post.call_args[0][0]
    assert call_url.startswith(custom_url)
    assert result.log_id == custom_url


# ---------------------------------------------------------------------------
# publish_to_rekor: error paths
# ---------------------------------------------------------------------------


def test_publish_to_rekor_non_200_raises_runtime_error():
    """Non-2xx response raises RuntimeError."""
    mock_response = MagicMock()
    mock_response.status_code = 422
    mock_response.text = "Unprocessable Entity"

    with patch("httpx.post", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Rekor submission failed"):
            publish_to_rekor(
                manifest_dict=SAMPLE_MANIFEST,
                signature_value=_SIG_VALUE,
                public_key_b64url=_PUB_B64URL,
            )


def test_publish_to_rekor_500_raises_runtime_error():
    """500 Internal Server Error raises RuntimeError."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"

    with patch("httpx.post", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Rekor submission failed: 500"):
            publish_to_rekor(
                manifest_dict=SAMPLE_MANIFEST,
                signature_value=_SIG_VALUE,
                public_key_b64url=_PUB_B64URL,
            )


def test_publish_to_rekor_network_error_raises():
    """httpx.RequestError propagates as-is (network unreachable etc.)."""
    import httpx

    with patch("httpx.post", side_effect=httpx.RequestError("connection refused")):
        with pytest.raises(httpx.RequestError):
            publish_to_rekor(
                manifest_dict=SAMPLE_MANIFEST,
                signature_value=_SIG_VALUE,
                public_key_b64url=_PUB_B64URL,
            )


def test_publish_to_rekor_timeout_raises():
    """httpx.TimeoutException propagates."""
    import httpx

    with patch("httpx.post", side_effect=httpx.TimeoutException("timed out")):
        with pytest.raises(httpx.TimeoutException):
            publish_to_rekor(
                manifest_dict=SAMPLE_MANIFEST,
                signature_value=_SIG_VALUE,
                public_key_b64url=_PUB_B64URL,
            )


# ---------------------------------------------------------------------------
# verify_transparency_log_entry: success path
# ---------------------------------------------------------------------------


def test_verify_entry_success():
    """200 response with matching hash returns True."""
    content_hash = _expected_content_hash()
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_get_response_body(
        FAKE_ENTRY_UUID, content_hash
    )

    with patch("httpx.get", return_value=mock_response):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is True


# ---------------------------------------------------------------------------
# verify_transparency_log_entry: not-found (404) path
# ---------------------------------------------------------------------------


def test_verify_entry_not_found_returns_false():
    """404 response returns False."""
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("httpx.get", return_value=mock_response):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is False


def test_verify_entry_500_returns_false():
    """5xx response also returns False."""
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 500

    with patch("httpx.get", return_value=mock_response):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is False


# ---------------------------------------------------------------------------
# verify_transparency_log_entry: network error path
# ---------------------------------------------------------------------------


def test_verify_entry_network_error_returns_false():
    """Network error (RequestError) is caught and returns False."""
    import httpx

    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    with patch("httpx.get", side_effect=httpx.RequestError("connection refused")):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is False


# ---------------------------------------------------------------------------
# verify_transparency_log_entry: hash mismatch (signature mismatch in log)
# ---------------------------------------------------------------------------


def test_verify_entry_hash_mismatch_returns_false():
    """Log entry contains a different content hash: verification fails."""
    wrong_hash = "0" * 64  # Deliberately wrong
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_get_response_body(
        FAKE_ENTRY_UUID, wrong_hash
    )

    with patch("httpx.get", return_value=mock_response):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is False


def test_verify_entry_missing_body_returns_false():
    """Entry body missing from the response: hash extraction yields empty string."""
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    # body key absent; default base64 decode of "e30=" is "{}" which has no hash
    mock_response.json.return_value = {
        FAKE_ENTRY_UUID: {"logID": FAKE_LOG_ID, "logIndex": 1}
    }

    with patch("httpx.get", return_value=mock_response):
        result = verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    assert result is False


# ---------------------------------------------------------------------------
# verify_transparency_log_entry: custom rekor_url
# ---------------------------------------------------------------------------


def test_verify_entry_uses_correct_url():
    """GET is called with the correct entry URL."""
    content_hash = _expected_content_hash()
    entry = TransparencyLogEntry(
        log_id=FAKE_LOG_ID,
        entry_id=FAKE_ENTRY_UUID,
        inclusion_proof="proof",
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_get_response_body(
        FAKE_ENTRY_UUID, content_hash
    )

    with patch("httpx.get", return_value=mock_response) as mock_get:
        verify_transparency_log_entry(SAMPLE_MANIFEST, entry)

    call_url = mock_get.call_args[0][0]
    assert FAKE_ENTRY_UUID in call_url
    assert REKOR_API_PATH in call_url
