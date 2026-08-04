"""HTTP surface for version 0.2 COSE manifests - POST /verify/cose.

The tests are weighted towards abuse rather than the happy path, because the
endpoint's job is to be a safe front door for untrusted bytes: what it refuses
matters more than what it accepts.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._cose import (
    MEDIA_TYPE_MANIFEST_COSE,
    MEDIA_TYPE_MANIFEST_JSON,
    attach_attestation,
    cose_payload,
    payload_hash,
    sign_cose_sign1,
)
from agent_manifest._signing import generate_ed25519
from agent_manifest._verify import (
    MAX_COSE_ENVELOPE_BYTES,
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    create_router,
)

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="fastapi not installed")

NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
MANIFEST_ID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

KP = generate_ed25519()


def manifest(**overrides):
    m = {
        "manifest_id": MANIFEST_ID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.2",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "issuer": "spiffe://trust.example/signing-authority",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA},
            "policy_bundle": {"hash": SHA_B},
        },
    }
    m.update(overrides)
    return m


def trust_store(**overrides):
    ctx = VerificationContext(
        system_prompt_hash=SHA,
        policy_bundle_hash=SHA_B,
        trusted_keys={KP.key_id: KP.public_b64url()},
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def client(cose_context=None, revocation_store=None):
    app = FastAPI()
    app.include_router(
        create_router({}, revocation_store or RevocationStore(), cose_context)
    )
    return TestClient(app)


def post(c, body, content_type=MEDIA_TYPE_MANIFEST_COSE, **params):
    headers = {} if content_type is None else {"Content-Type": content_type}
    return c.post("/verify/cose", content=body, headers=headers, params=params)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_a_valid_envelope_verifies():
    response = post(client(trust_store()), sign_cose_sign1(manifest(), KP))
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "VALID"
    assert body["signature_verified"] is True
    assert body["manifest_id"] == MANIFEST_ID


def test_the_result_is_not_cacheable_and_not_sniffable():
    """A verification result is a security decision about specific bytes."""
    response = post(client(trust_store()), sign_cose_sign1(manifest(), KP))
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_enforce_flags_are_honoured():
    signed = sign_cose_sign1(manifest(), KP)
    response = post(client(trust_store()), signed, enforce_attestation=True)
    assert response.json()["result"] == "ATTESTATION_UNAVAILABLE"


def test_attestation_binding_is_checked_over_http():
    m = manifest()
    signed = attach_attestation(
        sign_cose_sign1(m, KP),
        {
            "platform": "amd-sev-snp",
            "manifest_hash_in_report": payload_hash(cose_payload(m)),
        },
    )
    response = post(client(trust_store()), signed, enforce_attestation=True)
    body = response.json()
    assert body["result"] == "VALID"
    assert body["attestation_verified"] is True


# ---------------------------------------------------------------------------
# The media type is the gate
# ---------------------------------------------------------------------------


def test_the_json_media_type_is_refused():
    """The payload's type is not the object's type."""
    response = post(
        client(trust_store()), sign_cose_sign1(manifest(), KP), MEDIA_TYPE_MANIFEST_JSON
    )
    assert response.status_code == 415


def test_a_vendor_tree_alias_is_refused():
    """Envelope spec section 7: two valid type values for one object type is
    the ambiguity typ exists to remove."""
    response = post(
        client(trust_store()),
        sign_cose_sign1(manifest(), KP),
        "application/vnd.agent-manifest+cose",
    )
    assert response.status_code == 415


def test_a_generic_cbor_media_type_is_refused():
    response = post(
        client(trust_store()), sign_cose_sign1(manifest(), KP), "application/cbor"
    )
    assert response.status_code == 415


def test_an_absent_media_type_is_refused_rather_than_sniffed():
    c = client(trust_store())
    response = c.post("/verify/cose", content=sign_cose_sign1(manifest(), KP))
    assert response.status_code == 415


def test_media_type_parameters_are_tolerated():
    """`; charset=utf-8` from a well-meaning client is not a different type."""
    response = post(
        client(trust_store()),
        sign_cose_sign1(manifest(), KP),
        f"{MEDIA_TYPE_MANIFEST_COSE}; charset=utf-8",
    )
    assert response.status_code == 200


def test_media_type_case_is_not_significant():
    response = post(
        client(trust_store()),
        sign_cose_sign1(manifest(), KP),
        MEDIA_TYPE_MANIFEST_COSE.upper(),
    )
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Bounded input
# ---------------------------------------------------------------------------


def test_an_oversized_body_is_refused():
    response = post(client(trust_store()), b"\x00" * (MAX_COSE_ENVELOPE_BYTES + 1))
    assert response.status_code == 413


def test_a_lying_content_length_does_not_get_past_the_stream_cap():
    """Content-Length is a claim; the cap is enforced on the bytes."""
    c = client(trust_store())
    response = c.post(
        "/verify/cose",
        content=b"\x00" * (MAX_COSE_ENVELOPE_BYTES + 1),
        headers={
            "Content-Type": MEDIA_TYPE_MANIFEST_COSE,
            # understated on purpose
            "Content-Length": "10",
        },
    )
    assert response.status_code in (400, 413)


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


def test_without_a_server_trust_store_nothing_is_ever_valid():
    """No keys configured means no authentication is possible. The endpoint
    must not treat a well-formed signature as sufficient."""
    response = post(client(), sign_cose_sign1(manifest(), KP))
    assert response.status_code == 200
    assert response.json()["result"] == "UNVERIFIABLE"
    assert response.json()["signature_verified"] is False


def test_an_unknown_key_is_not_valid():
    other = generate_ed25519()
    response = post(client(trust_store()), sign_cose_sign1(manifest(), other))
    assert response.json()["result"] == "MISMATCH"


def test_a_tampered_payload_is_a_verdict_not_an_error():
    signed = bytearray(sign_cose_sign1(manifest(), KP))
    signed[-1] ^= 0x01
    response = post(client(trust_store()), bytes(signed))
    assert response.status_code == 200
    assert response.json()["result"] == "MISMATCH"


def test_garbage_is_a_verdict_not_a_server_error():
    response = post(client(trust_store()), b"\x82\x01not cbor at all")
    assert response.status_code == 200
    assert response.json()["result"] == "MISMATCH"


def test_an_empty_body_is_a_verdict_not_a_server_error():
    response = post(client(trust_store()), b"")
    assert response.status_code == 200
    assert response.json()["result"] == "MISMATCH"


def test_errors_do_not_reflect_parser_internals():
    """The endpoint must not be usable as an oracle for the decoder."""
    response = post(client(trust_store()), b"\xd2\x84\x40\xa0\x40\x40")
    text = response.text.lower()
    for leak in ("traceback", "cbor2", "file \"", "line ", "_cose.py"):
        assert leak not in text


def test_a_v01_manifest_over_this_endpoint_is_incompatible_not_valid():
    """The endpoint is for the 0.2 envelope; a 0.1 payload routes away."""
    import cbor2
    import json

    signed = sign_cose_sign1(manifest(), KP)
    tagged = cbor2.loads(signed)
    body = list(tagged.value)
    payload = json.loads(body[2].decode())
    payload["version"] = "0.1"
    body[2] = json.dumps(payload).encode()
    forged = cbor2.dumps(cbor2.CBORTag(tagged.tag, body), canonical=True)

    response = post(client(trust_store()), forged)
    assert response.json()["result"] == "INCOMPATIBLE_VERSION"


def test_a_revoked_manifest_is_revoked_over_http():
    store = RevocationStore()
    store.revoke(
        RevocationRecord(
            manifest_id=MANIFEST_ID,
            revoked_at=NOW,
            reason="key compromise",
            revoked_by="security@example",
        )
    )
    response = post(
        client(trust_store(), store), sign_cose_sign1(manifest(), KP)
    )
    assert response.json()["result"] == "REVOKED"


def test_the_caller_cannot_supply_keys_through_the_query_string():
    """Key material must not travel in a URL, so there is no parameter for it.

    A caller that tries gets the unauthenticated result, not a VALID one.
    """
    c = client()
    response = c.post(
        "/verify/cose",
        content=sign_cose_sign1(manifest(), KP),
        headers={"Content-Type": MEDIA_TYPE_MANIFEST_COSE},
        params={"trusted_keys": f"{KP.key_id}:{KP.public_b64url()}"},
    )
    assert response.json()["result"] == "UNVERIFIABLE"


def test_the_issuer_binding_is_enforced_over_http():
    ctx = trust_store(
        trusted_key_issuers={KP.key_id: ["spiffe://trust.example/issuer/payroll"]}
    )
    response = post(
        client(ctx), sign_cose_sign1(manifest(issuer="spiffe://trust.example/other"), KP)
    )
    assert response.json()["result"] == "MISMATCH"


def test_the_json_endpoint_is_unchanged():
    """Adding the COSE surface must not disturb the existing contract."""
    c = client(trust_store())
    response = c.post("/verify", json={"manifest_id": MANIFEST_ID})
    assert response.status_code == 404  # manifest_store is empty; route intact
