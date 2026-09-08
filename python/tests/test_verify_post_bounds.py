"""POST /verify (JSON) body-size and field-cardinality bounds - issue #383.

`POST /verify/cose` bounds its CBOR body before parsing it (see
test_cose_endpoint.py); this endpoint took a `VerifyRequest` Pydantic model
directly, so FastAPI would fully buffer and validate an arbitrarily large or
high-cardinality JSON body before `verify_manifest` ever ran. These tests
cover the fix: a shared byte cap on the raw body, and a shared entry-count
cap on `VerifyRequest`'s dict/set fields, mirroring the COSE endpoint's
defense-in-depth posture.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._signing import generate_ed25519
from agent_manifest._verify import (
    MAX_VERIFY_BODY_BYTES,
    MAX_VERIFY_COLLECTION_ENTRIES,
    RevocationStore,
    VerifyRequest,
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
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
        },
    }
    m.update(overrides)
    return m


def client(manifests=None, revocation_store=None):
    app = FastAPI()
    store = {MANIFEST_ID: manifest()} if manifests is None else manifests
    app.include_router(
        create_router(store, revocation_store or RevocationStore())
    )
    return TestClient(app)


# ---------------------------------------------------------------------------
# Body-size bound (mirrors POST /verify/cose)
# ---------------------------------------------------------------------------


def test_an_oversized_body_is_refused():
    huge = {"manifest_id": MANIFEST_ID, "trusted_keys": {"k": "v" * MAX_VERIFY_BODY_BYTES}}
    body = json.dumps(huge).encode()
    assert len(body) > MAX_VERIFY_BODY_BYTES
    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["detail"]["error_code"] == "VERIFY_REQUEST_TOO_LARGE"


def test_a_declared_content_length_cannot_be_used_to_smuggle_past_the_cap():
    """Unlike POST /verify/cose, verify_post never reads the Content-Length
    header at all - only the actual byte stream is counted. That means a
    lying (understated) Content-Length can't help a caller evade the cap
    (nothing ever trusts it in the first place), and this test's job is to
    confirm the stream-based cap alone is sufficient regardless of what the
    header claims."""
    huge = {"manifest_id": MANIFEST_ID, "trusted_keys": {"k": "v" * MAX_VERIFY_BODY_BYTES}}
    body = json.dumps(huge).encode()
    c = client()
    response = c.post(
        "/verify",
        content=body,
        headers={
            "Content-Type": "application/json",
            # understated on purpose - verify_post ignores this header either way
            "Content-Length": "10",
        },
    )
    assert response.status_code == 413


def test_a_body_at_exactly_the_limit_is_not_rejected_for_size():
    """The cap is `> MAX_VERIFY_BODY_BYTES`, not `>=`; a body landing exactly
    on the boundary should fail (if at all) on content, not size."""
    # Pad with a large, otherwise-harmless string value under the collection
    # cap (one entry) so only the byte-size boundary is being exercised.
    padding_key = "k"
    overhead = len(
        json.dumps({"manifest_id": MANIFEST_ID, "trusted_keys": {padding_key: ""}}).encode()
    )
    pad_len = max(0, MAX_VERIFY_BODY_BYTES - overhead)
    payload = {"manifest_id": MANIFEST_ID, "trusted_keys": {padding_key: "v" * pad_len}}
    body = json.dumps(payload).encode()
    assert len(body) <= MAX_VERIFY_BODY_BYTES
    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 200


def test_the_json_endpoint_still_accepts_normal_requests():
    """Streaming the body manually must not disturb the existing contract."""
    c = client()
    response = c.post("/verify", json={"manifest_id": MANIFEST_ID})
    assert response.status_code == 200
    assert response.json()["manifest_id"] == MANIFEST_ID


def test_manifest_not_found_is_still_reported_after_bounded_parsing():
    c = client({})
    response = c.post("/verify", json={"manifest_id": MANIFEST_ID})
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Content-Type enforcement
#
# verify_post takes a raw Request (to stream-cap the body before Pydantic
# parses it), which means FastAPI's own automatic content-type gate for a
# Pydantic-model body parameter no longer runs for this route. Without an
# explicit check, model_validate_json() would happily accept a JSON payload
# under any Content-Type (or none at all with an unexpected value), silently
# widening the documented application/json-only contract advertised in the
# OpenAPI schema.
# ---------------------------------------------------------------------------


def test_a_non_json_content_type_is_rejected_even_with_a_valid_json_body():
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 415
    assert response.json()["detail"]["error_code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_a_bogus_content_type_is_rejected():
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "not/a/real/type"}
    )
    assert response.status_code == 415


def test_form_encoded_content_type_is_rejected():
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post(
        "/verify",
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_a_json_vendor_subtype_is_accepted():
    """`application/vnd.api+json` and similar +json subtypes are valid JSON
    media types (RFC 6839) and must be accepted, matching what FastAPI's own
    body parsing does for a normal Pydantic-model parameter."""
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post(
        "/verify",
        content=body,
        headers={"Content-Type": "application/vnd.api+json"},
    )
    assert response.status_code == 200


def test_a_json_content_type_with_charset_parameter_is_accepted():
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post(
        "/verify",
        content=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 200


def test_a_missing_content_type_still_falls_back_to_json():
    """No Content-Type header at all is what FastAPI's default (non-strict)
    body parsing accepts for a Pydantic-model parameter; that must keep
    working exactly as before. httpx sends no Content-Type of its own for
    raw `content=bytes` (unlike `json=...`), so this genuinely exercises the
    header-absent path rather than an empty header value."""
    body = json.dumps({"manifest_id": MANIFEST_ID}).encode()
    c = client()
    response = c.post("/verify", content=body)
    assert response.status_code == 200

def test_malformed_json_is_a_422_not_a_server_error():
    c = client()
    response = c.post(
        "/verify", content=b"{not valid json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_validation_error_shape_matches_the_pre_fix_pydantic_body_contract():
    """`verify_post` used to take `VerifyRequest` directly, so FastAPI's own
    body validation produced errors with a leading "body" element in `loc`.
    Parsing the body by hand must not silently change that wire contract for
    existing callers that key off `detail[i]["loc"][0] == "body"`."""
    c = client()
    response = c.post("/verify", json={})  # missing required manifest_id
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail[0]["loc"] == ["body", "manifest_id"]
    assert detail[0]["type"] == "missing"
    # Deliberately dropped relative to FastAPI's default: `ctx` can carry a
    # non-serializable exception object, and `input` would echo the caller's
    # (potentially oversized) payload back in the response.
    assert "ctx" not in detail[0]
    assert "input" not in detail[0]


def test_the_json_request_body_schema_is_still_documented():
    """`verify_post` takes a raw `Request` now (to stream-cap the body before
    Pydantic parses it), which on its own would make FastAPI drop the request
    body from the generated OpenAPI schema entirely, since it can no longer
    infer it from a Pydantic-typed parameter. Callers, Swagger UI, and
    codegen tools still need to see what POST /verify accepts."""
    app = FastAPI()
    app.include_router(create_router({}, RevocationStore()))
    schema = app.openapi()
    request_body = schema["paths"]["/verify"]["post"].get("requestBody")
    assert request_body is not None, "POST /verify lost its documented request body"
    assert request_body["required"] is True
    body_schema = request_body["content"]["application/json"]["schema"]
    for field in (
        "manifest_id",
        "trusted_keys",
        "trusted_key_issuers",
        "delegation_public_keys",
        "approver_public_keys",
        "verified_transparency_entry_ids",
        "verified_transparency_receipt_hashes",
        "verified_attestation_manifest_hashes",
    ):
        assert field in body_schema["properties"], f"missing from documented schema: {field}"


def test_the_result_is_unaffected_by_the_new_bounds():
    """A normal, valid POST /verify call still behaves as before (v0.1
    detached-signature form, since Ed25519Signer.sign targets that format)."""
    from agent_manifest._signing import Ed25519Signer

    ctx_keys = {KP.key_id: KP.public_b64url()}
    m = manifest(version="0.1")
    del m["issuer"]
    m["signature"] = Ed25519Signer(KP).sign(m)
    c = client({MANIFEST_ID: m})
    response = c.post(
        "/verify", json={"manifest_id": MANIFEST_ID, "trusted_keys": ctx_keys}
    )
    assert response.status_code == 200
    assert response.json()["signature_verified"] is True


# ---------------------------------------------------------------------------
# Field-cardinality bound
# ---------------------------------------------------------------------------

FIELD_KINDS = {
    "trusted_keys": dict,
    "trusted_key_issuers": dict,
    "delegation_public_keys": dict,
    "approver_public_keys": dict,
    "verified_transparency_entry_ids": set,
    "verified_transparency_receipt_hashes": set,
    "verified_attestation_manifest_hashes": set,
}


@pytest.mark.parametrize("field_name,kind", FIELD_KINDS.items())
def test_each_unbounded_field_rejects_over_the_entry_ceiling(field_name, kind):
    """A small request body can still hide an oversized collection behind
    short keys/values - the entry-count cap catches that independently of
    the byte-size cap."""
    too_many = MAX_VERIFY_COLLECTION_ENTRIES + 1
    if kind is dict:
        if field_name == "trusted_key_issuers":
            value = {str(i): ["spiffe://x/y"] for i in range(too_many)}
        else:
            value = {str(i): "v" for i in range(too_many)}
    else:
        value = [str(i) for i in range(too_many)]

    with pytest.raises(Exception):
        VerifyRequest(manifest_id=MANIFEST_ID, **{field_name: value})


@pytest.mark.parametrize("field_name,kind", FIELD_KINDS.items())
def test_each_unbounded_field_accepts_at_the_entry_ceiling(field_name, kind):
    exactly = MAX_VERIFY_COLLECTION_ENTRIES
    if kind is dict:
        if field_name == "trusted_key_issuers":
            value = {str(i): ["spiffe://x/y"] for i in range(exactly)}
        else:
            value = {str(i): "v" for i in range(exactly)}
    else:
        value = [str(i) for i in range(exactly)]

    req = VerifyRequest(manifest_id=MANIFEST_ID, **{field_name: value})
    assert len(getattr(req, field_name)) == exactly


def test_an_oversized_collection_over_http_is_rejected_as_a_client_error():
    """The small-body / huge-collection shape the issue describes: short
    keys keep the wire body well under MAX_VERIFY_BODY_BYTES, so only the
    cardinality cap on VerifyRequest can catch it."""
    too_many = MAX_VERIFY_COLLECTION_ENTRIES + 1
    trusted_keys = {str(i): "v" for i in range(too_many)}
    body = json.dumps({"manifest_id": MANIFEST_ID, "trusted_keys": trusted_keys}).encode()
    assert len(body) < MAX_VERIFY_BODY_BYTES

    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_the_field_the_issue_report_missed_is_covered_too():
    """verified_attestation_manifest_hashes is a set[str] with the exact
    same shape as the two transparency hash sets sitting right above it in
    the model, and it reaches VerificationContext through the identical
    assignment in verify_post - but the original issue's field list didn't
    name it. A fix copied mechanically from that list would leave this one
    field open as a drop-in substitute for the six that got capped."""
    too_many = MAX_VERIFY_COLLECTION_ENTRIES + 1
    hashes = [str(i) for i in range(too_many)]
    body = json.dumps(
        {"manifest_id": MANIFEST_ID, "verified_attestation_manifest_hashes": hashes}
    ).encode()
    assert len(body) < MAX_VERIFY_BODY_BYTES

    c = client()
    response = c.post(
        "/verify", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


def test_transparency_and_attestation_hash_sets_are_also_capped():
    """The transparency/attestation hash sets belong to the family of
    fields the issue describes; confirm both are wired into the validator
    (the fixture list above already covers all three sets individually -
    this checks the model directly for the full field set the validator
    actually protects, including verified_attestation_manifest_hashes,
    which the original issue report's field list omitted but which has
    the identical unbounded set[str] shape)."""
    from agent_manifest._verify import VerifyRequest as VR

    validated_fields = set()
    for name, validator in VR.__pydantic_decorators__.field_validators.items():
        validated_fields.update(validator.info.fields)

    assert validated_fields == {
        "trusted_keys",
        "trusted_key_issuers",
        "delegation_public_keys",
        "approver_public_keys",
        "verified_transparency_entry_ids",
        "verified_transparency_receipt_hashes",
        "verified_attestation_manifest_hashes",
    }
