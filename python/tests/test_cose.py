"""COSE_Sign1 / COSE_Sign envelope tests - issue #243 phase 2.

Normative reference: spec/agent-manifest-cose-envelope-v0.2.md (ADR-0011).

The negative cases here are deliberately the ones only this envelope can
express - a tampered protected header, an alg substitution, a typ mismatch,
an unprotected header injected before verification - because those are what
phase 3 turns into portable AM-VEC vectors.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature

from agent_manifest._cose import (
    ALG_ED25519,
    ALG_EDDSA,
    ALG_ML_DSA_65,
    COSE_SIGN1_TAG,
    COSE_SIGN_TAG,
    HDR_ALG,
    HDR_CONTENT_TYPE,
    HDR_CRIT,
    HDR_KID,
    HDR_TYP,
    LABEL_APPROVALS,
    LABEL_ATTESTATION,
    MEDIA_TYPE_MANIFEST_COSE,
    MEDIA_TYPE_MANIFEST_JSON,
    CoseDowngradeError,
    CoseKeyError,
    CoseStructureError,
    CoseVersionError,
    attach_approvals,
    attach_attestation,
    attach_receipt,
    cose_payload,
    decode_cose_manifest,
    payload_hash,
    sign_cose_sign1,
    sign_cose_sign_hybrid,
    sign_manifest_cose,
    verify_cose_manifest,
)
from agent_manifest._signing import (
    AlgorithmUnavailableError,
    generate_ed25519,
    generate_hybrid,
    generate_ml_dsa65,
)
from agent_manifest._verify import (
    HitlResult,
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

from agent_manifest._signing import ml_dsa65_available

# ML-DSA-65 is provided by the SDK itself now - cryptography >= 47, or the
# liboqs bindings where a deployment still carries them - so the post-quantum
# half of this envelope is exercised with real FIPS 204 signatures rather
# than skipped.
require_pq = pytest.mark.skipif(
    not ml_dsa65_available(), reason="no ML-DSA-65 backend available"
)

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    CRYPTOGRAPHY_MLDSA = True
except ImportError:
    CRYPTOGRAPHY_MLDSA = False


@pytest.fixture
def pq_backend():
    """Kept as an explicit marker that a test needs a real ML-DSA-65 backend."""
    if not ml_dsa65_available():
        pytest.skip("no ML-DSA-65 backend available")
    return "sdk"

NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}


def base_manifest(**overrides):
    m = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.2",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA},
            "policy_bundle": {"hash": SHA_B},
            "model_identity": {
                "model_hash": None,
                "version": "claude-3",
                "deployment_type": "api",
            },
        },
    }
    m.update(overrides)
    return m


def base_context(**overrides):
    ctx = VerificationContext(
        system_prompt_hash=SHA,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def store():
    return RevocationStore()


def approval(**overrides):
    """A schema-valid HITL approval, authenticated by its own signature."""
    a = {
        "approval_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b60",
        "approver_id": "mailto:alice@example.com",
        "approver_identity_type": "email",
        "approver_role": "ciso",
        "approved_at": NOW.isoformat().replace("+00:00", "Z"),
        "approved_scope": {
            "artifacts": ["system_prompt"],
            "risk_tier": "high",
            "approval_duration_seconds": 3600,
        },
        "approval_signature": "c2ln",
        "approval_method": "hardware-key",
        "evidence_uri": "https://evidence.example/approvals/1",
    }
    a.update(overrides)
    return a


def parts(cose_bytes):
    """Return the decoded (tag, [protected_bytes, unprotected, payload, sig])."""
    tagged = cbor2.loads(cose_bytes)
    return tagged.tag, list(tagged.value)


def rebuild(tag, body):
    return cbor2.dumps(cbor2.CBORTag(tag, body), canonical=True)


# ---------------------------------------------------------------------------
# Structure (envelope spec sections 2 and 3)
# ---------------------------------------------------------------------------


def test_sign1_is_a_tagged_four_element_array():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    assert tag == COSE_SIGN1_TAG
    assert len(body) == 4
    protected, unprotected, payload, signature = body
    assert isinstance(protected, bytes)
    assert isinstance(payload, bytes)
    assert isinstance(signature, bytes)
    # Pinned encoding (ADR-0013): the unprotected header is a zero-length map,
    # never omitted. A three-element array is not a COSE_Sign1.
    assert unprotected == {}


def test_protected_header_carries_alg_kid_content_type_and_typ():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    assert header[HDR_ALG] == ALG_ED25519
    assert header[HDR_KID] == hashlib.sha256(KP.public_bytes).digest()
    assert header[HDR_CONTENT_TYPE] == MEDIA_TYPE_MANIFEST_JSON
    assert header[HDR_TYP] == MEDIA_TYPE_MANIFEST_COSE


def test_kid_is_the_v01_key_id_as_bytes():
    """A key registered for v0.1 keeps its identity across the migration."""
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    assert cbor2.loads(body[0])[HDR_KID].hex() == KP.key_id


def test_payload_is_the_canonical_json_of_the_manifest():
    manifest = base_manifest()
    _, body = parts(sign_cose_sign1(manifest, KP))
    assert body[2] == cose_payload(manifest)
    payload = json.loads(body[2].decode())
    assert payload["manifest_id"] == manifest["manifest_id"]
    assert payload["artifacts"]["system_prompt"] == {"hash": SHA}
    # Keys are in code-point order and null-valued optionals are excluded
    # (RFC 8785 and spec 4.3), which is what makes the bytes reproducible.
    assert body[2].index(b'"agent_id"') < body[2].index(b'"manifest_id"')
    assert "model_hash" not in payload["artifacts"]["model_identity"]


def test_payload_drops_fields_that_attach_after_signing():
    manifest = base_manifest(
        signature={"algorithm": "Ed25519"},
        attestation={"platform": "amd-sev-snp"},
        transparency_log_entry={"log_id": "x"},
        hitl_record={"required": True, "approvals": [{"approver_id": "a"}]},
    )
    payload = json.loads(cose_payload(manifest).decode())
    assert "signature" not in payload
    assert "attestation" not in payload
    assert "transparency_log_entry" not in payload
    # The HITL requirement stays signed; the approvals do not.
    assert payload["hitl_record"] == {"required": True}


def test_signing_is_deterministic_for_the_same_manifest_and_key():
    manifest = base_manifest()
    assert sign_cose_sign1(manifest, KP) == sign_cose_sign1(manifest, KP)


def test_signing_a_v01_manifest_is_refused():
    with pytest.raises(CoseVersionError):
        sign_cose_sign1(base_manifest(version="0.1"), KP)


# ---------------------------------------------------------------------------
# Verification, happy path
# ---------------------------------------------------------------------------


def test_roundtrip_verifies():
    result = verify_cose_manifest(sign_cose_sign1(base_manifest(), KP), TRUSTED_KEYS)
    assert result.verified is True
    assert result.algorithms == (ALG_ED25519,)
    assert result.signatures[0].key_id == KP.key_id
    assert result.signatures[0].algorithm_name == "Ed25519"
    assert result.manifest["agent_id"] == "spiffe://trust.example/agent/kyc/prod"


def test_manifest_hash_is_sha256_of_the_payload_bytes():
    """Envelope spec 5: hardware binds the payload bytes, with no subset rule."""
    manifest = base_manifest()
    signed = sign_cose_sign1(manifest, KP)
    result = verify_cose_manifest(signed, TRUSTED_KEYS)
    assert result.manifest_hash == payload_hash(cose_payload(manifest))
    assert result.manifest_hash == (
        "sha256:" + hashlib.sha256(result.payload).hexdigest()
    )


def test_no_trusted_keys_is_unverifiable_not_invalid():
    result = verify_cose_manifest(sign_cose_sign1(base_manifest(), KP), {})
    assert result.verified is False
    assert result.signatures[0].verified is False


def test_decode_never_reports_verified():
    result = decode_cose_manifest(sign_cose_sign1(base_manifest(), KP))
    assert result.verified is False
    assert result.manifest["manifest_id"] == base_manifest()["manifest_id"]


def test_sign_manifest_cose_dispatches_on_key_type():
    tag, _ = parts(sign_manifest_cose(base_manifest(), KP))
    assert tag == COSE_SIGN1_TAG


@require_pq
def test_ml_dsa_sign1_roundtrip(pq_backend):
    kp = generate_ml_dsa65()
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), kp)
    result = verify_cose_manifest(signed, {kp.key_id: kp.public_b64url()})
    assert result.verified is True
    assert result.algorithms == (ALG_ML_DSA_65,)


# ---------------------------------------------------------------------------
# Post-signing attachment (unprotected header)
# ---------------------------------------------------------------------------


def test_attaching_a_receipt_does_not_disturb_the_signature():
    signed = sign_cose_sign1(base_manifest(), KP)
    with_receipt = attach_receipt(signed, b"\xd2\x84fake-receipt")
    result = verify_cose_manifest(with_receipt, TRUSTED_KEYS)
    assert result.verified is True
    assert result.receipts == [b"\xd2\x84fake-receipt"]
    # The signed bytes are carried through untouched.
    assert parts(with_receipt)[1][0] == parts(signed)[1][0]
    assert parts(with_receipt)[1][2] == parts(signed)[1][2]
    assert parts(with_receipt)[1][3] == parts(signed)[1][3]


def test_receipts_accumulate():
    signed = attach_receipt(sign_cose_sign1(base_manifest(), KP), b"one")
    signed = attach_receipt(signed, b"two")
    assert verify_cose_manifest(signed, TRUSTED_KEYS).receipts == [b"one", b"two"]


def test_attestation_and_approvals_land_in_the_unprotected_header():
    signed = sign_cose_sign1(base_manifest(), KP)
    signed = attach_attestation(signed, {"platform": "amd-sev-snp"})
    signed = attach_approvals(signed, [{"approver_id": "a"}])
    result = verify_cose_manifest(signed, TRUSTED_KEYS)
    assert result.verified is True
    assert result.attestation == {"platform": "amd-sev-snp"}
    assert result.approvals == [{"approver_id": "a"}]
    assert set(result.unprotected) == {LABEL_ATTESTATION, LABEL_APPROVALS}


# ---------------------------------------------------------------------------
# Negative cases the v0.1 envelope cannot express
# ---------------------------------------------------------------------------


def test_untagged_structure_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    with pytest.raises(CoseStructureError, match="untagged"):
        verify_cose_manifest(cbor2.dumps(body, canonical=True), TRUSTED_KEYS)


def test_unexpected_tag_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    with pytest.raises(CoseStructureError, match="unexpected CBOR tag"):
        verify_cose_manifest(rebuild(17, body), TRUSTED_KEYS)


def test_tampered_protected_header_fails_the_signature():
    """alg is covered by the signature - the 0.6.0 class of bug is absent."""
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_ALG] = ALG_EDDSA  # same value, re-encoded map
    header["injected"] = "x"
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_alg_substitution_in_the_protected_header_fails_the_signature():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_ALG] = ALG_ML_DSA_65
    body[0] = cbor2.dumps(header, canonical=True)
    # Never accepted, either way. A build with an ML-DSA backend reaches the
    # fails it, because the protected bytes are inside the Sig_structure. A
    # signature and fails it; a build without one cannot perform ML-DSA-65
    # at all and says so, which
    # is UNVERIFIABLE (envelope spec 6 step 6) and still not a fallback to
    # the classical algorithm the manifest was actually signed with.
    with pytest.raises((InvalidSignature, AlgorithmUnavailableError)):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_alg_in_the_unprotected_header_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[1] = {HDR_ALG: ALG_EDDSA}
    with pytest.raises(CoseStructureError, match="unprotected header"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_absent_typ_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    del header[HDR_TYP]
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(CoseStructureError, match="typ"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_vendor_tree_typ_alias_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_TYP] = "application/vnd.agent-manifest+cose"
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(CoseStructureError, match="vendor-tree"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_wrong_content_type_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_CONTENT_TYPE] = "application/json"
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(CoseStructureError, match="content type"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_unknown_crit_entry_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_CRIT] = [HDR_ALG]
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(CoseStructureError, match="critical"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_tampered_payload_fails_the_signature():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    manifest = json.loads(body[2].decode())
    manifest["agent_id"] = "spiffe://trust.example/agent/attacker"
    body[2] = json.dumps(manifest).encode()
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_detached_payload_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = None
    with pytest.raises(CoseStructureError, match="inline not detached"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_trailing_bytes_are_rejected():
    signed = sign_cose_sign1(base_manifest(), KP)
    with pytest.raises(CoseStructureError, match="trailing bytes"):
        verify_cose_manifest(signed + b"\x00", TRUSTED_KEYS)


def test_empty_protected_header_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[0] = b""
    with pytest.raises(CoseStructureError, match="empty"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_unknown_alg_code_point_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    header[HDR_ALG] = -7  # ES256, not registered by this profile
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(CoseStructureError, match="unknown alg"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_unknown_kid_is_rejected():
    other = generate_ed25519()
    signed = sign_cose_sign1(base_manifest(), other)
    with pytest.raises(CoseKeyError, match="not in trusted_keys"):
        verify_cose_manifest(signed, TRUSTED_KEYS)


def test_post_quantum_profile_with_a_classical_signature_is_a_downgrade():
    """The bug shipped in v0.1 and fixed in 0.6.0, now unrepresentable."""
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), KP)
    with pytest.raises(CoseDowngradeError, match="post-quantum"):
        verify_cose_manifest(signed, TRUSTED_KEYS)


def test_downgrade_is_caught_without_any_trusted_keys():
    """Profile posture is checked whether or not this party holds the key."""
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), KP)
    with pytest.raises(CoseDowngradeError):
        verify_cose_manifest(signed, {})


def test_a_v01_payload_is_routed_away_from_this_envelope():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    manifest = json.loads(body[2].decode())
    manifest["version"] = "0.1"
    body[2] = json.dumps(manifest).encode()
    with pytest.raises(CoseVersionError, match="0.1"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_payload_that_is_not_json_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = b"\xff\xfe not json"
    with pytest.raises(CoseStructureError, match="JSON"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_duplicate_algorithm_entries_in_cose_sign_are_rejected():
    """Two entries for one algorithm cannot make a hybrid signature stronger."""
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    entry_protected = cbor2.dumps(
        {HDR_ALG: ALG_EDDSA, HDR_KID: hashlib.sha256(KP.public_bytes).digest()},
        canonical=True,
    )
    forged = rebuild(
        COSE_SIGN_TAG,
        [
            body_protected,
            {},
            body[2],
            [[entry_protected, {}, body[3]], [entry_protected, {}, body[3]]],
        ],
    )
    with pytest.raises(CoseStructureError, match="more than one"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


def test_cose_sign_with_no_signature_entries_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    forged = rebuild(COSE_SIGN_TAG, [body_protected, {}, body[2], []])
    with pytest.raises(CoseStructureError, match="no signature entries"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


# ---------------------------------------------------------------------------
# COSE_Sign structure
#
# The Sig_structure with a body header and a per-signature header, entry
# ordering, and the rule that every entry must verify. Real ML-DSA-65
# throughout, through whichever backend the SDK found.
# ---------------------------------------------------------------------------


def hybrid_trusted(kp):
    return {
        kp.ed25519.key_id: kp.ed25519.public_b64url(),
        kp.ml_dsa65.key_id: kp.ml_dsa65.public_b64url(),
    }


@require_pq
def test_cose_sign_carries_typ_in_the_body_and_alg_per_signature(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    tag, body = parts(signed)
    assert tag == COSE_SIGN_TAG
    body_header = cbor2.loads(body[0])
    assert body_header[HDR_TYP] == MEDIA_TYPE_MANIFEST_COSE
    assert body_header[HDR_CONTENT_TYPE] == MEDIA_TYPE_MANIFEST_JSON
    assert HDR_ALG not in body_header
    assert [cbor2.loads(e[0])[HDR_ALG] for e in body[3]] == [ALG_ED25519, ALG_ML_DSA_65]
    assert [cbor2.loads(e[0])[HDR_KID] for e in body[3]] == [
        hashlib.sha256(kp.ed25519.public_bytes).digest(),
        hashlib.sha256(kp.ml_dsa65.public_key_bytes).digest(),
    ]


@require_pq
def test_cose_sign_verifies_every_entry(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    result = verify_cose_manifest(signed, hybrid_trusted(kp))
    assert result.verified is True
    assert result.algorithms == (ALG_ED25519, ALG_ML_DSA_65)


@require_pq
def test_cose_sign_entries_cover_the_same_payload(pq_backend):
    kp = generate_hybrid()
    """The structure guarantees it - there is one payload, not two objects."""
    _, body = parts(
        sign_cose_sign_hybrid(base_manifest(crypto_profile="post-quantum"), kp)
    )
    assert body[2] == cose_payload(base_manifest(crypto_profile="post-quantum"))
    assert len(body[3]) == 2


@require_pq
def test_cose_sign_rejects_a_tampered_entry(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    tag, body = parts(signed)
    entries = [list(e) for e in body[3]]
    entries[1][2] = b"\x00" * len(entries[1][2])
    body[3] = entries
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), hybrid_trusted(kp))


@require_pq
def test_cose_sign_requires_a_trusted_key_for_every_entry(pq_backend):
    kp = generate_hybrid()
    """No falling back to the entry whose key happens to be held."""
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    classical_only = {kp.ed25519.key_id: kp.ed25519.public_b64url()}
    with pytest.raises(CoseKeyError):
        verify_cose_manifest(signed, classical_only)


@require_pq
def test_cose_sign_signature_does_not_transplant_between_entries(pq_backend):
    kp = generate_hybrid()
    """Each entry's own protected header is inside its Sig_structure."""
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    tag, body = parts(signed)
    entries = [list(e) for e in body[3]]
    # Give the PQ entry the classical entry's protected header bytes.
    entries[1][0] = entries[0][0]
    body[3] = entries
    with pytest.raises((InvalidSignature, CoseStructureError)):
        verify_cose_manifest(rebuild(tag, body), hybrid_trusted(kp))


# ---------------------------------------------------------------------------
# Hybrid (COSE_Sign with two signers), against a real ML-DSA-65
# ---------------------------------------------------------------------------


@require_pq
def test_hybrid_is_one_cose_sign_with_two_signers(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    tag, body = parts(signed)
    assert tag == COSE_SIGN_TAG
    assert len(body[3]) == 2
    # typ and content type in the body header, alg and kid per signature.
    body_header = cbor2.loads(body[0])
    assert body_header[HDR_TYP] == MEDIA_TYPE_MANIFEST_COSE
    assert HDR_ALG not in body_header
    assert [cbor2.loads(e[0])[HDR_ALG] for e in body[3]] == [ALG_ED25519, ALG_ML_DSA_65]


@require_pq
def test_hybrid_verifies_both_entries_against_component_keys(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    trusted = {
        kp.ed25519.key_id: kp.ed25519.public_b64url(),
        kp.ml_dsa65.key_id: kp.ml_dsa65.public_b64url(),
    }
    result = verify_cose_manifest(signed, trusted)
    assert result.verified is True
    assert result.algorithms == (ALG_ED25519, ALG_ML_DSA_65)


@require_pq
def test_ml_dsa_signature_verifies_under_an_independent_implementation(pq_backend):
    """The Sig_structure is right, checked without this module's verifier.

    Rebuilds RFC 9052 section 4.4 by hand from the object as parsed, then
    verifies the raw signature with cryptography's ML-DSA-65 directly. If
    ``_cose`` built the wrong bytes, this fails even though its own
    round-trip would pass.
    """
    if not CRYPTOGRAPHY_MLDSA:
        pytest.skip("cryptography has no ML-DSA")
    kp = generate_ml_dsa65()
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), kp)
    _, body = parts(signed)
    protected, _, payload, signature = body

    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    _mldsa.MLDSA65PublicKey.from_public_bytes(kp.public_key_bytes).verify(
        signature, to_be_signed
    )  # raises on failure

    # And the same bytes must not verify over anything else.
    with pytest.raises(Exception):
        _mldsa.MLDSA65PublicKey.from_public_bytes(kp.public_key_bytes).verify(
            signature, payload
        )


def test_ed25519_signature_verifies_under_an_independent_implementation():
    """Same check for the classical entry, straight through cryptography."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signed = sign_cose_sign1(base_manifest(), KP)
    _, body = parts(signed)
    protected, _, payload, signature = body
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
    Ed25519PublicKey.from_public_bytes(KP.public_bytes).verify(signature, to_be_signed)

    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(KP.public_bytes).verify(signature, payload)


@require_pq
def test_hybrid_entries_verify_under_independent_implementations(pq_backend):
    """Both COSE_Sign entries, each over its own Sig_structure, checked raw."""
    if not CRYPTOGRAPHY_MLDSA:
        pytest.skip("cryptography has no ML-DSA")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    _, body = parts(signed)
    body_protected, _, payload, entries = body

    ed_protected, _, ed_sig = entries[0]
    Ed25519PublicKey.from_public_bytes(kp.ed25519.public_bytes).verify(
        ed_sig,
        cbor2.dumps(
            ["Signature", body_protected, ed_protected, b"", payload], canonical=True
        ),
    )

    pq_protected, _, pq_sig = entries[1]
    _mldsa.MLDSA65PublicKey.from_public_bytes(kp.ml_dsa65.public_key_bytes).verify(
        pq_sig,
        cbor2.dumps(
            ["Signature", body_protected, pq_protected, b"", payload], canonical=True
        ),
    )


@require_pq
def test_ml_dsa_key_sizes_are_fips_204_ml_dsa_65(pq_backend):
    """Guards against a profile silently signing with the wrong parameter set."""
    kp = generate_ml_dsa65()
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), kp)
    _, body = parts(signed)
    assert len(kp.public_key_bytes) == 1952  # FIPS 204 ML-DSA-65 public key
    assert len(body[3]) == 3309  # FIPS 204 ML-DSA-65 signature


@require_pq
def test_hybrid_rejects_a_tampered_pq_entry_rather_than_falling_back(pq_backend):
    kp = generate_hybrid()
    signed = sign_cose_sign_hybrid(
        base_manifest(crypto_profile="post-quantum"), kp
    )
    tag, body = parts(signed)
    entries = list(body[3])
    entries[1] = [entries[1][0], {}, b"\x00" * len(entries[1][2])]
    body[3] = entries
    trusted = {
        kp.ed25519.key_id: kp.ed25519.public_b64url(),
        kp.ml_dsa65.key_id: kp.ml_dsa65.public_b64url(),
    }
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), trusted)


# ---------------------------------------------------------------------------
# Version-gated routing through the verification engine
# ---------------------------------------------------------------------------


def test_engine_verifies_a_cose_manifest():
    result = verify_manifest(
        sign_cose_sign1(base_manifest(), KP), base_context(), store()
    )
    assert result.result == OverallResult.VALID
    assert result.signature_verified is True


def test_engine_warns_when_no_receipt_is_attached():
    result = verify_manifest(
        sign_cose_sign1(base_manifest(), KP), base_context(), store()
    )
    assert any("transparency receipt" in w for w in result.warnings)


def test_engine_reports_unverifiable_without_trusted_keys():
    result = verify_manifest(
        sign_cose_sign1(base_manifest(), KP),
        base_context(trusted_keys={}),
        store(),
    )
    assert result.result == OverallResult.UNVERIFIABLE
    assert result.signature_verified is False


def test_engine_reports_mismatch_on_a_tampered_payload():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    manifest = json.loads(body[2].decode())
    manifest["expires_at"] = (NOW + timedelta(days=3650)).isoformat().replace(
        "+00:00", "Z"
    )
    body[2] = json.dumps(manifest).encode()
    result = verify_manifest(rebuild(tag, body), base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert result.mismatch_details[0].field == "signature"


def test_engine_reports_incompatible_version_for_a_v01_payload():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    manifest = json.loads(body[2].decode())
    manifest["version"] = "0.1"
    body[2] = json.dumps(manifest).encode()
    result = verify_manifest(rebuild(tag, body), base_context(), store())
    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.manifest_id == base_manifest()["manifest_id"]


def test_engine_still_verifies_a_v01_dict_unchanged():
    """The version gate is the point: existing records keep verifying."""
    from agent_manifest._signing import Ed25519Signer

    manifest = base_manifest(version="0.1")
    manifest["signature"] = Ed25519Signer(KP).sign(manifest)
    result = verify_manifest(manifest, base_context(), store())
    assert result.result == OverallResult.VALID


def test_a_bare_v02_dict_has_no_signature():
    """v0.2 has no signature field - the COSE structure is the signature."""
    result = verify_manifest(base_manifest(), base_context(), store())
    assert result.result == OverallResult.SIGNATURE_MISSING


def test_engine_binds_attestation_to_the_payload_hash():
    manifest = base_manifest()
    signed = sign_cose_sign1(manifest, KP)
    signed = attach_attestation(
        signed,
        {
            "platform": "amd-sev-snp",
            "manifest_hash_in_report": payload_hash(cose_payload(manifest)),
        },
    )
    result = verify_manifest(signed, base_context(enforce_attestation=True), store())
    assert result.attestation_verified is True
    assert result.result == OverallResult.VALID


def test_engine_rejects_an_attestation_bound_to_other_bytes():
    signed = sign_cose_sign1(base_manifest(), KP)
    signed = attach_attestation(
        signed,
        {"platform": "amd-sev-snp", "manifest_hash_in_report": "sha256:" + "c" * 64},
    )
    result = verify_manifest(signed, base_context(enforce_attestation=True), store())
    assert result.attestation_verified is False
    assert result.result == OverallResult.MISMATCH


def test_engine_evaluates_approvals_from_the_unprotected_header():
    manifest = base_manifest(hitl_record={"required": True})
    signed = sign_cose_sign1(manifest, KP)
    signed = attach_approvals(signed, [approval()])
    result = verify_manifest(signed, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.APPROVED


def test_signed_hitl_requirement_cannot_be_satisfied_by_editing_the_header():
    """Approvals are unsigned; the requirement they satisfy is not."""
    manifest = base_manifest(hitl_record={"required": True})
    signed = attach_approvals(sign_cose_sign1(manifest, KP), [])
    result = verify_manifest(signed, base_context(enforce_hitl=True), store())
    assert result.fields_verified.hitl_record == HitlResult.MISSING
    assert result.result == OverallResult.MISMATCH


# ---------------------------------------------------------------------------
# Malformed input
#
# Every branch below is a rejection path in the parser. They are tested for
# the same reason the parser has them: a verifier reads untrusted bytes, and
# a reject path that is never exercised is a reject path nobody knows works.
# ---------------------------------------------------------------------------


def sign1_body(**over):
    """A structurally valid COSE_Sign1 body, with fields replaceable."""
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    fields = {"protected": body[0], "unprotected": body[1], "payload": body[2],
              "signature": body[3]}
    fields.update(over)
    return [fields["protected"], fields["unprotected"], fields["payload"],
            fields["signature"]]


def protected_with(**over):
    """The protected header bytes, with parameters replaced or removed."""
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    header = cbor2.loads(body[0])
    for k, v in over.items():
        label = {"alg": HDR_ALG, "crit": HDR_CRIT, "cty": HDR_CONTENT_TYPE,
                 "kid": HDR_KID, "typ": HDR_TYP}[k]
        if v is None:
            header.pop(label, None)
        else:
            header[label] = v
    return cbor2.dumps(header, canonical=True)


def test_a_non_bytes_object_is_rejected():
    with pytest.raises(CoseStructureError, match="must be bytes"):
        verify_cose_manifest("not bytes", TRUSTED_KEYS)


def test_truncated_cbor_is_rejected():
    # An array header promising two items, with one item present.
    with pytest.raises(CoseStructureError, match="not valid CBOR"):
        verify_cose_manifest(b"\x82\x01", TRUSTED_KEYS)


def test_a_bare_break_byte_is_rejected():
    """cbor2 decodes 0xff to a break sentinel rather than raising, so the
    untagged-structure check is what has to catch it."""
    with pytest.raises(CoseStructureError, match="untagged"):
        verify_cose_manifest(b"\xff", TRUSTED_KEYS)


def test_deeply_nested_cbor_is_rejected_not_crashed():
    """DOS-006: nesting must produce a verdict, never a RecursionError."""
    bomb = b"\xd2" + b"\x81" * 10_000 + b"\x00"
    with pytest.raises(CoseStructureError):
        verify_cose_manifest(bomb, TRUSTED_KEYS)


def test_a_body_that_is_not_four_elements_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    with pytest.raises(CoseStructureError, match="four-element array"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body[:3]), TRUSTED_KEYS)


def test_a_non_bytes_protected_header_is_rejected():
    body = sign1_body(protected=123)
    with pytest.raises(CoseStructureError, match="protected header must be a byte string"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_non_map_unprotected_header_is_rejected():
    body = sign1_body(unprotected=[1, 2])
    with pytest.raises(CoseStructureError, match="unprotected header must be a map"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_protected_header_that_is_not_cbor_is_rejected():
    body = sign1_body(protected=b"\x82\x01")
    with pytest.raises(CoseStructureError, match="not valid CBOR"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_protected_header_that_is_not_a_map_is_rejected():
    body = sign1_body(protected=cbor2.dumps(42))
    with pytest.raises(CoseStructureError, match="must be a map"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_malformed_crit_is_rejected():
    body = sign1_body(protected=protected_with(crit=[]))
    with pytest.raises(CoseStructureError, match="crit must be a non-empty array"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_an_absent_alg_is_rejected():
    body = sign1_body(protected=protected_with(alg=None))
    with pytest.raises(CoseStructureError, match="no alg"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_non_integer_alg_is_rejected():
    body = sign1_body(protected=protected_with(alg="EdDSA"))
    with pytest.raises(CoseStructureError, match="alg must be an integer"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_boolean_alg_is_rejected():
    """bool is an int in Python; the code point check must not accept True."""
    body = sign1_body(protected=protected_with(alg=True))
    with pytest.raises(CoseStructureError, match="alg must be an integer"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_an_absent_kid_is_rejected():
    body = sign1_body(protected=protected_with(kid=None))
    with pytest.raises(CoseStructureError, match="no kid"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_non_bytes_signature_is_rejected():
    body = sign1_body(signature="not bytes")
    with pytest.raises(CoseStructureError, match="signature must be a byte string"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_payload_that_is_not_a_json_object_is_rejected():
    body = sign1_body(payload=json.dumps([1, 2, 3]).encode())
    with pytest.raises(CoseStructureError, match="JSON object"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_an_unknown_future_version_is_incompatible_not_invalid():
    manifest = base_manifest()
    manifest["version"] = "9.9"
    body = sign1_body(payload=json.dumps(manifest).encode())
    with pytest.raises(CoseVersionError, match="9.9"):
        verify_cose_manifest(rebuild(COSE_SIGN1_TAG, body), TRUSTED_KEYS)


def test_a_cose_sign_entry_that_is_not_three_elements_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    forged = rebuild(COSE_SIGN_TAG, [body_protected, {}, body[2], [[b"", {}]]])
    with pytest.raises(CoseStructureError, match="three-element array"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


def test_a_cose_sign_entry_with_a_non_bytes_protected_header_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    forged = rebuild(COSE_SIGN_TAG, [body_protected, {}, body[2], [[7, {}, b""]]])
    with pytest.raises(CoseStructureError, match="protected header must be a byte string"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


def test_a_cose_sign_entry_with_a_non_map_unprotected_header_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    entry_protected = cbor2.dumps({HDR_ALG: ALG_EDDSA, HDR_KID: b"k"}, canonical=True)
    forged = rebuild(
        COSE_SIGN_TAG, [body_protected, {}, body[2], [[entry_protected, 9, b""]]]
    )
    with pytest.raises(CoseStructureError, match="unprotected header must be a map"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


@require_pq
def test_sign_manifest_cose_dispatches_hybrid_to_cose_sign(pq_backend):
    tag, _ = parts(sign_manifest_cose(
        base_manifest(crypto_profile="post-quantum"), generate_hybrid()
    ))
    assert tag == COSE_SIGN_TAG


@require_pq
def test_a_tampered_ml_dsa_signature_is_rejected(pq_backend):
    """The ML-DSA verify-returns-false path, on a single-signer envelope."""
    kp = generate_ml_dsa65()
    signed = sign_cose_sign1(base_manifest(crypto_profile="post-quantum"), kp)
    tag, body = parts(signed)
    body[3] = bytes(len(body[3]))  # a correctly sized, wrong signature
    with pytest.raises(InvalidSignature, match="ML-DSA-65"):
        verify_cose_manifest(
            rebuild(tag, body), {kp.key_id: kp.public_b64url()}
        )


def test_a_cose_sign_entry_with_a_non_bytes_signature_is_rejected():
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    entry_protected = cbor2.dumps(
        {HDR_ALG: ALG_EDDSA, HDR_KID: hashlib.sha256(KP.public_bytes).digest()},
        canonical=True,
    )
    forged = rebuild(
        COSE_SIGN_TAG,
        [body_protected, {}, body[2], [[entry_protected, {}, "not bytes"]]],
    )
    with pytest.raises(CoseStructureError, match="signature must be a byte string"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


def test_a_wrong_length_ed25519_signature_is_rejected_before_openssl():
    """SIGN-001: fixed-length check before the bytes reach the primitive."""
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[3] = body[3][:32]  # half an Ed25519 signature
    with pytest.raises(InvalidSignature, match="must be 64 bytes"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


# ---------------------------------------------------------------------------
# RFC 9864: EdDSA (-8) is deprecated in favour of the fully-specified
# Ed25519 (-19). The SDK signs with -8, because that is what the envelope
# specification requires, and accepts both, so a verifier shipped today
# already works on the day the specification moves.
# ---------------------------------------------------------------------------


def ed25519_envelope_with_alg(alg, keypair=KP, manifest=None):
    """Sign a COSE_Sign1 whose protected header declares *alg*."""
    from agent_manifest._cose import _sig_structure_sign1

    payload = cose_payload(manifest or base_manifest())
    protected = cbor2.dumps(
        {
            HDR_ALG: alg,
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_KID: hashlib.sha256(keypair.public_bytes).digest(),
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )
    signature = keypair.private_key.sign(_sig_structure_sign1(protected, payload))
    return rebuild(COSE_SIGN1_TAG, [protected, {}, payload, signature])


def test_the_sdk_signs_with_the_fully_specified_identifier():
    """ADR-0014: producers sign -19; -8 is verified but never emitted."""
    _, body = parts(sign_cose_sign1(base_manifest(), KP))
    assert cbor2.loads(body[0])[HDR_ALG] == ALG_ED25519


def test_a_deprecated_eddsa_envelope_still_verifies():
    """An existing manifest signed under -8 stays verifiable indefinitely:
    audit records outlive the identifier they were signed under."""
    result = verify_cose_manifest(ed25519_envelope_with_alg(ALG_EDDSA), TRUSTED_KEYS)
    assert result.verified is True
    assert result.algorithms == (ALG_EDDSA,)
    assert result.signatures[0].algorithm_name == "EdDSA"


def test_the_engine_accepts_a_deprecated_eddsa_manifest():
    result = verify_manifest(
        ed25519_envelope_with_alg(ALG_EDDSA), base_context(), store()
    )
    assert result.result == OverallResult.VALID


def test_a_fully_specified_ed25519_alg_verifies():
    result = verify_cose_manifest(
        ed25519_envelope_with_alg(ALG_ED25519), TRUSTED_KEYS
    )
    assert result.verified is True
    assert result.algorithms == (ALG_ED25519,)
    assert result.signatures[0].algorithm_name == "Ed25519"


def test_a_fully_specified_ed25519_envelope_is_still_tamper_evident():
    envelope = ed25519_envelope_with_alg(ALG_ED25519)
    tag, body = parts(envelope)
    manifest = json.loads(body[2].decode())
    manifest["agent_id"] = "spiffe://trust.example/agent/attacker"
    body[2] = json.dumps(manifest).encode()
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_swapping_between_the_two_ed25519_identifiers_breaks_the_signature():
    """Both are accepted, but neither is interchangeable after signing: alg is
    inside the protected header the signature covers."""
    envelope = ed25519_envelope_with_alg(ALG_ED25519)
    tag, body = parts(envelope)
    header = cbor2.loads(body[0])
    header[HDR_ALG] = ALG_EDDSA
    body[0] = cbor2.dumps(header, canonical=True)
    with pytest.raises(InvalidSignature):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_a_post_quantum_profile_is_not_satisfied_by_ed25519_either_spelling():
    envelope = ed25519_envelope_with_alg(
        ALG_ED25519, manifest=base_manifest(crypto_profile="post-quantum")
    )
    with pytest.raises(CoseDowngradeError):
        verify_cose_manifest(envelope, TRUSTED_KEYS)


def test_the_engine_accepts_a_fully_specified_ed25519_manifest():
    result = verify_manifest(
        ed25519_envelope_with_alg(ALG_ED25519), base_context(), store()
    )
    assert result.result == OverallResult.VALID
    assert result.signature_verified is True


def test_two_spellings_of_ed25519_are_not_two_signers():
    """A COSE_Sign carrying -8 and -19 entries is one algorithm twice, and
    must not be able to pass as a hybrid signature."""
    from agent_manifest._cose import _sig_structure_sign

    payload = cose_payload(base_manifest())
    body_protected = cbor2.dumps(
        {HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON, HDR_TYP: MEDIA_TYPE_MANIFEST_COSE},
        canonical=True,
    )
    entries = []
    for alg in (ALG_EDDSA, ALG_ED25519):
        sign_protected = cbor2.dumps(
            {HDR_ALG: alg, HDR_KID: hashlib.sha256(KP.public_bytes).digest()},
            canonical=True,
        )
        sig = KP.private_key.sign(
            _sig_structure_sign(body_protected, sign_protected, payload)
        )
        entries.append([sign_protected, {}, sig])
    forged = rebuild(COSE_SIGN_TAG, [body_protected, {}, payload, entries])
    with pytest.raises(CoseStructureError, match="more than one"):
        verify_cose_manifest(forged, TRUSTED_KEYS)


# ---------------------------------------------------------------------------
# Policy and parsing hardening
#
# These three came out of an adversarial pass comparing the COSE path against
# what the v0.1 path already enforces. The first was a genuine regression.
# ---------------------------------------------------------------------------


def test_a_trusted_key_may_not_sign_for_an_unauthorized_issuer():
    """The v0.1 path rejects this; the COSE path must not be weaker.

    trusted_key_issuers binds a key to the issuers it may sign for. Without
    this check, any trusted key could sign a manifest claiming any issuer,
    which is precisely the blast radius that binding exists to limit.
    """
    manifest = base_manifest(issuer="spiffe://trust.example/issuer/other")
    ctx = base_context(
        trusted_key_issuers={KP.key_id: ["spiffe://trust.example/issuer/payroll"]}
    )
    result = verify_manifest(sign_cose_sign1(manifest, KP), ctx, store())
    assert result.result == OverallResult.MISMATCH
    assert [d.field for d in result.mismatch_details] == ["signature.issuer"]


def test_an_authorized_issuer_still_verifies():
    manifest = base_manifest(issuer="spiffe://trust.example/issuer/payroll")
    ctx = base_context(
        trusted_key_issuers={KP.key_id: ["spiffe://trust.example/issuer/payroll"]}
    )
    result = verify_manifest(sign_cose_sign1(manifest, KP), ctx, store())
    assert result.result == OverallResult.VALID


@require_pq
def test_every_hybrid_signer_must_be_authorized_for_the_issuer(pq_backend):
    """One authorized component key must not carry an unauthorized one."""
    kp = generate_hybrid()
    manifest = base_manifest(
        issuer="spiffe://trust.example/issuer/payroll", crypto_profile="post-quantum"
    )
    ctx = base_context(
        trusted_keys={
            kp.ed25519.key_id: kp.ed25519.public_b64url(),
            kp.ml_dsa65.key_id: kp.ml_dsa65.public_b64url(),
        },
        trusted_key_issuers={
            kp.ed25519.key_id: ["spiffe://trust.example/issuer/payroll"],
            # the ML-DSA key is authorized for a different issuer
            kp.ml_dsa65.key_id: ["spiffe://trust.example/issuer/other"],
        },
    )
    result = verify_manifest(sign_cose_sign_hybrid(manifest, kp), ctx, store())
    assert result.result == OverallResult.MISMATCH


def test_a_payload_with_duplicate_member_names_is_rejected():
    """Parsers disagree about which value wins, so two verifiers could read
    different manifests out of the same signed bytes."""
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = b'{"manifest_id":"x","version":"0.2","version":"0.1"}'
    with pytest.raises(CoseStructureError, match="duplicate member name"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_a_payload_containing_nan_is_rejected():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = b'{"manifest_id":"x","version":"0.2","drift":NaN}'
    with pytest.raises(CoseStructureError, match="RFC 8785"):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_a_deeply_nested_payload_returns_a_verdict_rather_than_unwinding():
    """DOS-006: untrusted input must never escape as an exception."""
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = (('{"a":' * 5000) + "1" + ("}" * 5000)).encode()
    result = verify_manifest(rebuild(tag, body), base_context(), store())
    assert result.result == OverallResult.MISMATCH


def test_a_deeply_nested_payload_is_a_structure_error_not_a_crash():
    tag, body = parts(sign_cose_sign1(base_manifest(), KP))
    body[2] = (('{"a":' * 5000) + "1" + ("}" * 5000)).encode()
    with pytest.raises(CoseStructureError):
        verify_cose_manifest(rebuild(tag, body), TRUSTED_KEYS)


def test_a_v02_manifest_may_not_use_the_v01_envelope():
    """The version gate has to bind in both directions.

    A manifest claiming 0.2 while carrying a detached signature block is using
    the envelope with the unauthenticated algorithm identifier and the
    canonicalize-before-verify step that ADR-0011 moved away from. Accepting it
    would make the gate advisory and leave the phase 5 deprecation with nothing
    to enforce.
    """
    from agent_manifest._signing import Ed25519Signer

    manifest = base_manifest()  # version 0.2
    manifest["signature"] = Ed25519Signer(KP).sign(manifest)
    result = verify_manifest(manifest, base_context(), store())
    assert result.result == OverallResult.MISMATCH
    assert result.signature_verified is False
    assert result.mismatch_details[0].field == "signature"
    assert "0.2" in result.mismatch_details[0].expected_hash


def test_a_v01_manifest_with_the_v01_envelope_is_unaffected():
    """The check must not touch the path every existing record uses."""
    from agent_manifest._signing import Ed25519Signer

    manifest = base_manifest(version="0.1")
    manifest["signature"] = Ed25519Signer(KP).sign(manifest)
    assert verify_manifest(manifest, base_context(), store()).result == (
        OverallResult.VALID
    )
