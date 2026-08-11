"""Spec 3.9: declared intent, and why it is the issuer who declares it.

The requirement this exists for (AARM R2/R3) wants the action evaluated against
the agent's stated intent. The load-bearing decision is *who states it*. An
intent the governed agent asserts about itself proves nothing, because an agent
that wants to do X declares X. So intent is carried inside the issuer's signature,
where the running agent cannot choose or revise it.

Two properties are tested hardest:

1. **It is covered by the signature.** An intent the signature does not cover is
   an intent anyone downstream can rewrite, which would make the whole field
   decorative.
2. **Adding it broke nothing.** `signing_pre_image` omits absent fields, so a
   manifest with no `intent` must produce byte-identical pre-image to before the
   field existed, and its signature must still verify.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_manifest import (
    SIGNED_FIELDS,
    DeclaredIntent,
    intent_hash,
    signing_pre_image,
)

STATEMENT = "Reconcile supplier invoices against the general ledger."


def _manifest(**extra: object) -> dict:
    manifest = {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": "spiffe://trust.example/agent/reconciler/prod",
        "version": "0.2",
        "issued_at": "2026-08-11T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "issuer": "spiffe://trust.example/manifest-authority",
        "crypto_profile": "standard",
        "artifacts": {
            "policy_bundle": {"hash": "sha256:" + "ab" * 32, "policy_language": "cedar"},
        },
    }
    manifest.update(extra)
    return manifest


# --------------------------------------------------------------------------
# The signature must cover it
# --------------------------------------------------------------------------


def test_intent_is_in_the_signed_field_set() -> None:
    assert "intent" in SIGNED_FIELDS


def test_intent_reaches_the_signing_pre_image() -> None:
    pre = signing_pre_image(_manifest(intent={"statement": STATEMENT}))
    assert STATEMENT.encode() in pre


def test_rewriting_the_intent_changes_the_pre_image() -> None:
    """The property that makes the field worth having: an intent the issuer did
    not sign cannot be substituted for one it did."""
    honest = signing_pre_image(_manifest(intent={"statement": STATEMENT}))
    tampered = signing_pre_image(_manifest(intent={"statement": "Do anything."}))
    assert honest != tampered


def test_a_tampered_intent_fails_signature_verification() -> None:
    """End to end, through the real signing path rather than the pre-image alone."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    manifest = _manifest(intent={"statement": STATEMENT})
    signature = private.sign(signing_pre_image(manifest))

    # As issued: verifies.
    private.public_key().verify(signature, signing_pre_image(manifest))

    # Someone downstream broadens the intent and keeps the issuer's signature.
    manifest["intent"] = {"statement": "Do anything the operator asks."}
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        private.public_key().verify(signature, signing_pre_image(manifest))
    assert public  # the key identity is unchanged; only the intent moved


# --------------------------------------------------------------------------
# Adding the field broke nothing
# --------------------------------------------------------------------------


def test_a_manifest_without_intent_is_unchanged_by_the_new_field() -> None:
    """Absent fields are omitted from the pre-image, so every signature issued
    before spec 3.9 still verifies. Asserted against the exact bytes rather than
    trusting the mechanism."""
    manifest = _manifest()
    assert "intent" not in manifest
    pre = signing_pre_image(manifest)
    assert b"intent" not in pre

    parsed = json.loads(pre)
    assert set(parsed) <= set(SIGNED_FIELDS)
    assert "intent" not in parsed


def test_an_explicit_null_intent_is_also_omitted() -> None:
    """canonicalize excludes nulls, so `intent: null` and an absent intent
    produce the same bytes and neither disturbs an old signature."""
    assert signing_pre_image(_manifest(intent=None)) == signing_pre_image(_manifest())


# --------------------------------------------------------------------------
# The derived digest
# --------------------------------------------------------------------------


def test_intent_hash_is_none_when_no_intent_is_declared() -> None:
    """Distinct from a digest over an empty statement: nothing was declared."""
    assert intent_hash(_manifest()) is None


def test_intent_hash_is_stable_and_prefixed() -> None:
    manifest = _manifest(intent={"statement": STATEMENT})
    first = intent_hash(manifest)
    assert first is not None
    assert first.startswith("sha256:")
    assert len(first) == len("sha256:") + 64
    assert intent_hash(_manifest(intent={"statement": STATEMENT})) == first


def test_intent_hash_changes_with_the_statement() -> None:
    a = intent_hash(_manifest(intent={"statement": STATEMENT}))
    b = intent_hash(_manifest(intent={"statement": STATEMENT + " Only."}))
    assert a != b


def test_intent_hash_covers_the_whole_object_not_just_the_statement() -> None:
    """So a field added to intent in a later revision is covered without this
    function changing."""
    a = intent_hash(_manifest(intent={"statement": STATEMENT}))
    b = intent_hash(_manifest(intent={"statement": STATEMENT, "scope": "invoices"}))
    assert a != b


# --------------------------------------------------------------------------
# The model
# --------------------------------------------------------------------------


def test_statement_is_required_and_non_empty() -> None:
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        DeclaredIntent(statement="")


def test_intent_carries_no_stored_hash() -> None:
    """A stored digest beside the statement is two representations of one value
    that can be made to disagree; the digest is derived instead."""
    assert set(DeclaredIntent.model_fields) == {"statement"}
