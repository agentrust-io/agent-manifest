"""Relying-party challenge and context binding (spec 5.1.2 - issue #266).

`verification_id` is picked by the verification service and `verified_at` is a
producer-selected timestamp, so neither shows a relying party that a result was
made for its live request. These cover the two fields that do: the echoed
`challenge_nonce` and `verification_context_hash`, plus the derivation that
composes this challenge with the section 3.3.2 runtime report.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest import derive_runtime_nonce, verification_context_hash
from agent_manifest._verify import (
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

UTC = timezone.utc
NONCE = "a1b2c3d4" * 4  # 128 bits


def _manifest(**overrides):
    now = datetime.now(UTC)
    doc = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {},
    }
    doc.update(overrides)
    return doc


def _verify(**context_kwargs):
    return verify_manifest(
        _manifest(), VerificationContext(**context_kwargs), RevocationStore()
    )


# ---------------------------------------------------------------------------
# The nonce
# ---------------------------------------------------------------------------


def test_nonce_is_echoed_unchanged():
    assert _verify(challenge_nonce=NONCE).challenge_nonce == NONCE


def test_absent_challenge_produces_a_result_with_no_nonce():
    """A result carrying no nonce is unbound to any request, and says so by
    omission rather than by inventing one."""
    assert _verify().challenge_nonce is None


# ---------------------------------------------------------------------------
# The context hash
# ---------------------------------------------------------------------------


def test_result_always_carries_a_context_hash():
    result = _verify()
    assert result.verification_context_hash is not None
    assert result.verification_context_hash.startswith("sha256:")


def test_same_question_hashes_the_same():
    a = verification_context_hash(VerificationContext(purpose="tool-call"))
    b = verification_context_hash(VerificationContext(purpose="tool-call"))
    assert a == b


def test_the_nonce_is_not_an_input_to_the_context_hash():
    """Spec 5.1.2 rule 3. Two requests asking the same question must hash the
    same, or the value is not comparable across requests."""
    with_nonce = verification_context_hash(
        VerificationContext(purpose="audit", challenge_nonce=NONCE)
    )
    without = verification_context_hash(VerificationContext(purpose="audit"))
    assert with_nonce == without


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "audit"),
        ("verifier_id", "spiffe://trust.example/auditor"),
        ("enforce_hitl", True),
        ("enforce_attestation", True),
        ("min_slsa_level", 3),
        ("strict_artifact_verification", False),
        ("require_delegation", True),
        ("conformance_level", 2),
    ],
)
def test_every_decision_affecting_input_changes_the_hash(field, value):
    """Spec 5.1.2 rule 2: an implementation that drops an input from the hash
    is asserting a decision it did not make. One case per input, so a field
    added to the context and forgotten here fails as a gap in coverage."""
    base = verification_context_hash(VerificationContext(purpose="tool-call"))
    changed = verification_context_hash(
        VerificationContext(**{"purpose": "tool-call", field: value})
    )
    assert changed != base


def test_evidence_and_trust_anchors_are_not_in_the_hash():
    """Runtime hashes are the evidence being checked and trusted_keys are the
    anchors doing the checking. Neither is the question the relying party
    asked, and folding them in would make the hash change for reasons a
    relying party cannot reproduce from its own request."""
    plain = verification_context_hash(VerificationContext(purpose="tool-call"))
    loaded = verification_context_hash(
        VerificationContext(
            purpose="tool-call",
            system_prompt_hash="sha256:" + "a" * 64,
            trusted_keys={"k": "pub"},
        )
    )
    assert loaded == plain


def test_a_relying_party_can_recompute_the_hash_from_what_it_sent():
    """The check spec 5.1.2 rule 5 requires: recompute locally, compare."""
    context = VerificationContext(
        purpose="tool-call", verifier_id="spiffe://x/y", enforce_hitl=True
    )
    result = verify_manifest(_manifest(), context, RevocationStore())
    assert result.verification_context_hash == verification_context_hash(context)


def test_a_different_question_does_not_match_the_recomputation():
    """The replay this exists to catch: a result produced for an `audit`
    request presented against a `tool-call` decision."""
    served = verify_manifest(
        _manifest(), VerificationContext(purpose="audit"), RevocationStore()
    )
    expected_here = verification_context_hash(VerificationContext(purpose="tool-call"))
    assert served.verification_context_hash != expected_here


def test_a_weaker_context_does_not_match_a_stronger_request():
    served = verify_manifest(
        _manifest(),
        VerificationContext(purpose="tool-call", enforce_hitl=False),
        RevocationStore(),
    )
    asked = verification_context_hash(
        VerificationContext(purpose="tool-call", enforce_hitl=True)
    )
    assert served.verification_context_hash != asked


# ---------------------------------------------------------------------------
# Composition with the section 3.3.2 runtime report
# ---------------------------------------------------------------------------


def test_runtime_nonce_derivation_is_deterministic():
    assert derive_runtime_nonce(NONCE) == derive_runtime_nonce(NONCE)


def test_runtime_nonce_is_domain_separated_from_the_challenge():
    """The derived value must not be usable as a verification challenge in its
    own right, so it cannot simply be the challenge or its bare digest."""
    import hashlib

    derived = derive_runtime_nonce(NONCE)
    assert derived != bytes.fromhex(NONCE)
    assert derived != hashlib.sha256(bytes.fromhex(NONCE)).digest()


def test_distinct_challenges_derive_distinct_runtime_nonces():
    other = "f" * 32
    assert derive_runtime_nonce(NONCE) != derive_runtime_nonce(other)


@pytest.mark.parametrize("bad", ["", "zz" * 16, "not-hex"])
def test_non_hex_challenge_is_rejected(bad):
    with pytest.raises(ValueError):
        derive_runtime_nonce(bad)


def test_short_challenge_is_rejected():
    """128 bits is the floor spec 5.1.2 rule 1 sets. A 64-bit challenge is
    guessable often enough that binding to it proves little."""
    with pytest.raises(ValueError, match="128 bits"):
        derive_runtime_nonce("ab" * 8)
