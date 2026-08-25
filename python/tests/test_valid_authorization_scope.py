"""AM-VERIFY-SCOPE: what VALID does and does not establish - issue #272.

These tests assert what the implementation does today, not what it should do.
They pass against main as written, and they are intended to. Spec 5.3.2 now
states the boundary they demonstrate; the tests came first, deliberately.

A manifest can reach VALID with every artifact intact and its tool catalogue
matching byte for byte, while the call made through an authorized tool is one
no reviewer would have approved. That is not a defect in verification. It is
the boundary of what verification answers: VALID establishes that the agent is
the one that was approved, and says nothing about what that agent may do with
the tools it was approved to hold.

Scope is deliberately narrow, per the discussion on #272: the read versus
irreversible-write distinction inside a single authorized tool. Parameter-level
policy in general is a design question and is not demonstrated here.
"""
import inspect
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._signing import Ed25519Signer, generate_ed25519
from agent_manifest._verify import (
    FieldResult,
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

NOW = datetime.now(timezone.utc)
TS_FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
TOOL_CATALOG = "sha256:" + "d" * 64
MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}

# The one tool the reviewer approved, and the two calls through it that a
# reviewer would treat very differently. Both are inside the approved tool.
APPROVED_TOOL = "db.execute"
READ_CALL = {"tool": APPROVED_TOOL, "args": {"sql": "SELECT id FROM customers LIMIT 1"}}
IRREVERSIBLE_WRITE_CALL = {"tool": APPROVED_TOOL, "args": {"sql": "DELETE FROM customers"}}


def sign(m):
    m["signature"] = Ed25519Signer(KP).sign(m)
    return m


def manifest_with_tool_catalog(**overrides):
    """A manifest whose tool catalogue is exactly what was approved."""
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": TS_FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SHA_A},
            "policy_bundle": {"hash": SHA_B, "enforcement_mode": "enforce"},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
            "decision_trace": {"audit_chain_root": SHA_C},
            "tool_manifest": {"catalog_hash": TOOL_CATALOG},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    m.update(overrides)
    return sign(m)


def ctx_matching_catalog():
    """A context in which every artifact, including the tool catalogue, matches."""
    c = VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        audit_chain_root=SHA_C,
        trusted_keys=dict(TRUSTED_KEYS),
    )
    c.tool_catalog_hash = TOOL_CATALOG
    return c


# ---------------------------------------------------------------------------
# The premise: this manifest really is VALID, on every field, including tools
# ---------------------------------------------------------------------------

def test_manifest_with_intact_tool_catalog_is_valid():
    r = verify_manifest(manifest_with_tool_catalog(), ctx_matching_catalog(), RevocationStore())
    assert r.result == OverallResult.VALID
    assert r.mismatch_details == []


def test_tool_catalog_field_matches():
    r = verify_manifest(manifest_with_tool_catalog(), ctx_matching_catalog(), RevocationStore())
    assert r.fields_verified.tool_manifest == FieldResult.MATCH


# ---------------------------------------------------------------------------
# The boundary: the call is not an input, so VALID cannot depend on it
# ---------------------------------------------------------------------------

def test_verification_takes_no_invocation_parameter():
    """The structural form of the argument. There is nowhere to put the call."""
    params = set(inspect.signature(verify_manifest).parameters)
    assert not params & {"call", "invocation", "tool_call", "action", "request"}


@pytest.mark.parametrize(
    "call",
    [READ_CALL, IRREVERSIBLE_WRITE_CALL],
    ids=["read", "irreversible_write"],
)
def test_valid_is_reached_identically_whatever_the_call(call):
    """Both calls go through the one approved tool. Verification cannot see either,
    so the result is the same for a SELECT and for an unqualified DELETE."""
    assert call["tool"] == APPROVED_TOOL
    r = verify_manifest(manifest_with_tool_catalog(), ctx_matching_catalog(), RevocationStore())
    assert r.result == OverallResult.VALID
    assert r.fields_verified.tool_manifest == FieldResult.MATCH


# Every field VALID reports on, as of this commit. Each is a statement about what
# the agent is composed of. None is a statement about what it did.
ARTIFACT_FIELDS = {
    "system_prompt",
    "policy_bundle",
    "model_identity",
    "decision_trace",
    "tool_manifest",
    "memory_baseline",
    "rag_corpus",
    "supply_chain",
    "delegation_chain",
    "hitl_record",
}


def test_every_verified_field_is_an_artifact_not_an_action():
    """The result enumerates ten artifacts and nothing about the call made through
    them. If a field describing an action is ever added, this fails and whoever
    added it has to decide what VALID now means."""
    r = verify_manifest(manifest_with_tool_catalog(), ctx_matching_catalog(), RevocationStore())
    exposed = {n for n in dir(r.fields_verified) if not n.startswith("_")}

    # Every artifact this version verifies is still reported.
    assert ARTIFACT_FIELDS <= exposed

    # And nothing in the result describes the invocation.
    assert not exposed & {
        "tool_call", "invocation", "action", "effect",
        "reversibility", "parameters", "arguments",
    }
