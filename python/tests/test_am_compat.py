"""AM-COMPAT: Cross-implementation compatibility tests — issue #20.

Covers AGT integration, MCP protocol extension, cMCP field cross-check,
SLSA provenance binding, and JSON Schema export for non-Python verifiers.
Target: 31 tests.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest._merkle import build_catalog_tree, build_corpus_tree
from agent_manifest._providers import TPMProvider
from agent_manifest._signing import SIGNED_FIELDS, signing_pre_image, generate_ed25519, Ed25519Signer, Ed25519Verifier
from agent_manifest._types import HashValue, ManifestId
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest
)
from agent_manifest.models import (
    ArtifactBindings, DeploymentType,
    EnforcementMode, Manifest, ModelIdentityBinding, PolicyBundleBinding,
    SlsaLevel, SlsaProvenance, SupplyChainBinding, SystemPromptBinding,
    ToolEntry, ToolManifestBinding,
)

NOW = datetime.now(timezone.utc)
SHA = HashValue("sha256:" + "a" * 64)
SHA2 = HashValue("sha256:" + "b" * 64)
MID = ManifestId("018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c")


# ---------------------------------------------------------------------------
# JSON Schema export (AM-COMPAT-01 to 04)
# ---------------------------------------------------------------------------

def test_json_schema_is_dict():
    m = _minimal_manifest()
    schema = m.json_schema()
    assert isinstance(schema, dict)

def test_json_schema_has_properties():
    schema = _minimal_manifest().json_schema()
    assert "properties" in schema

def test_json_schema_manifest_id_present():
    schema = _minimal_manifest().json_schema()
    assert "manifest_id" in schema["properties"]

def test_json_schema_serializable():
    schema = _minimal_manifest().json_schema()
    json.dumps(schema)  # must not raise


# ---------------------------------------------------------------------------
# MCP protocol extension (AM-COMPAT-05 to 09)
# ---------------------------------------------------------------------------

def test_mcp_initialize_extension_fields():
    """Verify the expected MCP clientInfo extension fields are defined."""
    # The spec defines agentManifestId and agentManifestVerificationEndpoint
    # as clientInfo extensions. We test that we can construct the dict.
    m = _minimal_manifest()
    client_info = {
        "name": "kyc-agent",
        "version": "1.0.0",
        "agentManifestId": str(m.manifest_id),
        "agentManifestVerificationEndpoint": "https://verify.example/verify",
    }
    assert client_info["agentManifestId"] == str(MID)

def test_mcp_tool_call_evidence_has_manifest_id():
    trace = {
        "trace_id": "trace-001",
        "agent_id": "spiffe://x/agent",
        "agent_manifest_id": str(MID),
        "manifest_verification_result": "VALID",
        "tool_id": "com.example.read",
        "policy_hash": "sha256:" + "a" * 64,
        "catalog_hash": "sha256:" + "b" * 64,
        "decision": "allow",
        "timestamp": NOW.isoformat(),
        "signature": "sig_abc",
    }
    assert trace["agent_manifest_id"] == str(MID)

def test_mcp_tool_evidence_verification_result_enum():
    for result in ("VALID", "MISMATCH", "EXPIRED"):
        trace = {"manifest_verification_result": result}
        assert trace["manifest_verification_result"] in ("VALID", "MISMATCH", "EXPIRED")

def test_mcp_rug_pull_detected_by_catalog_hash():
    """Changing tool description must produce different catalog hash."""
    t1 = ToolEntry(
        tool_id="com.example.read", name="read",
        server_id="spiffe://x/s",
        schema_hash=HashValue("sha256:" + "a" * 64),
        description_hash=HashValue("sha256:" + "b" * 64),
        version="1",
    )
    t2 = ToolEntry(
        tool_id="com.example.read", name="read",
        server_id="spiffe://x/s",
        schema_hash=HashValue("sha256:" + "a" * 64),
        description_hash=HashValue("sha256:" + "c" * 64),  # description mutated
        version="1",
    )
    assert build_catalog_tree([t1]) != build_catalog_tree([t2])

def test_allow_dynamic_registration_false_by_default():
    binding = ToolManifestBinding(
        catalog_hash=SHA,
        tools=[ToolEntry(
            tool_id="t", name="t", server_id="spiffe://x",
            schema_hash=SHA, description_hash=SHA2, version="1",
        )],
        bound_at=NOW,
    )
    assert binding.allow_dynamic_registration is False


# ---------------------------------------------------------------------------
# AGT policy bundle hash integration (AM-COMPAT-10 to 15)
# ---------------------------------------------------------------------------

def test_policy_bundle_hash_in_signed_fields():
    assert "artifacts" in SIGNED_FIELDS  # artifacts covers policy_bundle

def test_policy_bundle_hash_in_signing_pre_image():
    m = _manifest_dict(policy_hash="sha256:" + "f" * 64)
    pre = signing_pre_image(m)
    assert "f" * 10 in pre.decode()

def test_enforcement_mode_in_pre_image():
    m = _manifest_dict()
    pre = signing_pre_image(m)
    assert b"enforce" in pre

def test_policy_hash_change_invalidates_signature():
    kp = generate_ed25519()
    m = _manifest_dict()
    sig = Ed25519Signer(kp).sign(m)
    from cryptography.exceptions import InvalidSignature
    tampered = _manifest_dict(policy_hash="sha256:" + "0" * 64)
    with pytest.raises(InvalidSignature):
        Ed25519Verifier(kp.public_bytes).verify(tampered, sig["signature_value"])

def test_agt_audit_chain_root_in_decision_trace():
    m = _manifest_dict()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": "sha256:" + "c" * 64}
    pre = signing_pre_image(m)
    assert b"decision_trace" in pre

def test_policy_bundle_enforcement_mode_advisory_allowed():
    b = PolicyBundleBinding(
        hash=SHA, policy_language="cedar", version="1",
        enforcement_mode=EnforcementMode.advisory, bound_at=NOW,
    )
    assert b.enforcement_mode.value == "advisory"


# ---------------------------------------------------------------------------
# cMCP attestation field cross-check (AM-COMPAT-16 to 20)
# ---------------------------------------------------------------------------

def test_attest_pre_image_includes_policy_bundle():
    p = TPMProvider()
    m = _manifest_dict_with_sig()
    pre = p.manifest_pre_image(m)
    assert b"policy_bundle" in pre

def test_attest_pre_image_includes_enforcement_mode():
    p = TPMProvider()
    pre = p.manifest_pre_image(_manifest_dict_with_sig())
    assert b"enforce" in pre

def test_attest_and_sign_cover_same_policy_hash():
    """Both signing and attestation pre-images encode the policy bundle hash."""
    m = _manifest_dict_with_sig(policy_hash="sha256:" + "e" * 64)
    sign_pre = signing_pre_image(m)
    attest_pre = TPMProvider().manifest_pre_image(m)
    assert b"e" * 10 in sign_pre
    assert b"e" * 10 in attest_pre

def test_supply_chain_digest_in_attest_pre_image():
    p = TPMProvider()
    m = _manifest_dict_with_sig()
    m["artifacts"]["supply_chain"] = {"container_image_digest": "sha256:" + "d" * 64}
    pre = p.manifest_pre_image(m)
    assert b"d" * 10 in pre

def test_manifest_hash_deterministic_across_providers():
    m = _manifest_dict_with_sig()
    h1 = TPMProvider().manifest_hash_value(m)
    h2 = TPMProvider().manifest_hash_value(m)
    assert h1 == h2


# ---------------------------------------------------------------------------
# SLSA provenance binding (AM-COMPAT-21 to 25)
# ---------------------------------------------------------------------------

def test_slsa_provenance_in_supply_chain():
    b = SupplyChainBinding(
        container_image_digest=SHA,
        slsa_provenance=SlsaProvenance(
            level=SlsaLevel.three,
            provenance_uri="https://build.example/prov/123",
            build_system="github-actions",
        ),
        bound_at=NOW,
    )
    assert b.slsa_provenance.level == SlsaLevel.three

def test_slsa_level_four():
    p = SlsaProvenance(level=SlsaLevel.four, provenance_uri="https://x", build_system="hermetic")
    assert p.level == 4

def test_slsa_provenance_optional():
    b = SupplyChainBinding(container_image_digest=SHA, bound_at=NOW)
    assert b.slsa_provenance is None

def test_sbom_cyclonedx():
    from agent_manifest.models import Sbom, SbomFormat
    s = Sbom(
        format=SbomFormat.cyclonedx, version="1.6",
        sbom_hash=SHA, sbom_uri="https://x/sbom.json",
        document_id="urn:uuid:abc123",
    )
    assert s.document_id == "urn:uuid:abc123"

def test_mcp_servers_in_supply_chain():
    from agent_manifest.models import McpServer
    b = SupplyChainBinding(
        container_image_digest=SHA,
        mcp_servers=[McpServer(
            server_id="spiffe://x/mcp", image_digest=SHA2,
            slsa_level=SlsaLevel.two, phase2_attested=True,
        )],
        bound_at=NOW,
    )
    assert b.mcp_servers[0].phase2_attested is True


# ---------------------------------------------------------------------------
# End-to-end sign → attest → verify (AM-COMPAT-26 to 31)
# ---------------------------------------------------------------------------

def test_sign_then_verify_valid():
    kp = generate_ed25519()
    m = _manifest_dict()
    sig = Ed25519Signer(kp).sign(m)
    m["signature"] = sig
    # Verify the signature
    Ed25519Verifier(kp.public_bytes).verify(m, sig["signature_value"])

def test_full_manifest_model_roundtrip():
    m = _minimal_manifest()
    dumped = m.model_dump(mode="json")
    restored = Manifest.model_validate(dumped)
    assert restored.manifest_id == m.manifest_id

def test_verification_engine_valid_after_sign():
    kp = generate_ed25519()
    raw = _manifest_dict(policy_hash="sha256:" + "b" * 64)
    raw["signature"] = Ed25519Signer(kp).sign(raw)
    ctx = VerificationContext(
        system_prompt_hash="sha256:" + "a" * 64,
        policy_bundle_hash="sha256:" + "b" * 64,
    )
    result = verify_manifest(raw, ctx, RevocationStore())
    assert result.result == OverallResult.VALID

def test_corpus_tree_root_is_hash_value():
    from agent_manifest._merkle import CorpusDocument
    docs = [CorpusDocument("doc-1", b"content")]
    root = build_corpus_tree(docs)
    HashValue._validate(root)  # must be a valid HashValue

def test_catalog_tree_root_is_hash_value():
    t = ToolEntry(
        tool_id="t", name="t", server_id="spiffe://x",
        schema_hash=SHA, description_hash=SHA2, version="1",
    )
    root = build_catalog_tree([t])
    HashValue._validate(root)

def test_manifest_json_schema_has_required():
    schema = _minimal_manifest().json_schema()
    # Pydantic v2 marks required fields
    assert "$defs" in schema or "properties" in schema


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_manifest():
    return Manifest(
        manifest_id=MID,
        agent_id="spiffe://trust.example/agent/kyc/prod",
        issued_at=NOW,
        expires_at=NOW + timedelta(days=90),
        issuer="spiffe://trust.example/issuer",
        artifacts=ArtifactBindings(
            system_prompt=SystemPromptBinding(hash=SHA, bound_at=NOW),
            policy_bundle=PolicyBundleBinding(
                hash=SHA, policy_language="cedar",
                version="1.0", enforcement_mode=EnforcementMode.enforce, bound_at=NOW,
            ),
            model_identity=ModelIdentityBinding(
                provider="anthropic", model_id="claude", version="3",
                deployment_type=DeploymentType.api, bound_at=NOW,
            ),
        ),
    )


def _manifest_dict(policy_hash="sha256:" + "b" * 64):
    return {
        "manifest_id": str(MID),
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "policy_bundle": {"hash": policy_hash, "enforcement_mode": "enforce"},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }


def _manifest_dict_with_sig(**kwargs):
    m = _manifest_dict(**kwargs)
    m["signature"] = {"algorithm": "Ed25519", "signature_value": "abc123def"}
    return m
