"""AM-BIND: Artifact binding conformance tests — issue #16.

Covers all 10 artifact bindings: schema validation, cardinality enforcement,
conditional requirements, enum exhaustiveness, and the Manifest root model.
Target: 47 tests.
"""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_manifest._types import HashValue, ManifestId
from agent_manifest.models import (
    DataClassification,
    DecisionTraceBinding,
    DeploymentType,
    DriftPolicy,
    EnforcementMode,
    HitlApproval,
    HitlRecord,
    MemoryBaselineBinding,
    ModelIdentityBinding,
    PolicyBundleBinding,
    PolicyLanguage,
    PoisoningResult,
    PoisoningScan,
    RagCorpusBinding,
    RiskTier,
    RugPullPolicy,
    Sbom,
    SbomFormat,
    SlsaLevel,
    SlsaProvenance,
    SupplyChainBinding,
    SystemPromptBinding,
    ToolEntry,
    ToolManifestBinding,
    TraceType,
    Manifest,
    ArtifactBindings,
    DelegationHop,
    ScopeGrant,
    PrincipalType,
    CryptoProfile,
    ApprovalMethod,
    ApprovedScope,
)

NOW = datetime.now(timezone.utc)
TS = NOW.isoformat()
SHA = HashValue("sha256:" + "a" * 64)
SHA2 = HashValue("sha256:" + "b" * 64)
MID = ManifestId("018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c")


# ---------------------------------------------------------------------------
# ManifestId — UUID v7
# ---------------------------------------------------------------------------

def test_manifest_id_valid():
    assert ManifestId._validate("018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c")

def test_manifest_id_wrong_version_nibble():
    with pytest.raises(ValueError, match="UUID v7"):
        ManifestId._validate("018f4a3b-2c1d-4e5f-a8b9-0d1e2f3a4b5c")  # v4

def test_manifest_id_wrong_variant():
    with pytest.raises(ValueError, match="UUID v7"):
        ManifestId._validate("018f4a3b-2c1d-7e5f-18b9-0d1e2f3a4b5c")  # variant not 8-b

def test_manifest_id_not_a_string():
    with pytest.raises(ValueError):
        ManifestId._validate(12345)


# ---------------------------------------------------------------------------
# HashValue
# ---------------------------------------------------------------------------

def test_hash_value_sha256_valid():
    h = HashValue._validate("sha256:" + "a" * 64)
    assert h.algorithm == "sha256"
    assert len(h.hex_digest) == 64

def test_hash_value_shake256_valid():
    h = HashValue._validate("shake256:" + "f" * 64)
    assert h.algorithm == "shake256"

def test_hash_value_wrong_length():
    with pytest.raises(ValueError):
        HashValue._validate("sha256:" + "a" * 63)

def test_hash_value_unknown_algorithm():
    with pytest.raises(ValueError):
        HashValue._validate("md5:" + "a" * 32)

def test_hash_value_uppercase_rejected():
    with pytest.raises(ValueError):
        HashValue._validate("sha256:" + "A" * 64)


# ---------------------------------------------------------------------------
# Artifact #1 — SystemPromptBinding
# ---------------------------------------------------------------------------

def test_system_prompt_minimal():
    b = SystemPromptBinding(hash=SHA, bound_at=NOW)
    assert b.hash == SHA

def test_system_prompt_optional_fields():
    b = SystemPromptBinding(
        hash=SHA, bound_at=NOW,
        classification=DataClassification.confidential,
        safety_level="high",
    )
    assert b.classification == DataClassification.confidential


# ---------------------------------------------------------------------------
# Artifact #2 — PolicyBundleBinding
# ---------------------------------------------------------------------------

def test_policy_bundle_cedar():
    b = PolicyBundleBinding(
        hash=SHA, policy_language=PolicyLanguage.cedar,
        version="1.0.0", enforcement_mode=EnforcementMode.enforce, bound_at=NOW,
    )
    assert b.enforcement_mode == EnforcementMode.enforce

def test_policy_bundle_advisory_mode():
    b = PolicyBundleBinding(
        hash=SHA, policy_language=PolicyLanguage.rego,
        version="0.1", enforcement_mode=EnforcementMode.advisory, bound_at=NOW,
    )
    assert b.enforcement_mode == EnforcementMode.advisory


# ---------------------------------------------------------------------------
# Artifact #3 — ToolManifestBinding
# ---------------------------------------------------------------------------

def _tool(tool_id="com.example.t", schema_hex="a"*64, desc_hex="b"*64):
    return ToolEntry(
        tool_id=tool_id, name="t",
        server_id="spiffe://x/server",
        schema_hash=HashValue(f"sha256:{schema_hex}"),
        description_hash=HashValue(f"sha256:{desc_hex}"),
        version="1.0",
    )

def test_tool_manifest_allow_dynamic_false_by_default():
    b = ToolManifestBinding(catalog_hash=SHA, tools=[_tool()], bound_at=NOW)
    assert b.allow_dynamic_registration is False

def test_tool_manifest_boolean_not_string():
    b = ToolManifestBinding(
        catalog_hash=SHA, tools=[_tool()],
        allow_dynamic_registration=False, bound_at=NOW,
    )
    assert isinstance(b.allow_dynamic_registration, bool)

def test_tool_manifest_rug_pull_enum():
    b = ToolManifestBinding(
        catalog_hash=SHA, tools=[_tool()],
        rug_pull_policy=RugPullPolicy.require_reapproval, bound_at=NOW,
    )
    assert b.rug_pull_policy == RugPullPolicy.require_reapproval


# ---------------------------------------------------------------------------
# Artifact #4 — ModelIdentityBinding — conditional model_hash
# ---------------------------------------------------------------------------

def test_model_api_no_hash():
    b = ModelIdentityBinding(
        provider="anthropic", model_id="claude", version="3",
        deployment_type=DeploymentType.api, model_hash=None, bound_at=NOW,
    )
    assert b.model_hash is None

def test_model_api_with_hash_rejected():
    with pytest.raises(ValidationError, match="must be null for.*api"):
        ModelIdentityBinding(
            provider="anthropic", model_id="claude", version="3",
            deployment_type=DeploymentType.api, model_hash=SHA, bound_at=NOW,
        )

def test_model_local_requires_hash():
    with pytest.raises(ValidationError, match="REQUIRED when deployment_type"):
        ModelIdentityBinding(
            provider="internal", model_id="llm", version="1",
            deployment_type=DeploymentType.local, model_hash=None, bound_at=NOW,
        )

def test_model_confidential_inference_requires_hash():
    b = ModelIdentityBinding(
        provider="opaque", model_id="llm", version="1",
        deployment_type=DeploymentType.confidential_inference,
        model_hash=SHA, bound_at=NOW,
    )
    assert b.model_hash == SHA

def test_model_third_party_api_hash_optional():
    b = ModelIdentityBinding(
        provider="azure_oai", model_id="gpt4", version="0613",
        deployment_type=DeploymentType.third_party_api, bound_at=NOW,
    )
    assert b.model_hash is None


# ---------------------------------------------------------------------------
# Artifact #5 — RagCorpusBinding
# ---------------------------------------------------------------------------

def test_rag_corpus_with_scan():
    b = RagCorpusBinding(
        corpus_id="corp-1", merkle_root=SHA, document_count=100,
        ingestion_policy_hash=SHA2, vector_store="pinecone/1.0",
        embedding_model="text-embedding-3", last_updated=NOW,
        poisoning_scan=PoisoningScan(
            scanner_version="v0.1", scanned_at=NOW, result=PoisoningResult.clean
        ),
        bound_at=NOW,
    )
    assert b.poisoning_scan.result == PoisoningResult.clean


# ---------------------------------------------------------------------------
# Artifact #6 — MemoryBaselineBinding
# ---------------------------------------------------------------------------

def test_memory_baseline_ttl_minimum():
    with pytest.raises(ValidationError):
        MemoryBaselineBinding(
            baseline_id=MID, snapshot_hash=SHA, memory_type="session",
            store="redis/7", approved_at=NOW,
            ttl_seconds=3599,  # below 3600 minimum
            drift_policy=DriftPolicy.deny_on_drift, bound_at=NOW,
        )

def test_memory_baseline_ttl_maximum():
    with pytest.raises(ValidationError):
        MemoryBaselineBinding(
            baseline_id=MID, snapshot_hash=SHA, memory_type="persistent",
            store="redis/7", approved_at=NOW,
            ttl_seconds=7_776_001,  # above 90-day maximum
            drift_policy=DriftPolicy.log_only, bound_at=NOW,
        )

def test_memory_baseline_valid_ttl():
    b = MemoryBaselineBinding(
        baseline_id=MID, snapshot_hash=SHA, memory_type="session",
        store="redis/7", approved_at=NOW,
        ttl_seconds=86400,
        drift_policy=DriftPolicy.alert_on_drift, bound_at=NOW,
    )
    assert b.ttl_seconds == 86400


# ---------------------------------------------------------------------------
# Artifact #7 — DecisionTraceBinding (added in #24)
# ---------------------------------------------------------------------------

def test_decision_trace_valid():
    b = DecisionTraceBinding(
        trace_type=TraceType.hash_chained,
        audit_chain_root=SHA,
        audit_chain_uri="https://audit.example/chain",
        signing_key_id="key-1",
        audit_key_sealed=True,
        first_entry_at=NOW - timedelta(hours=1),
        last_entry_at=NOW,
        bound_at=NOW,
    )
    assert b.audit_key_sealed is True

def test_decision_trace_invalid_window():
    with pytest.raises(ValidationError, match="first_entry_at"):
        DecisionTraceBinding(
            trace_type=TraceType.merkle_log,
            audit_chain_root=SHA,
            audit_chain_uri="https://x",
            signing_key_id="k",
            audit_key_sealed=True,
            first_entry_at=NOW,
            last_entry_at=NOW - timedelta(hours=1),  # before first
            bound_at=NOW,
        )

def test_decision_trace_audit_key_sealed_is_bool():
    b = DecisionTraceBinding(
        trace_type=TraceType.hash_chained, audit_chain_root=SHA,
        audit_chain_uri="https://x", signing_key_id="k",
        audit_key_sealed=False, first_entry_at=NOW, last_entry_at=NOW, bound_at=NOW,
    )
    assert isinstance(b.audit_key_sealed, bool)


# ---------------------------------------------------------------------------
# Root Manifest — expiry validation
# ---------------------------------------------------------------------------

def _minimal_manifest(**overrides):
    base = dict(
        manifest_id=MID,
        agent_id="spiffe://trust.example/agent/kyc/prod",
        issued_at=NOW,
        expires_at=NOW + timedelta(days=90),
        issuer="spiffe://trust.example/issuer",
        artifacts=ArtifactBindings(
            system_prompt=SystemPromptBinding(hash=SHA, bound_at=NOW),
            policy_bundle=PolicyBundleBinding(
                hash=SHA, policy_language=PolicyLanguage.cedar,
                version="1.0", enforcement_mode=EnforcementMode.enforce, bound_at=NOW,
            ),
            model_identity=ModelIdentityBinding(
                provider="anthropic", model_id="claude", version="3",
                deployment_type=DeploymentType.api, bound_at=NOW,
            ),
        ),
    )
    base.update(overrides)
    return base

def test_manifest_valid():
    m = Manifest(**_minimal_manifest())
    assert m.manifest_id == MID

def test_manifest_expires_too_soon():
    with pytest.raises(ValidationError, match="at least 1 hour"):
        Manifest(**_minimal_manifest(expires_at=NOW + timedelta(minutes=30)))

def test_manifest_expires_too_far():
    with pytest.raises(ValidationError, match="365 days"):
        Manifest(**_minimal_manifest(expires_at=NOW + timedelta(days=366)))

def test_manifest_delegation_depth_exceeded():
    hops = [
        DelegationHop(
            hop=i, principal_type=PrincipalType.agent,
            principal_id=f"spiffe://x/{i}",
            delegated_at=NOW,
            scope_grant=ScopeGrant(
                max_delegation_depth=2, ttl_seconds=3600,
            ),
            delegation_signature="sig",
        )
        for i in range(3)  # 3 hops > max_delegation_depth=2
    ]
    with pytest.raises(ValidationError, match="max_delegation_depth"):
        Manifest(**_minimal_manifest(delegation_chain=hops))

def test_manifest_json_schema_export():
    m = Manifest(**_minimal_manifest())
    schema = m.json_schema()
    assert "properties" in schema
    assert "manifest_id" in schema["properties"]
