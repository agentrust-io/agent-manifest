"""Pydantic v2 data models for the Agent Manifest Specification v0.1.

All 10 artifact bindings are represented. Cardinality (REQUIRED / OPTIONAL /
conditionally-required) follows Section 3 of the spec. Enums are exhaustive per
the spec's allowed value sets.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._types import HashValue, ManifestId


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyLanguage(str, Enum):
    cedar = "cedar"
    rego = "rego"
    yaml_agt = "yaml-agt"
    composite = "composite"


class EnforcementMode(str, Enum):
    enforce = "enforce"
    advisory = "advisory"
    audit_only = "audit-only"


class DeploymentType(str, Enum):
    api = "api"
    local = "local"
    confidential_inference = "confidential-inference"
    third_party_api = "third-party-api"


class MemoryType(str, Enum):
    none = "none"
    session = "session"
    persistent = "persistent"
    shared = "shared"


class DriftPolicy(str, Enum):
    deny_on_drift = "deny-on-drift"
    alert_on_drift = "alert-on-drift"
    log_only = "log-only"


class RugPullPolicy(str, Enum):
    deny_and_alert = "deny-and-alert"
    deny_and_hold = "deny-and-hold"
    require_reapproval = "require-reapproval"


class TraceType(str, Enum):
    hash_chained = "hash-chained"
    merkle_log = "merkle-log"


class SbomFormat(str, Enum):
    cyclonedx = "cyclonedx"
    spdx = "spdx"


class SlsaLevel(int, Enum):
    one = 1
    two = 2
    three = 3
    four = 4


class PoisoningResult(str, Enum):
    clean = "clean"
    flagged = "flagged"
    not_scanned = "not-scanned"


class ApprovalMethod(str, Enum):
    hardware_key = "hardware-key"
    software_key = "software-key"
    mfa_backed = "mfa-backed"


class PrincipalType(str, Enum):
    human = "human"
    system = "system"
    agent = "agent"


class DataClassification(str, Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class CryptoProfile(str, Enum):
    standard = "standard"
    post_quantum = "post-quantum"


class SignatureAlgorithm(str, Enum):
    ed25519 = "Ed25519"
    ml_dsa_65 = "ML-DSA-65"
    hybrid = "hybrid-Ed25519-ML-DSA-65"


class KeyType(str, Enum):
    software = "software"
    hsm = "hsm"
    tee_sealed = "tee-sealed"


class TimeoutAction(str, Enum):
    deny = "deny"
    suspend = "suspend"
    alert = "alert"


class RiskTier(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------------------
# Sub-models (shared across bindings)
# ---------------------------------------------------------------------------


class PoisoningScan(BaseModel):
    scanner_version: str
    scanned_at: datetime
    result: PoisoningResult


class SlsaProvenance(BaseModel):
    level: SlsaLevel
    provenance_uri: str
    build_system: str


class Sbom(BaseModel):
    format: SbomFormat
    version: str
    sbom_hash: HashValue
    sbom_uri: str
    # CycloneDX serialNumber or SPDX documentNamespace - required by spec #46
    document_id: Optional[str] = None


class McpServer(BaseModel):
    server_id: str  # SPIFFE URI of the MCP server
    image_digest: HashValue
    slsa_level: SlsaLevel
    phase2_attested: bool = False


class ToolEntry(BaseModel):
    tool_id: str
    name: str
    server_id: str  # SPIFFE URI
    schema_hash: HashValue
    # description_hash is bound separately from schema_hash: MCP tool poisoning
    # attacks target descriptions, not schemas. Both must be bound independently.
    description_hash: HashValue
    version: str
    permission_scope: Optional[str] = None
    egress_destinations: list[str] = Field(default_factory=list)


class ScopeGrant(BaseModel):
    tools: list[str] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    max_delegation_depth: int = Field(default=3, ge=0, le=10)
    ttl_seconds: int = Field(ge=60)
    constraints: list[str] = Field(default_factory=list)


class ApprovedScope(BaseModel):
    artifacts: list[str]
    risk_tier: RiskTier
    approval_duration_seconds: int = Field(ge=60)
    conditions: list[str] = Field(default_factory=list)


class HitlApproval(BaseModel):
    approval_id: ManifestId
    # MUST NOT be a SPIFFE URI - human identity uses DID, email, or employee ID
    approver_id: str

    @field_validator("approver_id")
    @classmethod
    def _approver_id_must_not_be_spiffe(cls, v: str) -> str:
        if v.startswith("spiffe://"):
            raise ValueError(
                "approver_id MUST NOT be a SPIFFE URI - SPIFFE identifies machine "
                "workloads, not humans. Use a DID, mailto: URI, or employee ID "
                "(spec Section 3.5, ADR-0009 scope note)."
            )
        return v
    approver_role: str
    approved_at: datetime
    approved_scope: ApprovedScope
    approval_signature: str
    approval_method: ApprovalMethod
    evidence_uri: str


class EscalationPolicy(BaseModel):
    trigger: str  # Cedar policy fragment
    escalation_target: str  # SPIFFE URI of escalation authority
    timeout_action: TimeoutAction


class TransparencyLogEntry(BaseModel):
    log_id: str
    entry_id: str
    inclusion_proof: str
    # Sigstore bundle compatibility fields (spec #43)
    checkpoint: Optional[str] = None
    integrated_time: Optional[int] = None


# ---------------------------------------------------------------------------
# Artifact bindings - one per spec section 3.2.x
# ---------------------------------------------------------------------------


class SystemPromptBinding(BaseModel):
    """Artifact #1 - spec Section 3.2.1."""

    hash: HashValue
    hash_algorithm: str = "SHA-256"
    version: Optional[str] = None
    classification: Optional[DataClassification] = None
    language: Optional[str] = None
    safety_level: Optional[str] = None
    bound_at: datetime


class PolicyBundleBinding(BaseModel):
    """Artifact #2 - spec Section 3.2.2."""

    hash: HashValue
    policy_language: PolicyLanguage
    version: str
    enforcement_mode: EnforcementMode
    scope: list[str] = Field(default_factory=list)
    agt_version: Optional[str] = None
    bound_at: datetime


class ToolManifestBinding(BaseModel):
    """Artifact #3 - spec Section 3.2.3."""

    catalog_hash: HashValue
    tools: list[ToolEntry]
    allow_dynamic_registration: bool = False
    rug_pull_policy: RugPullPolicy = RugPullPolicy.deny_and_alert
    bound_at: datetime


class ModelIdentityBinding(BaseModel):
    """Artifact #4 - spec Section 3.2.4.

    model_hash conditionality (spec F-08):
      - deployment_type=api          -> model_hash MUST be None
      - deployment_type=local        -> model_hash REQUIRED
      - deployment_type=confidential-inference -> model_hash REQUIRED
      - deployment_type=third-party-api -> model_hash OPTIONAL (no binary access)
    """

    provider: str
    model_id: str
    version: str
    capability_level: Optional[str] = None
    safety_alignment_version: Optional[str] = None
    quantization: str = "none"
    deployment_type: DeploymentType
    model_hash: Optional[HashValue] = None
    bound_at: datetime

    @model_validator(mode="after")
    def _validate_model_hash(self) -> "ModelIdentityBinding":
        if self.deployment_type == DeploymentType.api:
            if self.model_hash is not None:
                raise ValueError(
                    "model_hash MUST be null for deployment_type='api'. "
                    "API models are attested by provider+version, not binary hash."
                )
        elif self.deployment_type in (
            DeploymentType.local,
            DeploymentType.confidential_inference,
        ):
            if self.model_hash is None:
                raise ValueError(
                    f"model_hash is REQUIRED when deployment_type='{self.deployment_type.value}'"
                )
        return self


class RagCorpusBinding(BaseModel):
    """Artifact #5 - spec Section 3.2.5."""

    corpus_id: str
    merkle_root: HashValue
    document_count: int = Field(ge=0)
    ingestion_policy_hash: HashValue
    vector_store: str
    embedding_model: str
    last_updated: datetime
    poisoning_scan: PoisoningScan
    bound_at: datetime


class MemoryBaselineBinding(BaseModel):
    """Artifact #6 - spec Section 3.2.6.

    ttl_seconds: min 3600 (1 hour), max 7776000 (90 days).
    """

    baseline_id: ManifestId
    snapshot_hash: HashValue
    memory_type: MemoryType
    store: str
    approved_at: datetime
    ttl_seconds: int = Field(ge=3_600, le=7_776_000)
    drift_policy: DriftPolicy
    bound_at: datetime


class MemoryCheckpointBinding(BaseModel):
    """Artifact #6 checkpoint anchor - spec Section 3.2.6.2 (v0.2).

    Additive companion to MemoryBaselineBinding. Binds the append-only
    operation-log root (`memory_root`) for a governed checkpoint advance, so a
    verifier can check an incremental memory delta via an RFC 9162 consistency
    proof (see `_memory_delta.verify_delta`) instead of re-approving the whole
    store. `snapshot_hash` semantics in MemoryBaselineBinding are unchanged; the
    materialized set-snapshot is a fold over the log.

    ttl_seconds: min 3600 (1 hour), max 7776000 (90 days).
    """

    memory_root: HashValue
    seq: int = Field(ge=0)
    approved_at: datetime
    ttl_seconds: int = Field(ge=3_600, le=7_776_000)
    approval_signature: Optional[str] = None


class DecisionTraceBinding(BaseModel):
    """Artifact #7 - spec Section 3.2.7 (added in #24)."""

    trace_type: TraceType
    audit_chain_root: HashValue
    audit_chain_uri: str
    signing_key_id: str
    audit_key_sealed: bool
    first_entry_at: datetime
    last_entry_at: datetime
    entry_count: Optional[int] = Field(default=None, ge=0)
    bound_at: datetime

    @model_validator(mode="after")
    def _validate_chain_window(self) -> "DecisionTraceBinding":
        if self.first_entry_at > self.last_entry_at:
            raise ValueError("first_entry_at must not be after last_entry_at")
        return self


class SupplyChainBinding(BaseModel):
    """Artifact #9 - spec Section 3.2.8 (renumbered from 3.2.7 in #24)."""

    container_image_digest: HashValue
    base_image_digest: Optional[HashValue] = None
    slsa_provenance: Optional[SlsaProvenance] = None
    sbom: Optional[Sbom] = None
    mcp_servers: list[McpServer] = Field(default_factory=list)
    bound_at: datetime


# ---------------------------------------------------------------------------
# Top-level structures (artifacts #8 and #10 live here per spec Section 3.1)
# ---------------------------------------------------------------------------


class DelegationHop(BaseModel):
    """One hop in the A2A delegation chain (Artifact #8 - spec Section 3.4)."""

    hop: int = Field(ge=0)
    principal_type: PrincipalType
    principal_id: str
    delegated_at: datetime
    scope_grant: ScopeGrant
    delegation_signature: str
    principal_manifest_id: Optional[ManifestId] = None
    principal_attestation_hash: Optional[HashValue] = None


class HitlRecord(BaseModel):
    """Artifact #10 - spec Section 3.5."""

    required: bool
    approvals: list[HitlApproval] = Field(default_factory=list)
    escalation_policy: Optional[EscalationPolicy] = None

    @model_validator(mode="after")
    def _validate_approvals_present(self) -> "HitlRecord":
        if self.required and not self.approvals:
            raise ValueError(
                "hitl_record.required is true but no approvals are present"
            )
        return self


class ArtifactBindings(BaseModel):
    """Container for the 8 artifact bindings that live under `artifacts`."""

    system_prompt: SystemPromptBinding
    policy_bundle: PolicyBundleBinding
    tool_manifest: Optional[ToolManifestBinding] = None
    model_identity: ModelIdentityBinding
    rag_corpus: Optional[RagCorpusBinding] = None
    memory_baseline: Optional[MemoryBaselineBinding] = None
    decision_trace: Optional[DecisionTraceBinding] = None
    supply_chain: Optional[SupplyChainBinding] = None


class ManifestSignature(BaseModel):
    algorithm: SignatureAlgorithm
    key_id: str
    key_type: KeyType
    signed_at: datetime
    signed_fields: list[str] = Field(
        default=[
            "manifest_id", "agent_id", "version", "issued_at", "expires_at",
            "issuer", "crypto_profile", "artifacts", "delegation_chain", "hitl_record",
        ]
    )
    signature_value: str
    transparency_log_entry: Optional[TransparencyLogEntry] = None


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class Manifest(BaseModel):
    """Root Agent Manifest document - spec Section 3.1."""

    model_config = ConfigDict(populate_by_name=True)

    context: str = Field(
        default="https://agentmanifest.agentrust.io/v0.1/context.json",
        alias="@context",
    )
    type: str = Field(default="AgentManifest", alias="@type")
    manifest_id: ManifestId
    agent_id: str  # SPIFFE URI
    version: str = "0.1"
    issued_at: datetime
    expires_at: datetime
    issuer: str  # SPIFFE URI of signing authority
    crypto_profile: CryptoProfile = CryptoProfile.standard
    artifacts: ArtifactBindings
    # attestation is appended by the TEE at launch - excluded from signature pre-image
    attestation: Optional[dict[str, Any]] = None
    delegation_chain: list[DelegationHop] = Field(default_factory=list)
    hitl_record: Optional[HitlRecord] = None
    signature: Optional[ManifestSignature] = None

    @model_validator(mode="after")
    def _validate_expiry_window(self) -> "Manifest":
        delta = self.expires_at - self.issued_at
        if delta < timedelta(hours=1):
            raise ValueError("expires_at must be at least 1 hour after issued_at")
        if delta > timedelta(days=365):
            raise ValueError("expires_at must not be more than 365 days after issued_at")
        return self

    @model_validator(mode="after")
    def _validate_delegation_depth(self) -> "Manifest":
        if not self.delegation_chain:
            return self
        max_depth = self.delegation_chain[0].scope_grant.max_delegation_depth
        if len(self.delegation_chain) > max_depth:
            raise ValueError(
                f"delegation_chain length {len(self.delegation_chain)} exceeds "
                f"root max_delegation_depth {max_depth}"
            )
        for i, hop in enumerate(self.delegation_chain):
            if hop.hop != i:
                raise ValueError(f"delegation_chain[{i}].hop is {hop.hop}, expected {i}")
        return self

    def json_schema(self) -> dict[str, Any]:
        """Export JSON Schema for non-Python verifier implementations."""
        return self.model_json_schema()
