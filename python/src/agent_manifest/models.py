"""Pydantic v2 data models for the Agent Manifest Specification v0.1.

All 10 artifact bindings are represented. Cardinality (REQUIRED / OPTIONAL /
conditionally-required) follows Section 3 of the spec. Enums are exhaustive per
the spec's allowed value sets.

Unknown fields are rejected (``extra="forbid"``): the spec defines exhaustive
field sets per object, so an unrecognized key is structural drift, not an
extension point. This is what lets the example-validation CI gate catch
spec/model/example divergence.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._delegation import DEFAULT_MAX_DELEGATION_DEPTH, delegation_depth_exceeded
from ._signing import SIGNED_FIELDS
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


class ModelAttestationType(str, Enum):
    """Spec Section 3.2.4 - hash-bound vs provider-asserted model identity."""

    hash_bound = "hash-bound"
    provider_asserted = "provider-asserted"


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


class ApproverIdentityType(str, Enum):
    """Spec Section 3.5 - human-attributable identity forms."""

    oidc = "oidc"
    email = "email"
    did = "did"


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


class OverrideMechanism(str, Enum):
    """Spec Section 3.5 - hitl_runtime override mechanisms (EU AI Act Art. 14(4)(a))."""

    kill_signal = "kill-signal"
    suspend_and_hold = "suspend-and-hold"
    require_confirmation = "require-confirmation"


class RiskTier(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# ---------------------------------------------------------------------------
# Base model - reject unknown fields so drift is a validation error
# ---------------------------------------------------------------------------


class SpecModel(BaseModel):
    """Base for all spec objects: unknown fields are validation errors."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Sub-models (shared across bindings)
# ---------------------------------------------------------------------------


class PoisoningScan(SpecModel):
    # scanner_version and scanned_at are REQUIRED for Level 1+ (spec 3.2.5);
    # Level 0 manifests with result=not-scanned may omit them.
    scanner_version: Optional[str] = None
    scanned_at: Optional[datetime] = None
    result: PoisoningResult


class SlsaProvenance(SpecModel):
    """Spec Section 3.2.8 - DSSE/in-toto aligned provenance pointer."""

    builder_id: str
    subject_digest: HashValue  # MUST match container_image_digest
    provenance_uri: str
    rekor_entry_id: Optional[str] = None  # REQUIRED for Level 2+
    declared_level: Optional[SlsaLevel] = None  # non-normative operator declaration


class Sbom(SpecModel):
    format: SbomFormat
    # SBOM specification schema version, e.g. "CycloneDX 1.6" or "SPDX 2.3"
    schema_version: str
    # CycloneDX serialNumber URN or SPDX documentNamespace URI
    document_id: str
    sbom_hash: HashValue
    sbom_uri: str


class McpServer(SpecModel):
    server_id: str  # SPIFFE URI of the MCP server
    image_digest: HashValue
    slsa_level: SlsaLevel
    phase2_attested: bool = False
    sbom: Optional[Sbom] = None


class ToolEntry(SpecModel):
    """One tool in the bound catalog - spec Section 3.2.3.

    Field names follow the spec's protocol-agnostic forms: ``tool_name`` is
    the protocol-native tool name (e.g. MCP tool name) and ``endpoint_id``
    is the SPIFFE URI of the tool endpoint server (e.g. MCP server).
    """

    tool_id: str  # reverse-domain tool identifier
    tool_name: str
    endpoint_id: str  # SPIFFE URI of the tool endpoint server
    schema_hash: HashValue
    # description_hash is bound separately from schema_hash: MCP tool poisoning
    # attacks target descriptions, not schemas. Both must be bound independently.
    description_hash: HashValue
    version: str
    permission_scope: Optional[str] = None
    egress_destinations: list[str] = Field(default_factory=list)


class ScopeGrant(SpecModel):
    tools: list[str] = Field(default_factory=list)
    data_classifications: list[DataClassification] = Field(default_factory=list)
    # Default 3 per spec 3.4.1; verifying parties MUST apply 3 when omitted.
    max_delegation_depth: int = Field(default=DEFAULT_MAX_DELEGATION_DEPTH, ge=0)
    ttl_seconds: Optional[int] = Field(default=None, ge=1)
    constraints: list[str] = Field(default_factory=list)


class ApprovedScope(SpecModel):
    artifacts: list[str]
    risk_tier: RiskTier
    approval_duration_seconds: int = Field(ge=1)
    conditions: list[str] = Field(default_factory=list)


class HitlApproval(SpecModel):
    approval_id: ManifestId
    # MUST NOT be a SPIFFE URI - human identity uses an OIDC subject,
    # mailto: URI, or W3C DID (spec Section 3.5).
    approver_id: str
    approver_identity_type: ApproverIdentityType
    # REQUIRED when approver_identity_type is oidc (spec Section 3.5)
    approver_oidc_issuer: Optional[str] = None
    approver_role: str
    approved_at: datetime
    approved_scope: ApprovedScope
    approval_signature: str
    approval_method: ApprovalMethod
    evidence_uri: str

    @field_validator("approver_id")
    @classmethod
    def _approver_id_must_not_be_spiffe(cls, v: str) -> str:
        if v.startswith("spiffe://"):
            raise ValueError(
                "approver_id MUST NOT be a SPIFFE URI - SPIFFE identifies machine "
                "workloads, not humans. Use an OIDC subject, mailto: URI, or W3C "
                "DID (spec Section 3.5, ADR-0009 scope note)."
            )
        return v

    @model_validator(mode="after")
    def _validate_oidc_issuer(self) -> "HitlApproval":
        if (
            self.approver_identity_type == ApproverIdentityType.oidc
            and not self.approver_oidc_issuer
        ):
            raise ValueError(
                "approver_oidc_issuer is REQUIRED when approver_identity_type "
                "is 'oidc' (spec Section 3.5)"
            )
        return self


class EscalationPolicy(SpecModel):
    trigger: Optional[str] = None  # Cedar policy fragment
    escalation_target: Optional[str] = None  # SPIFFE URI of escalation authority
    timeout_action: TimeoutAction  # REQUIRED when escalation_policy is present


class HitlRuntime(SpecModel):
    """Runtime human oversight capabilities - spec Section 3.5 (Art. 14(4)(a)).

    All three endpoint/mechanism fields are REQUIRED for Level 2+ conformance;
    they are modeled as optional because Level 0/1 manifests may omit the block
    contents.
    """

    interrupt_endpoint: Optional[str] = None
    override_mechanism: Optional[OverrideMechanism] = None
    monitoring_endpoint: Optional[str] = None
    automation_bias_disclosure: Optional[str] = None


class InclusionProof(SpecModel):
    """Transparency log inclusion proof - spec Section 3.6."""

    checkpoint: str  # signed tree head
    hashes: list[str]  # sha256 hex tile hashes
    tree_size: int = Field(ge=0)


class TransparencyLogEntry(SpecModel):
    """Sigstore-aligned transparency log entry - spec Section 3.6.

    A TOP-LEVEL manifest field (spec 3.1 / SPEC-10), populated after log
    submission. NOT part of the signing pre-image.
    """

    log_id: str  # SHA-256 fingerprint of the log's public key
    log_index: int = Field(ge=0)
    entry_uuid: str  # Rekor entry UUID
    integrated_time: int = Field(ge=0)  # Unix epoch seconds
    inclusion_proof: InclusionProof


class LogRetention(SpecModel):
    """Declared log retention policy - spec Section 8.1 / REG-002."""

    minimum_retention_days: int = Field(ge=1)
    regulatory_retention_override: Optional[int] = Field(default=None, ge=1)
    retention_enforced_by: str


class DataScope(SpecModel):
    """GDPR processing scope disclosure - spec Section 9.3 / REG-005."""

    personal_data_categories: list[str] = Field(default_factory=list)
    legal_basis: list[str] = Field(default_factory=list)
    automated_decision_making: bool
    dpia_reference: Optional[str] = None


class OperationalLifecycle(SpecModel):
    """EU AI Act Art. 13(3)(c)/(e) lifecycle disclosures - spec Section 9.4."""

    expected_lifetime_days: int = Field(ge=1)
    planned_maintenance_schedule: Optional[str] = None
    update_policy: Optional[str] = None
    reissuance_triggers: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Artifact bindings - one per spec section 3.2.x
# ---------------------------------------------------------------------------


class SystemPromptBinding(SpecModel):
    """Artifact #1 - spec Section 3.2.1."""

    hash: HashValue
    hash_algorithm: str = "SHA-256"
    version: str
    classification: DataClassification
    language: Optional[str] = None
    safety_level: Optional[str] = None
    bound_at: datetime


class PolicyBundleBinding(SpecModel):
    """Artifact #2 - spec Section 3.2.2."""

    hash: HashValue
    policy_language: PolicyLanguage
    version: str
    enforcement_mode: EnforcementMode
    scope: list[str] = Field(default_factory=list)
    # REQUIRED when policy_language is yaml-agt or composite (spec 3.2.2)
    agt_version: Optional[str] = None
    bound_at: datetime

    @model_validator(mode="after")
    def _validate_agt_version(self) -> "PolicyBundleBinding":
        if (
            self.policy_language in (PolicyLanguage.yaml_agt, PolicyLanguage.composite)
            and self.agt_version is None
        ):
            raise ValueError(
                "agt_version is REQUIRED when policy_language is "
                f"'{self.policy_language.value}' (spec Section 3.2.2)"
            )
        return self


class ToolManifestBinding(SpecModel):
    """Artifact #3 - spec Section 3.2.3."""

    catalog_hash: HashValue
    tools: list[ToolEntry]
    allow_dynamic_registration: bool = False
    rug_pull_policy: RugPullPolicy
    bound_at: datetime


class ModelIdentityBinding(SpecModel):
    """Artifact #4 - spec Section 3.2.4.

    model_hash conditionality (spec 3.2.4):
      - deployment_type=api or third-party-api -> model_hash MUST be null and
        model_attestation_type MUST be 'provider-asserted'
      - deployment_type=local or confidential-inference -> model_hash REQUIRED
        and model_attestation_type MUST be 'hash-bound'
    """

    provider: str
    model_id: str
    version: str
    capability_level: Optional[str] = None
    safety_alignment_version: Optional[str] = None
    quantization: str = "none"
    deployment_type: DeploymentType
    model_hash: Optional[HashValue] = None
    model_attestation_type: ModelAttestationType
    bound_at: datetime

    @model_validator(mode="after")
    def _validate_model_hash(self) -> "ModelIdentityBinding":
        if self.deployment_type in (DeploymentType.api, DeploymentType.third_party_api):
            if self.model_hash is not None:
                raise ValueError(
                    "model_hash MUST be null when deployment_type is "
                    f"'{self.deployment_type.value}' (spec Section 3.2.4). "
                    "API models are attested by provider+version, not binary hash."
                )
            if self.model_attestation_type != ModelAttestationType.provider_asserted:
                raise ValueError(
                    "model_attestation_type MUST be 'provider-asserted' when "
                    "model_hash is null (spec Section 3.2.4)"
                )
        else:
            if self.model_hash is None:
                raise ValueError(
                    f"model_hash is REQUIRED when deployment_type='{self.deployment_type.value}'"
                )
            if self.model_attestation_type != ModelAttestationType.hash_bound:
                raise ValueError(
                    "model_attestation_type MUST be 'hash-bound' when "
                    "model_hash is non-null (spec Section 3.2.4)"
                )
        return self


class RagCorpusBinding(SpecModel):
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


class MemoryBaselineBinding(SpecModel):
    """Artifact #6 - spec Section 3.2.6.

    Conditionality (spec 3.2.6):
      - memory_type=none       -> snapshot_hash MUST be null; ttl_seconds omitted
      - memory_type=session    -> snapshot_hash REQUIRED
      - memory_type=persistent -> snapshot_hash and ttl_seconds REQUIRED
      - memory_type=shared     -> snapshot_hash, ttl_seconds and
                                  shared_memory_owner REQUIRED
    ttl_seconds: min 3600 (1 hour), max 7776000 (90 days).
    """

    baseline_id: ManifestId
    snapshot_hash: Optional[HashValue] = None
    memory_type: MemoryType
    store: str
    approved_at: datetime
    ttl_seconds: Optional[int] = Field(default=None, ge=3_600, le=7_776_000)
    drift_policy: DriftPolicy
    # manifest_id of the agent holding the authoritative snapshot
    shared_memory_owner: Optional[ManifestId] = None
    check_interval_seconds: Optional[int] = Field(default=None, ge=1)
    bound_at: datetime

    @model_validator(mode="after")
    def _validate_memory_type_conditionality(self) -> "MemoryBaselineBinding":
        if self.memory_type == MemoryType.none:
            if self.snapshot_hash is not None:
                raise ValueError(
                    "snapshot_hash MUST be null when memory_type is 'none' "
                    "(spec Section 3.2.6)"
                )
        elif self.snapshot_hash is None:
            raise ValueError(
                "snapshot_hash is REQUIRED when memory_type is "
                f"'{self.memory_type.value}' (spec Section 3.2.6)"
            )
        if (
            self.memory_type in (MemoryType.persistent, MemoryType.shared)
            and self.ttl_seconds is None
        ):
            raise ValueError(
                "ttl_seconds is REQUIRED when memory_type is 'persistent' or "
                "'shared' (spec Section 3.2.6)"
            )
        if self.memory_type == MemoryType.shared and self.shared_memory_owner is None:
            raise ValueError(
                "shared_memory_owner is REQUIRED when memory_type is 'shared' "
                "(spec Section 3.2.6)"
            )
        if self.memory_type != MemoryType.shared and self.shared_memory_owner is not None:
            raise ValueError(
                "shared_memory_owner is only valid when memory_type is 'shared' "
                "(spec Section 3.2.6)"
            )
        return self

class MemoryCheckpointBinding(SpecModel):
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


class DecisionTraceBinding(SpecModel):
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


class SupplyChainBinding(SpecModel):
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


class DelegationHop(SpecModel):
    """One hop in the A2A delegation chain (Artifact #8 - spec Section 3.4)."""

    hop: int = Field(ge=0)
    principal_type: PrincipalType
    principal_id: str
    delegated_at: datetime
    scope_grant: ScopeGrant
    delegation_signature: str
    principal_manifest_id: Optional[ManifestId] = None
    principal_attestation_hash: Optional[HashValue] = None


class HitlRecord(SpecModel):
    """Artifact #10 - spec Section 3.5.

    ``required=true`` with an empty ``approvals`` list is structurally valid:
    approvals attach post-issuance (the signing pre-image normalizes
    ``approvals`` to ``[]`` - spec Section 3.6 / ADR-0006 as amended).
    Whether an approval must be present is enforced at verification time
    (``enforce_hitl``), not at schema validation time.
    """

    required: bool
    approvals: list[HitlApproval] = Field(default_factory=list)
    escalation_policy: Optional[EscalationPolicy] = None
    hitl_runtime: Optional[HitlRuntime] = None


class ArtifactBindings(SpecModel):
    """Container for the 8 artifact bindings that live under `artifacts`."""

    system_prompt: SystemPromptBinding
    policy_bundle: PolicyBundleBinding
    tool_manifest: Optional[ToolManifestBinding] = None
    model_identity: ModelIdentityBinding
    rag_corpus: Optional[RagCorpusBinding] = None
    memory_baseline: Optional[MemoryBaselineBinding] = None
    decision_trace: Optional[DecisionTraceBinding] = None
    supply_chain: Optional[SupplyChainBinding] = None


class ManifestSignature(SpecModel):
    """Manifest signature block - spec Section 3.6.

    Signature field conditionality:
      - algorithm=Ed25519 or ML-DSA-65 -> signature_value REQUIRED
      - algorithm=hybrid-Ed25519-ML-DSA-65 -> classical_signature and
        pq_signature REQUIRED (signature_value may be empty/omitted)
    """

    algorithm: SignatureAlgorithm
    key_id: str
    key_type: KeyType
    signed_at: datetime
    signed_fields: list[str] = Field(default_factory=lambda: list(SIGNED_FIELDS))
    signature_value: Optional[str] = None
    classical_signature: Optional[str] = None
    pq_signature: Optional[str] = None

    @model_validator(mode="after")
    def _validate_signature_conditionality(self) -> "ManifestSignature":
        if self.algorithm == SignatureAlgorithm.hybrid:
            if not self.classical_signature or not self.pq_signature:
                raise ValueError(
                    "classical_signature and pq_signature are REQUIRED when "
                    "algorithm is 'hybrid-Ed25519-ML-DSA-65' (spec Section 3.6)"
                )
        else:
            if not self.signature_value:
                raise ValueError(
                    "signature_value is REQUIRED when algorithm is "
                    f"'{self.algorithm.value}' (spec Section 3.6)"
                )
            if self.classical_signature or self.pq_signature:
                raise ValueError(
                    "classical_signature and pq_signature are only valid when "
                    "algorithm is 'hybrid-Ed25519-ML-DSA-65' (spec Section 3.6)"
                )
        return self


# ---------------------------------------------------------------------------
# Root model
# ---------------------------------------------------------------------------


class Manifest(SpecModel):
    """Root Agent Manifest document - spec Section 3.1."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    context: str = Field(
        default="https://agentmanifest.agentrust.io/v0.1/context.json",
        alias="@context",
    )
    type: str = Field(default="AgentManifest", alias="@type")
    manifest_id: ManifestId
    previous_manifest_id: Optional[ManifestId] = None
    agent_id: str  # SPIFFE URI
    version: str = "0.1"
    min_verifier_version: Optional[str] = None
    issued_at: datetime
    expires_at: datetime
    issuer: str  # SPIFFE URI of signing authority
    crypto_profile: CryptoProfile = CryptoProfile.standard
    artifacts: ArtifactBindings
    # attestation is appended by the TEE at launch - excluded from signature pre-image
    attestation: Optional[dict[str, Any]] = None
    # CONDITIONALLY REQUIRED; an empty array is invalid - omit the field
    # entirely when there is no delegation (spec 3.1 cardinality table).
    delegation_chain: Optional[list[DelegationHop]] = Field(default=None, min_length=1)
    hitl_record: Optional[HitlRecord] = None
    # References the previous manifest's log entry on key rotation (spec 2.2);
    # part of the signing pre-image, unlike transparency_log_entry.
    prior_transparency_log_entry: Optional[TransparencyLogEntry] = None
    log_retention: Optional[LogRetention] = None
    data_scope: Optional[DataScope] = None
    operational_lifecycle: Optional[OperationalLifecycle] = None
    signature: Optional[ManifestSignature] = None
    # Populated after transparency log submission (spec 3.6 ordering rules);
    # NOT covered by the signature.
    transparency_log_entry: Optional[TransparencyLogEntry] = None

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
        chain = self.delegation_chain
        if not chain:
            return self
        # One depth rule, shared with the runtime verifier (_delegation.py):
        # depth = number of sub-delegation hops below the root = len(chain) - 1.
        root_max_depth = chain[0].scope_grant.max_delegation_depth
        if delegation_depth_exceeded(len(chain), root_max_depth):
            raise ValueError(
                f"delegation_chain depth {len(chain) - 1} exceeds "
                f"root max_delegation_depth {root_max_depth}"
            )
        for i, hop in enumerate(chain):
            if hop.hop != i:
                raise ValueError(f"delegation_chain[{i}].hop is {hop.hop}, expected {i}")
        return self

    def json_schema(self) -> dict[str, Any]:
        """Export JSON Schema for non-Python verifier implementations."""
        return self.model_json_schema()
