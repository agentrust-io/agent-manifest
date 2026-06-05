# Core models

The `Manifest` and all nested types are Pydantic v2 models. All fields are serialisable to JSON via `.model_dump(mode="json")`. See [ADR-0004](../adr/0004-pydantic-v2-schema-modeling.md) for the rationale.

## Manifest

::: agent_manifest.models.Manifest

## Artifact bindings

::: agent_manifest.models.ArtifactBindings

::: agent_manifest.models.ModelIdentityBinding

::: agent_manifest.models.SystemPromptBinding

::: agent_manifest.models.PolicyBundleBinding

::: agent_manifest.models.ToolManifestBinding

::: agent_manifest.models.RagCorpusBinding

::: agent_manifest.models.MemoryBaselineBinding

::: agent_manifest.models.DecisionTraceBinding

::: agent_manifest.models.SupplyChainBinding

## Delegation and approval

::: agent_manifest.models.DelegationHop

::: agent_manifest.models.ScopeGrant

::: agent_manifest.models.HitlRecord

::: agent_manifest.models.HitlApproval

## Signature

::: agent_manifest.models.ManifestSignature

## Supporting types

::: agent_manifest.models.ToolEntry

::: agent_manifest.models.McpServer

::: agent_manifest.models.PoisoningScan

::: agent_manifest.models.SlsaProvenance

::: agent_manifest.models.Sbom

## Enumerations

::: agent_manifest.models.CryptoProfile

::: agent_manifest.models.RiskTier

::: agent_manifest.models.DataClassification

::: agent_manifest.models.PrincipalType

::: agent_manifest.models.SlsaLevel

::: agent_manifest.models.PolicyLanguage

::: agent_manifest.models.EnforcementMode

::: agent_manifest.models.DeploymentType

::: agent_manifest.models.MemoryType

::: agent_manifest.models.TraceType

::: agent_manifest.models.SbomFormat

::: agent_manifest.models.PoisoningResult

::: agent_manifest.models.ApprovalMethod

::: agent_manifest.models.SignatureAlgorithm

::: agent_manifest.models.KeyType
