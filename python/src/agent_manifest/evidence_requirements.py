"""Experimental signed intent; evidence and appraisal remain separate inputs.

This profile is not a registered or adopted specification. It uses v0.2 COSE
with an explicit, issuer-signed profile that older model validators reject.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

EXPERIMENTAL_PROFILE = "evidence-requirements-experimental-v1"
ComponentId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
]
Name = Annotated[str, Field(min_length=1, max_length=256)]


class RequirementModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ComponentRequirement(RequirementModel):
    component_id: ComponentId
    component_type: Literal[
        "identity",
        "runtime",
        "accelerator",
        "code",
        "policy",
        "model",
        "tool-catalog",
        "mcp-server",
        "guardrail",
        "data-state",
    ]
    required: bool
    accepted_profiles: Annotated[list[Name], Field(min_length=1, max_length=16)]
    accepted_appraisal_authorities: Annotated[
        list[Name], Field(min_length=1, max_length=16)
    ]
    maximum_age_seconds: Annotated[int, Field(ge=1, le=86400)]
    expected_observed_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")] | None = None
    artifact_ref: (
        Literal[
            "artifacts.system_prompt",
            "artifacts.policy_bundle",
            "artifacts.tool_manifest",
            "artifacts.model_identity",
            "artifacts.rag_corpus",
            "artifacts.memory_baseline",
            "artifacts.decision_trace",
            "artifacts.supply_chain",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def unique_lists(self) -> ComponentRequirement:
        for values in (self.accepted_profiles, self.accepted_appraisal_authorities):
            if len(values) != len(set(values)):
                raise ValueError("requirement lists contain duplicates")
        return self


class RequiredBinding(RequirementModel):
    source: ComponentId
    target: ComponentId
    relationship: Literal["same-workload"]
    accepted_methods: Annotated[
        list[Literal["same-instance-v1"]], Field(min_length=1, max_length=1)
    ]


class EvidenceRequirements(RequirementModel):
    components: Annotated[
        list[ComponentRequirement], Field(min_length=1, max_length=64)
    ]
    required_bindings: Annotated[list[RequiredBinding], Field(max_length=128)]
    combination_policy_ref: Name

    @model_validator(mode="after")
    def topology(self) -> EvidenceRequirements:
        ids = [c.component_id for c in self.components]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate component IDs")
        bindings = [
            (b.source, b.target, b.relationship) for b in self.required_bindings
        ]
        if len(bindings) != len(set(bindings)):
            raise ValueError("duplicate relationships")
        for binding in self.required_bindings:
            if binding.source == binding.target:
                raise ValueError("self relationship")
            if binding.source not in ids or binding.target not in ids:
                raise ValueError("undeclared relationship endpoint")
        return self


def manifest_digest(artifact: bytes | dict[str, Any], *, media_type: str) -> str:
    """Digest an exact COSE artifact, or a complete canonical legacy document.

    This helper does not authenticate the artifact. The legacy construction
    includes detached signature and attachments; it is not the signing preimage.
    Raw legacy JSON is deliberately unsupported, avoiding duplicate-key ambiguity.
    """
    if media_type == "application/agent-manifest+cose":
        if type(artifact) is not bytes or not artifact or len(artifact) > 1_048_576:
            raise ValueError("manifest bytes required within size bound")
        raw = artifact
    elif media_type == "application/agent-manifest+json":
        from ._canonicalize import canonicalize

        if type(artifact) is not dict or artifact.get("version") != "0.1":
            raise ValueError("complete legacy manifest object required")
        try:
            # Nulls kept: this digests the whole object as held, not the
            # null-excluding signing pre-image.
            raw = canonicalize(artifact, exclude_none=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("legacy artifact is not canonicalizable") from exc
        if len(raw) > 1_048_576:
            raise ValueError("legacy artifact exceeds size bound")
    else:
        raise ValueError("unsupported manifest media type")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class VerifiedRequirements:
    manifest_digest: str
    manifest_id: str
    agent_id: str
    agent_instance_id: str | None
    expires_at: int
    requirements: EvidenceRequirements
    # Whitelisted normalized outcomes, never raw mismatch detail or evidence.
    artifact_results: tuple[tuple[str, str], ...]


def verify_evidence_manifest(
    artifact: bytes, context: Any, revocation_store: Any
) -> VerifiedRequirements:
    """Authenticate intent with the normal SDK and retain exact artifact binding.

    Refuses composition-only, missing requirements and any non-VALID appraisal.
    A requirements declaration does not assert runtime evidence was appraised.
    """
    from . import verify_cose_manifest, verify_manifest
    from ._verify import _parse_timestamp

    artifact_hash = manifest_digest(
        artifact, media_type="application/agent-manifest+cose"
    )
    result = verify_manifest(artifact, context, revocation_store)
    if result.result.value != "VALID":
        raise ValueError("manifest appraisal not valid: " + result.result.value)
    manifest = verify_cose_manifest(artifact, context.trusted_keys).manifest
    if manifest.get("profile") != EXPERIMENTAL_PROFILE:
        raise ValueError("signed experimental requirements profile required")
    requirements = EvidenceRequirements.model_validate(
        manifest.get("evidence_requirements")
    )
    fields = result.fields_verified.model_dump(mode="json")
    allowed = {
        "system_prompt",
        "policy_bundle",
        "tool_manifest",
        "model_identity",
        "rag_corpus",
        "memory_baseline",
        "decision_trace",
        "supply_chain",
    }
    projection = tuple(
        sorted((key, str(value)) for key, value in fields.items() if key in allowed)
    )
    # The verifier's own parser, so the expiry read here is the one it appraised.
    expiry = _parse_timestamp(manifest["expires_at"])
    return VerifiedRequirements(
        artifact_hash,
        manifest["manifest_id"],
        manifest["agent_id"],
        manifest.get("agent_instance_id"),
        int(expiry.timestamp()),
        requirements,
        projection,
    )
