"""Non-normative memory checkpoint behavioral assessment helpers.

This module implements the reference harness boundary proposed in issue #298.
It deliberately does not modify Agent Manifest conformance or checkpoint
promotion policy.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Callable, Literal, Protocol, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._canonicalize import canonical_hash
from ._types import HashValue


MIN_REPEATABILITY_TRIALS = 20
JsonScalar: TypeAlias = str | int | bool | None


class AssessmentModel(BaseModel):
    """Strict, immutable base model for assessment evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class BehavioralResult(str, Enum):
    # Bandit B105 is a false positive here: this is a public result token.
    pass_ = "pass"  # nosec B105
    fail = "fail"
    indeterminate = "indeterminate"


class MaterialAccess(str, Enum):
    public = "public"
    restricted = "restricted"
    unavailable_to_verifier = "unavailable_to_verifier"


class AdapterCapability(str, Enum):
    deterministic = "deterministic"
    unsupported_or_unknown = "unsupported_or_unknown"


class ObservedStatus(str, Enum):
    stable = "stable"
    unstable = "unstable"
    not_run = "not_run"


class RequiredIn(str, Enum):
    baseline = "baseline"
    candidate = "candidate"
    both = "both"


class SeverityClass(str, Enum):
    behavioral = "behavioral"
    confidentiality = "confidentiality"


class IndeterminateReason(str, Enum):
    adapter_unsupported = "adapter_unsupported"
    repeatability_unstable = "repeatability_unstable"
    repeatability_not_run = "repeatability_not_run"
    baseline_precondition_unmet = "baseline_precondition_unmet"
    id_churn = "id_churn"


class RetrieverProfile(AssessmentModel):
    implementation_id: str
    implementation_version: str
    adapter_version: str
    harness_version: str = "0.1"
    adapter_capability: AdapterCapability
    embedding_model_id: str | None = None
    embedding_model_revision: str | None = None
    quantization: str | None = None
    tokenizer_id: str | None = None
    query_preprocessing: tuple[str, ...] = ()
    distance_metric: str
    index_implementation: str
    index_build_config: dict[str, JsonScalar] = Field(default_factory=dict)
    filtering_rules: tuple[str, ...] = ()
    top_k: int = Field(gt=0)
    truncation_rule: str
    reranker_id: str | None = None
    reranker_config: dict[str, JsonScalar] = Field(default_factory=dict)
    tie_policy: str | None = None
    seed: int | None = None
    opaque_components: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _require_tie_policy_for_deterministic(self) -> "RetrieverProfile":
        if (
            self.adapter_capability is AdapterCapability.deterministic
            and not (self.tie_policy or "").strip()
        ):
            raise ValueError("deterministic profiles require an explicit tie_policy")
        return self


class StateReference(AssessmentModel):
    checkpoint_digest: HashValue
    retrieval_state_digest: HashValue | None = None
    indexed_item_count: int | None = Field(default=None, ge=0)


class RuntimeObservation(AssessmentModel):
    runtime_id: str | None = None
    embedding_dimension: int | None = Field(default=None, gt=0)
    indexed_item_count: int | None = Field(default=None, ge=0)
    fingerprint_probe_digest: HashValue | None = None


class RetrievedItem(AssessmentModel):
    item_key: str
    item_version_digest: HashValue
    rank: int = Field(ge=1)
    scope_labels: tuple[str, ...] = ()


class RetrievalRequest(AssessmentModel):
    query: str
    context: dict[str, str] = Field(default_factory=dict)


class RepeatabilityEvidence(AssessmentModel):
    trials: int = Field(ge=0)
    distinct_orderings_observed: int = Field(ge=0)
    observed_status: ObservedStatus
    tie_events_observed: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_status(self) -> "RepeatabilityEvidence":
        if self.observed_status is ObservedStatus.not_run:
            if self.trials != 0 or self.distinct_orderings_observed != 0:
                raise ValueError("not_run repeatability evidence must record zero trials/orderings")
            return self
        if self.trials < MIN_REPEATABILITY_TRIALS:
            raise ValueError(
                f"repeatability evidence requires at least {MIN_REPEATABILITY_TRIALS} trials"
            )
        if self.observed_status is ObservedStatus.stable and self.distinct_orderings_observed != 1:
            raise ValueError("stable repeatability evidence requires exactly one observed ordering")
        if self.observed_status is ObservedStatus.unstable and self.distinct_orderings_observed < 2:
            raise ValueError("unstable repeatability evidence requires at least two observed orderings")
        return self


class InvocationEvidence(AssessmentModel):
    state_name: str
    request_digest: HashValue
    repeatability: RepeatabilityEvidence


class ItemReference(AssessmentModel):
    key: str
    required_in: RequiredIn


class ProbeCommon(AssessmentModel):
    probe_id: str
    required: bool = True


class CorrectionPrecedenceProbe(ProbeCommon):
    kind: Literal["correction_precedence"] = "correction_precedence"
    query: str
    context: dict[str, str] = Field(default_factory=dict)
    superseded: ItemReference
    correction: ItemReference
    severity: SeverityClass = SeverityClass.behavioral


class AnchorPreservationProbe(ProbeCommon):
    kind: Literal["anchor_preservation"] = "anchor_preservation"
    query: str
    context: dict[str, str] = Field(default_factory=dict)
    anchor: ItemReference
    max_rank: int = Field(gt=0)
    severity: SeverityClass = SeverityClass.behavioral


class ScopeIsolationProbe(ProbeCommon):
    kind: Literal["scope_isolation"] = "scope_isolation"
    query: str
    context: dict[str, str] = Field(default_factory=dict)
    forbidden_item_keys: tuple[str, ...] = ()
    forbidden_scope_labels: tuple[str, ...] = ()
    severity: SeverityClass = SeverityClass.confidentiality

    @model_validator(mode="after")
    def _require_forbidden_target(self) -> "ScopeIsolationProbe":
        if not self.forbidden_item_keys and not self.forbidden_scope_labels:
            raise ValueError("scope isolation probes require a forbidden key or scope label")
        return self


class StateConditionedDifferentiationProbe(ProbeCommon):
    kind: Literal["state_conditioned_differentiation"] = "state_conditioned_differentiation"
    query: str
    context_a: dict[str, str]
    context_b: dict[str, str]
    a_required_keys: tuple[str, ...] = ()
    a_forbidden_keys: tuple[str, ...] = ()
    b_required_keys: tuple[str, ...] = ()
    b_forbidden_keys: tuple[str, ...] = ()
    require_distinct_ordering: bool = True
    severity: SeverityClass = SeverityClass.behavioral

    @model_validator(mode="after")
    def _require_expectation(self) -> "StateConditionedDifferentiationProbe":
        if self.context_a == self.context_b:
            raise ValueError("state-conditioned probes require distinct context_a and context_b")
        if not (
            self.a_required_keys
            or self.a_forbidden_keys
            or self.b_required_keys
            or self.b_forbidden_keys
            or self.require_distinct_ordering
        ):
            raise ValueError("state-conditioned probes require at least one explicit expectation")
        return self


Probe: TypeAlias = Annotated[
    CorrectionPrecedenceProbe
    | AnchorPreservationProbe
    | ScopeIsolationProbe
    | StateConditionedDifferentiationProbe,
    Field(discriminator="kind"),
]


class ProbeSuite(AssessmentModel):
    version: Literal["0.1"] = "0.1"
    probes: tuple[Probe, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _require_gating_probe(self) -> "ProbeSuite":
        probe_ids = [probe.probe_id for probe in self.probes]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("probe suites require unique probe_id values")
        if not any(probe.required for probe in self.probes):
            raise ValueError("probe suites require at least one required probe")
        return self


class ProbeResult(AssessmentModel):
    probe_id: str
    required: bool
    result: BehavioralResult
    severity: SeverityClass
    reasons: tuple[IndeterminateReason, ...] = ()
    violations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_reasons(self) -> "ProbeResult":
        if self.result is BehavioralResult.indeterminate and not self.reasons:
            raise ValueError("indeterminate results require at least one reason")
        if self.result is not BehavioralResult.indeterminate and self.reasons:
            raise ValueError("only indeterminate results may carry indeterminate reasons")
        return self


class Coverage(AssessmentModel):
    required_probe_count: int = Field(ge=0)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    indeterminate: int = Field(ge=0)
    indeterminate_rate: float = Field(ge=0.0, le=1.0)


class SecurityFlags(AssessmentModel):
    contains_confidentiality_failure: bool = False


class MemoryCheckpointAssessment(AssessmentModel):
    type: Literal["MemoryCheckpointAssessment"] = "MemoryCheckpointAssessment"
    version: Literal["0.1"] = "0.1"
    baseline_state: StateReference
    candidate_state: StateReference
    probe_suite_digest: HashValue
    retriever_profile_digest: HashValue
    assessed_at: datetime
    material_access: MaterialAccess
    runtime_observation: RuntimeObservation | None = None
    invocation_evidence: tuple[InvocationEvidence, ...]
    probe_results: tuple[ProbeResult, ...]
    coverage: Coverage
    security_flags: SecurityFlags
    result: BehavioralResult

    @field_validator("assessed_at")
    @classmethod
    def _require_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("assessed_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_internal_consistency(self) -> "MemoryCheckpointAssessment":
        probe_ids = [item.probe_id for item in self.probe_results]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("probe_results must contain unique probe_id values")

        invocation_ids = [
            (item.state_name, str(item.request_digest))
            for item in self.invocation_evidence
        ]
        if len(invocation_ids) != len(set(invocation_ids)):
            raise ValueError(
                "invocation_evidence must contain unique state/request pairs"
            )

        required = [item for item in self.probe_results if item.required]
        if not required:
            raise ValueError("assessment must contain at least one required probe result")

        passed = sum(item.result is BehavioralResult.pass_ for item in required)
        failed = sum(item.result is BehavioralResult.fail for item in required)
        indeterminate = sum(
            item.result is BehavioralResult.indeterminate for item in required
        )
        count = len(required)
        expected_rate = indeterminate / count

        if self.coverage.required_probe_count != count:
            raise ValueError("coverage.required_probe_count does not match probe_results")
        if self.coverage.passed != passed:
            raise ValueError("coverage.passed does not match probe_results")
        if self.coverage.failed != failed:
            raise ValueError("coverage.failed does not match probe_results")
        if self.coverage.indeterminate != indeterminate:
            raise ValueError("coverage.indeterminate does not match probe_results")
        if abs(self.coverage.indeterminate_rate - expected_rate) > 1e-12:
            raise ValueError("coverage.indeterminate_rate does not match probe_results")

        expected_result = (
            BehavioralResult.fail
            if failed
            else BehavioralResult.indeterminate
            if indeterminate
            else BehavioralResult.pass_
        )
        if self.result is not expected_result:
            raise ValueError("assessment result does not match required probe results")

        confidentiality_failure = any(
            item.result is BehavioralResult.fail
            and item.severity is SeverityClass.confidentiality
            for item in self.probe_results
        )
        if (
            self.security_flags.contains_confidentiality_failure
            != confidentiality_failure
        ):
            raise ValueError(
                "security_flags.contains_confidentiality_failure does not match probe_results"
            )
        return self


class RetrieverAdapter(Protocol):
    """Minimal execution boundary for a memory assessment retriever."""

    @property
    def profile(self) -> RetrieverProfile: ...

    def state_reference(self, state_name: str) -> StateReference: ...

    def contains_item_key(self, state_name: str, item_key: str) -> bool: ...

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]: ...

    def runtime_observation(self) -> RuntimeObservation | None: ...


def canonical_model_hash(model: BaseModel) -> HashValue:
    """Return a repository-canonical SHA-256 digest for a Pydantic model."""

    digest = canonical_hash(model.model_dump(mode="json", exclude_none=True))
    return HashValue(digest)


def _ordered_identity(
    items: Sequence[RetrievedItem],
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    ordered = sorted(items, key=lambda item: item.rank)
    ranks = [item.rank for item in ordered]
    if len(ranks) != len(set(ranks)):
        raise ValueError("retrieval result contains duplicate ranks")
    item_keys = [item.item_key for item in ordered]
    if len(item_keys) != len(set(item_keys)):
        raise ValueError("retrieval result contains duplicate item_key values")
    return tuple(
        (
            item.item_key,
            str(item.item_version_digest),
            tuple(sorted(item.scope_labels)),
        )
        for item in ordered
    )


def _by_key(items: Sequence[RetrievedItem]) -> dict[str, RetrievedItem]:
    result: dict[str, RetrievedItem] = {}
    for item in items:
        if item.item_key in result:
            raise ValueError(f"retrieval result contains duplicate item_key {item.item_key!r}")
        result[item.item_key] = item
    return result


class AssessmentHarness:
    """Reference deterministic harness for `MemoryCheckpointAssessment/0.1`."""

    def __init__(self, *, repeatability_trials: int = MIN_REPEATABILITY_TRIALS) -> None:
        if repeatability_trials < MIN_REPEATABILITY_TRIALS:
            raise ValueError(
                f"repeatability_trials must be at least {MIN_REPEATABILITY_TRIALS}"
            )
        self._repeatability_trials = repeatability_trials

    def run(
        self,
        adapter: RetrieverAdapter,
        suite: ProbeSuite,
        *,
        baseline_state_name: str = "baseline",
        candidate_state_name: str = "candidate",
        material_access: MaterialAccess = MaterialAccess.public,
        assessed_at: datetime | None = None,
    ) -> MemoryCheckpointAssessment:
        profile = adapter.profile.model_copy(deep=True)
        suite_snapshot = suite.model_copy(deep=True)
        baseline_state = adapter.state_reference(baseline_state_name).model_copy(deep=True)
        candidate_state = adapter.state_reference(candidate_state_name).model_copy(deep=True)
        cache: dict[
            tuple[str, str], tuple[tuple[RetrievedItem, ...], RepeatabilityEvidence]
        ] = {}
        invocation_evidence: dict[tuple[str, str], InvocationEvidence] = {}

        def collect(
            state_name: str,
            request: RetrievalRequest,
        ) -> tuple[tuple[RetrievedItem, ...], RepeatabilityEvidence]:
            request_snapshot = request.model_copy(deep=True)
            request_digest = canonical_model_hash(request_snapshot)
            key = (state_name, str(request_digest))
            if key in cache:
                return cache[key]
            if profile.adapter_capability is AdapterCapability.unsupported_or_unknown:
                evidence = RepeatabilityEvidence(
                    trials=0,
                    distinct_orderings_observed=0,
                    observed_status=ObservedStatus.not_run,
                )
                result: tuple[RetrievedItem, ...] = ()
            else:
                observations: dict[
                    tuple[tuple[str, str, tuple[str, ...]], ...],
                    tuple[RetrievedItem, ...],
                ] = {}
                for _ in range(self._repeatability_trials):
                    current = tuple(
                        adapter.retrieve(
                            state_name,
                            request_snapshot.model_copy(deep=True),
                        )
                    )
                    ordering = _ordered_identity(current)
                    observations.setdefault(ordering, current)
                distinct = len(observations)
                evidence = RepeatabilityEvidence(
                    trials=self._repeatability_trials,
                    distinct_orderings_observed=distinct,
                    observed_status=(
                        ObservedStatus.stable if distinct == 1 else ObservedStatus.unstable
                    ),
                )
                result = next(iter(observations.values()))
            cache[key] = (result, evidence)
            invocation_evidence[key] = InvocationEvidence(
                state_name=state_name,
                request_digest=request_digest,
                repeatability=evidence,
            )
            return result, evidence

        results = [
            self._evaluate_probe(
                adapter,
                probe,
                baseline_state_name,
                candidate_state_name,
                collect,
                profile.adapter_capability,
            )
            for probe in suite_snapshot.probes
        ]

        required = [result for result in results if result.required]
        passed = sum(result.result is BehavioralResult.pass_ for result in required)
        failed = sum(result.result is BehavioralResult.fail for result in required)
        indeterminate = sum(
            result.result is BehavioralResult.indeterminate for result in required
        )
        count = len(required)
        coverage = Coverage(
            required_probe_count=count,
            passed=passed,
            failed=failed,
            indeterminate=indeterminate,
            indeterminate_rate=(indeterminate / count if count else 0.0),
        )
        aggregate = (
            BehavioralResult.fail
            if failed
            else BehavioralResult.indeterminate
            if indeterminate
            else BehavioralResult.pass_
        )
        security_flags = SecurityFlags(
            contains_confidentiality_failure=any(
                result.result is BehavioralResult.fail
                and result.severity is SeverityClass.confidentiality
                for result in results
            )
        )
        runtime_observation = adapter.runtime_observation()
        if (
            adapter.state_reference(baseline_state_name) != baseline_state
            or adapter.state_reference(candidate_state_name) != candidate_state
        ):
            raise RuntimeError("adapter state reference changed during assessment")
        return MemoryCheckpointAssessment(
            baseline_state=baseline_state,
            candidate_state=candidate_state,
            probe_suite_digest=canonical_model_hash(suite_snapshot),
            retriever_profile_digest=canonical_model_hash(profile),
            assessed_at=assessed_at or datetime.now(timezone.utc),
            material_access=material_access,
            runtime_observation=runtime_observation,
            invocation_evidence=tuple(invocation_evidence.values()),
            probe_results=tuple(results),
            coverage=coverage,
            security_flags=security_flags,
            result=aggregate,
        )

    def _identity_precondition(
        self,
        adapter: RetrieverAdapter,
        references: Sequence[ItemReference],
        baseline_state_name: str,
        candidate_state_name: str,
    ) -> bool:
        for reference in references:
            if reference.required_in in (RequiredIn.baseline, RequiredIn.both):
                if not adapter.contains_item_key(baseline_state_name, reference.key):
                    return False
            if reference.required_in in (RequiredIn.candidate, RequiredIn.both):
                if not adapter.contains_item_key(candidate_state_name, reference.key):
                    return False
        return True

    @staticmethod
    def _repeatability_reason(
        evidence: Sequence[RepeatabilityEvidence],
        capability: AdapterCapability,
    ) -> IndeterminateReason | None:
        if capability is AdapterCapability.unsupported_or_unknown:
            return IndeterminateReason.adapter_unsupported
        if any(item.observed_status is ObservedStatus.not_run for item in evidence):
            return IndeterminateReason.repeatability_not_run
        if any(item.observed_status is ObservedStatus.unstable for item in evidence):
            return IndeterminateReason.repeatability_unstable
        return None

    def _evaluate_probe(
        self,
        adapter: RetrieverAdapter,
        probe: Probe,
        baseline_state_name: str,
        candidate_state_name: str,
        collect: Callable[
            [str, RetrievalRequest],
            tuple[tuple[RetrievedItem, ...], RepeatabilityEvidence],
        ],
        capability: AdapterCapability,
    ) -> ProbeResult:
        if isinstance(probe, CorrectionPrecedenceProbe):
            refs = (probe.superseded, probe.correction)
            if not self._identity_precondition(
                adapter, refs, baseline_state_name, candidate_state_name
            ):
                return self._indeterminate(probe, IndeterminateReason.id_churn)
            request = RetrievalRequest(query=probe.query, context=probe.context)
            baseline, base_rep = collect(baseline_state_name, request)
            candidate, cand_rep = collect(candidate_state_name, request)
            repeat_reason = self._repeatability_reason((base_rep, cand_rep), capability)
            if repeat_reason is not None:
                return self._indeterminate(probe, repeat_reason)
            base_by_key = _by_key(baseline)
            if probe.superseded.key not in base_by_key:
                return self._indeterminate(
                    probe, IndeterminateReason.baseline_precondition_unmet
                )
            candidate_by_key = _by_key(candidate)
            correction = candidate_by_key.get(probe.correction.key)
            if correction is None:
                return self._fail(
                    probe, f"correction {probe.correction.key!r} was not retrieved"
                )
            superseded = candidate_by_key.get(probe.superseded.key)
            if superseded is not None and correction.rank >= superseded.rank:
                return self._fail(
                    probe,
                    f"correction rank {correction.rank} did not outrank superseded rank {superseded.rank}",
                )
            return self._pass(probe)

        if isinstance(probe, AnchorPreservationProbe):
            if not self._identity_precondition(
                adapter, (probe.anchor,), baseline_state_name, candidate_state_name
            ):
                return self._indeterminate(probe, IndeterminateReason.id_churn)
            request = RetrievalRequest(query=probe.query, context=probe.context)
            baseline, base_rep = collect(baseline_state_name, request)
            candidate, cand_rep = collect(candidate_state_name, request)
            repeat_reason = self._repeatability_reason((base_rep, cand_rep), capability)
            if repeat_reason is not None:
                return self._indeterminate(probe, repeat_reason)
            baseline_anchor = _by_key(baseline).get(probe.anchor.key)
            if baseline_anchor is None or baseline_anchor.rank > probe.max_rank:
                return self._indeterminate(
                    probe, IndeterminateReason.baseline_precondition_unmet
                )
            candidate_anchor = _by_key(candidate).get(probe.anchor.key)
            if candidate_anchor is None:
                return self._fail(probe, f"anchor {probe.anchor.key!r} was not retrieved")
            if candidate_anchor.rank > probe.max_rank:
                return self._fail(
                    probe,
                    f"anchor rank {candidate_anchor.rank} exceeds max_rank {probe.max_rank}",
                )
            return self._pass(probe)

        if isinstance(probe, ScopeIsolationProbe):
            request = RetrievalRequest(query=probe.query, context=probe.context)
            candidate, evidence = collect(candidate_state_name, request)
            repeat_reason = self._repeatability_reason((evidence,), capability)
            if repeat_reason is not None:
                return self._indeterminate(probe, repeat_reason)
            forbidden_keys = set(probe.forbidden_item_keys)
            forbidden_scopes = set(probe.forbidden_scope_labels)
            scope_violations: list[str] = []
            for item in candidate:
                if item.item_key in forbidden_keys:
                    scope_violations.append(f"forbidden item {item.item_key!r} was retrieved")
                overlap = forbidden_scopes.intersection(item.scope_labels)
                if overlap:
                    scope_violations.append(
                        f"item {item.item_key!r} carried forbidden scope labels {sorted(overlap)!r}"
                    )
            if scope_violations:
                return self._fail(probe, *scope_violations)
            return self._pass(probe)

        if isinstance(probe, StateConditionedDifferentiationProbe):
            required_keys = set(probe.a_required_keys).union(probe.b_required_keys)
            if any(
                not adapter.contains_item_key(candidate_state_name, key)
                for key in required_keys
            ):
                return self._indeterminate(probe, IndeterminateReason.id_churn)
            request_a = RetrievalRequest(query=probe.query, context=probe.context_a)
            request_b = RetrievalRequest(query=probe.query, context=probe.context_b)
            items_a, evidence_a = collect(candidate_state_name, request_a)
            items_b, evidence_b = collect(candidate_state_name, request_b)
            repeat_reason = self._repeatability_reason((evidence_a, evidence_b), capability)
            if repeat_reason is not None:
                return self._indeterminate(probe, repeat_reason)
            keys_a = tuple(item.item_key for item in sorted(items_a, key=lambda item: item.rank))
            keys_b = tuple(item.item_key for item in sorted(items_b, key=lambda item: item.rank))
            set_a = set(keys_a)
            set_b = set(keys_b)
            state_violations: list[str] = []
            for key in probe.a_required_keys:
                if key not in set_a:
                    state_violations.append(f"context A did not retrieve required item {key!r}")
            for key in probe.a_forbidden_keys:
                if key in set_a:
                    state_violations.append(f"context A retrieved forbidden item {key!r}")
            for key in probe.b_required_keys:
                if key not in set_b:
                    state_violations.append(f"context B did not retrieve required item {key!r}")
            for key in probe.b_forbidden_keys:
                if key in set_b:
                    state_violations.append(f"context B retrieved forbidden item {key!r}")
            if probe.require_distinct_ordering and keys_a == keys_b:
                state_violations.append("context A and B produced identical ordered item identities")
            if state_violations:
                return self._fail(probe, *state_violations)
            return self._pass(probe)

        raise TypeError(f"unsupported probe type {type(probe).__name__}")

    @staticmethod
    def _pass(probe: Probe) -> ProbeResult:
        return ProbeResult(
            probe_id=probe.probe_id,
            required=probe.required,
            result=BehavioralResult.pass_,
            severity=probe.severity,
        )

    @staticmethod
    def _fail(probe: Probe, *violations: str) -> ProbeResult:
        return ProbeResult(
            probe_id=probe.probe_id,
            required=probe.required,
            result=BehavioralResult.fail,
            severity=probe.severity,
            violations=tuple(violations),
        )

    @staticmethod
    def _indeterminate(probe: Probe, reason: IndeterminateReason) -> ProbeResult:
        return ProbeResult(
            probe_id=probe.probe_id,
            required=probe.required,
            result=BehavioralResult.indeterminate,
            severity=probe.severity,
            reasons=(reason,),
        )
