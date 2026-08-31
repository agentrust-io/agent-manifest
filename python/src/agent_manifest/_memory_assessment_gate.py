"""Non-normative applicability gate for memory checkpoint assessments.

The assessment artifact records what was evaluated and what happened. This
module models the separate relying-party question: whether the presented
assessment evidence satisfies one explicitly adopted approval gate.

It does not approve checkpoints, mutate evidence, or change Agent Manifest
conformance. A caller that adopts this gate remains responsible for enforcing
its result at the actual approval boundary.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import Enum

from pydantic import field_validator, model_validator

from ._memory_assessment import AssessmentModel, BehavioralResult, MemoryCheckpointAssessment
from ._types import HashValue


class ApplicabilityMismatch(str, Enum):
    """Why a presented assessment does not satisfy the required evidence shape."""

    baseline_checkpoint = "baseline_checkpoint"
    candidate_checkpoint = "candidate_checkpoint"
    baseline_retrieval_state = "baseline_retrieval_state"
    candidate_retrieval_state = "candidate_retrieval_state"
    probe_suite = "probe_suite"
    retriever_profile = "retriever_profile"
    before_evidence_window = "before_evidence_window"
    after_evidence_window = "after_evidence_window"


class GateFailureReason(str, Enum):
    """Why an adopted assessment gate is not satisfied."""

    no_applicable_assessment = "no_applicable_assessment"
    applicable_assessment_failed = "applicable_assessment_failed"
    applicable_assessment_indeterminate = "applicable_assessment_indeterminate"


class AssessmentGatePolicy(AssessmentModel):
    """Content requirements for one explicitly adopted assessment gate.

    The policy binds the evidence shape that must be presented at approval
    time. Retrieval-state digests and the time window are optional policy
    refinements. When supplied, they are load-bearing applicability criteria.
    """

    baseline_checkpoint_digest: HashValue
    candidate_checkpoint_digest: HashValue
    probe_suite_digest: HashValue
    retriever_profile_digest: HashValue
    baseline_retrieval_state_digest: HashValue | None = None
    candidate_retrieval_state_digest: HashValue | None = None
    assessed_not_before: datetime | None = None
    assessed_not_after: datetime | None = None

    @field_validator("assessed_not_before", "assessed_not_after")
    @classmethod
    def _require_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("assessment gate timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_evidence_window(self) -> "AssessmentGatePolicy":
        if (
            self.assessed_not_before is not None
            and self.assessed_not_after is not None
            and self.assessed_not_before > self.assessed_not_after
        ):
            raise ValueError("assessed_not_before must not be after assessed_not_after")
        return self


class AssessmentGateEvaluation(AssessmentModel):
    """Result of applying one adopted gate to presented assessment evidence."""

    satisfied: bool
    presented_assessment_count: int
    applicable_assessment_count: int
    applicable_results: tuple[BehavioralResult, ...] = ()
    non_applicable_mismatches: tuple[ApplicabilityMismatch, ...] = ()
    reasons: tuple[GateFailureReason, ...] = ()

    @model_validator(mode="after")
    def _validate_internal_consistency(self) -> "AssessmentGateEvaluation":
        if self.presented_assessment_count < 0:
            raise ValueError("presented_assessment_count must be non-negative")
        if self.applicable_assessment_count < 0:
            raise ValueError("applicable_assessment_count must be non-negative")
        if self.applicable_assessment_count > self.presented_assessment_count:
            raise ValueError("applicable assessment count cannot exceed presented count")
        if len(self.applicable_results) != self.applicable_assessment_count:
            raise ValueError("applicable_results must match applicable_assessment_count")

        has_fail = BehavioralResult.fail in self.applicable_results
        has_indeterminate = BehavioralResult.indeterminate in self.applicable_results

        if self.satisfied:
            if not self.applicable_results:
                raise ValueError("a satisfied gate requires applicable assessment evidence")
            if has_fail or has_indeterminate:
                raise ValueError("a satisfied gate requires every applicable result to pass")
            if self.reasons:
                raise ValueError("a satisfied gate cannot carry failure reasons")
            return self

        if not self.reasons:
            raise ValueError("an unsatisfied gate requires at least one failure reason")
        if not self.applicable_results:
            if GateFailureReason.no_applicable_assessment not in self.reasons:
                raise ValueError("missing applicable evidence must be reported explicitly")
            return self
        if GateFailureReason.no_applicable_assessment in self.reasons:
            raise ValueError("no_applicable_assessment conflicts with applicable evidence")
        if has_fail and GateFailureReason.applicable_assessment_failed not in self.reasons:
            raise ValueError("applicable fail must be reported explicitly")
        if (
            has_indeterminate
            and GateFailureReason.applicable_assessment_indeterminate not in self.reasons
        ):
            raise ValueError("applicable indeterminate must be reported explicitly")
        return self


def _applicability_mismatches(
    policy: AssessmentGatePolicy,
    assessment: MemoryCheckpointAssessment,
) -> tuple[ApplicabilityMismatch, ...]:
    mismatches: list[ApplicabilityMismatch] = []
    if assessment.baseline_state.checkpoint_digest != policy.baseline_checkpoint_digest:
        mismatches.append(ApplicabilityMismatch.baseline_checkpoint)
    if assessment.candidate_state.checkpoint_digest != policy.candidate_checkpoint_digest:
        mismatches.append(ApplicabilityMismatch.candidate_checkpoint)
    if assessment.probe_suite_digest != policy.probe_suite_digest:
        mismatches.append(ApplicabilityMismatch.probe_suite)
    if assessment.retriever_profile_digest != policy.retriever_profile_digest:
        mismatches.append(ApplicabilityMismatch.retriever_profile)
    if (
        policy.baseline_retrieval_state_digest is not None
        and assessment.baseline_state.retrieval_state_digest
        != policy.baseline_retrieval_state_digest
    ):
        mismatches.append(ApplicabilityMismatch.baseline_retrieval_state)
    if (
        policy.candidate_retrieval_state_digest is not None
        and assessment.candidate_state.retrieval_state_digest
        != policy.candidate_retrieval_state_digest
    ):
        mismatches.append(ApplicabilityMismatch.candidate_retrieval_state)
    if (
        policy.assessed_not_before is not None
        and assessment.assessed_at < policy.assessed_not_before
    ):
        mismatches.append(ApplicabilityMismatch.before_evidence_window)
    if (
        policy.assessed_not_after is not None
        and assessment.assessed_at > policy.assessed_not_after
    ):
        mismatches.append(ApplicabilityMismatch.after_evidence_window)
    return tuple(mismatches)


def evaluate_assessment_gate(
    policy: AssessmentGatePolicy,
    assessments: Sequence[MemoryCheckpointAssessment],
) -> AssessmentGateEvaluation:
    """Evaluate whether presented evidence satisfies an adopted assessment gate.

    Applicability is evaluated before behavioral outcome. Evidence that binds a
    different checkpoint, suite, retriever profile, required retrieval state,
    or evidence window does not satisfy this gate and remains valid evidence of
    whatever it actually assessed.

    The gate is pass-only: at least one applicable assessment must be present,
    and every presented applicable assessment must be ``pass``. ``fail`` and
    ``indeterminate`` remain distinct behavioral outcomes, but neither satisfies
    the approval gate. This function reports admissibility for this gate only;
    it never grants checkpoint approval.
    """

    applicable_results: list[BehavioralResult] = []
    mismatches: set[ApplicabilityMismatch] = set()

    for assessment in assessments:
        current_mismatches = _applicability_mismatches(policy, assessment)
        if current_mismatches:
            mismatches.update(current_mismatches)
            continue
        applicable_results.append(assessment.result)

    ordered_mismatches = tuple(sorted(mismatches, key=lambda item: item.value))
    if not applicable_results:
        return AssessmentGateEvaluation(
            satisfied=False,
            presented_assessment_count=len(assessments),
            applicable_assessment_count=0,
            non_applicable_mismatches=ordered_mismatches,
            reasons=(GateFailureReason.no_applicable_assessment,),
        )

    reasons: list[GateFailureReason] = []
    if BehavioralResult.fail in applicable_results:
        reasons.append(GateFailureReason.applicable_assessment_failed)
    if BehavioralResult.indeterminate in applicable_results:
        reasons.append(GateFailureReason.applicable_assessment_indeterminate)

    return AssessmentGateEvaluation(
        satisfied=not reasons,
        presented_assessment_count=len(assessments),
        applicable_assessment_count=len(applicable_results),
        applicable_results=tuple(applicable_results),
        non_applicable_mismatches=ordered_mismatches,
        reasons=tuple(reasons),
    )
