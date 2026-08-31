from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from agent_manifest._memory_assessment import (
    AdapterCapability,
    AnchorPreservationProbe,
    AssessmentHarness,
    BehavioralResult,
    CorrectionPrecedenceProbe,
    IndeterminateReason,
    ItemReference,
    MaterialAccess,
    ProbeSuite,
    RequiredIn,
    RetrievedItem,
    RetrievalRequest,
    RetrieverProfile,
    RuntimeObservation,
    ScopeIsolationProbe,
    SeverityClass,
    StateConditionedDifferentiationProbe,
    StateReference,
)


def _hash(char: str) -> str:
    return "sha256:" + char * 64


class FixtureAdapter:
    """Deterministic in-memory adapter used only by the assessment tests."""

    def __init__(
        self,
        *,
        capability: AdapterCapability = AdapterCapability.deterministic,
        unstable: bool = False,
    ) -> None:
        self._profile = RetrieverProfile(
            implementation_id="fixture",
            implementation_version="1",
            adapter_version="0.1",
            adapter_capability=capability,
            distance_metric="fixture-order",
            index_implementation="fixture",
            top_k=4,
            truncation_rule="none",
            tie_policy="item_key_lexical",
        )
        self.unstable = unstable
        self.calls = 0
        self.store = {
            "baseline": {"old", "anchor", "other", "tenant-b"},
            "candidate": {
                "old",
                "new",
                "anchor",
                "other",
                "tenant-b",
                "state-a",
                "state-b",
            },
        }

    @property
    def profile(self) -> RetrieverProfile:
        return self._profile

    def state_reference(self, state_name: str) -> StateReference:
        return StateReference(
            checkpoint_digest=_hash("a" if state_name == "baseline" else "b"),
            retrieval_state_digest=_hash("c" if state_name == "baseline" else "d"),
            indexed_item_count=len(self.store[state_name]),
        )

    def contains_item_key(self, state_name: str, item_key: str) -> bool:
        return item_key in self.store[state_name]

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]:
        self.calls += 1

        def item(
            key: str,
            rank: int,
            scopes: tuple[str, ...] = (),
        ) -> RetrievedItem:
            chars = {
                "old": "1",
                "new": "2",
                "anchor": "3",
                "other": "4",
                "tenant-b": "5",
                "state-a": "6",
                "state-b": "7",
            }
            return RetrievedItem(
                item_key=key,
                item_version_digest=_hash(chars[key]),
                rank=rank,
                scope_labels=scopes,
            )

        if request.query == "correction":
            if state_name == "baseline":
                return [item("old", 1), item("anchor", 2)]
            return [item("new", 1), item("old", 2), item("anchor", 3)]

        if request.query == "anchor":
            if state_name == "baseline":
                return [item("anchor", 1), item("other", 2)]
            return [item("other", 1), item("anchor", 2)]

        if request.query == "scope":
            return [item("tenant-b", 1, ("tenant:b",)), item("other", 2)]

        if request.query == "other-safe":
            return [item("other", 1)]

        if request.query == "state":
            mood = request.context.get("mood")
            if mood == "a":
                result = [item("state-a", 1), item("state-b", 2)]
            else:
                result = [item("state-b", 1), item("state-a", 2)]
            if self.unstable and self.calls % 2 == 0:
                return [
                    result[1].model_copy(update={"rank": 1}),
                    result[0].model_copy(update={"rank": 2}),
                ]
            return result

        return []

    def runtime_observation(self) -> RuntimeObservation | None:
        return RuntimeObservation(runtime_id="fixture-1", indexed_item_count=7)


class VersionChangingAnchorAdapter(FixtureAdapter):
    """Keeps the anchor key stable while changing its recorded content version."""

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]:
        items = list(super().retrieve(state_name, request))
        if request.query == "anchor" and state_name == "candidate":
            return [
                item.model_copy(update={"item_version_digest": _hash("8")})
                if item.item_key == "anchor"
                else item
                for item in items
            ]
        return items


class DriftingStateAdapter(FixtureAdapter):
    """Changes the candidate state reference after probe execution begins."""

    def __init__(self) -> None:
        super().__init__()
        self.state_reference_calls = {"baseline": 0, "candidate": 0}

    def state_reference(self, state_name: str) -> StateReference:
        self.state_reference_calls[state_name] += 1
        reference = super().state_reference(state_name)
        if state_name == "candidate" and self.state_reference_calls[state_name] > 1:
            return reference.model_copy(update={"checkpoint_digest": _hash("e")})
        return reference


def test_all_four_invariants_can_pass() -> None:
    adapter = FixtureAdapter()
    suite = ProbeSuite(
        probes=(
            CorrectionPrecedenceProbe(
                probe_id="corr",
                query="correction",
                superseded=ItemReference(key="old", required_in=RequiredIn.both),
                correction=ItemReference(key="new", required_in=RequiredIn.candidate),
            ),
            AnchorPreservationProbe(
                probe_id="anchor",
                query="anchor",
                anchor=ItemReference(key="anchor", required_in=RequiredIn.both),
                max_rank=2,
            ),
            ScopeIsolationProbe(
                probe_id="scope",
                query="other-safe",
                forbidden_scope_labels=("tenant:b",),
            ),
            StateConditionedDifferentiationProbe(
                probe_id="state",
                query="state",
                context_a={"mood": "a"},
                context_b={"mood": "b"},
                a_required_keys=("state-a",),
                b_required_keys=("state-b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(
        adapter,
        suite,
        material_access=MaterialAccess.restricted,
    )

    assert assessment.result is BehavioralResult.pass_
    assert assessment.coverage.passed == 4
    assert assessment.material_access is MaterialAccess.restricted


def test_scope_failure_surfaces_confidentiality_flag() -> None:
    adapter = FixtureAdapter()
    suite = ProbeSuite(
        probes=(
            ScopeIsolationProbe(
                probe_id="scope",
                query="scope",
                forbidden_scope_labels=("tenant:b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert assessment.result is BehavioralResult.fail
    assert assessment.security_flags.contains_confidentiality_failure is True
    assert assessment.probe_results[0].severity is SeverityClass.confidentiality


def test_empty_retrieval_satisfies_scope_isolation_only() -> None:
    suite = ProbeSuite(
        probes=(
            ScopeIsolationProbe(
                probe_id="scope",
                query="no-results",
                forbidden_scope_labels=("tenant:b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(FixtureAdapter(), suite)

    assert assessment.result is BehavioralResult.pass_
    assert assessment.coverage.passed == 1
    assert assessment.security_flags.contains_confidentiality_failure is False


def test_missing_baseline_anchor_is_indeterminate_not_failure() -> None:
    adapter = FixtureAdapter()
    suite = ProbeSuite(
        probes=(
            AnchorPreservationProbe(
                probe_id="anchor",
                query="other-safe",
                anchor=ItemReference(key="anchor", required_in=RequiredIn.both),
                max_rank=2,
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert assessment.result is BehavioralResult.indeterminate
    assert assessment.probe_results[0].reasons == (
        IndeterminateReason.baseline_precondition_unmet,
    )


def test_anchor_persistence_is_key_based_not_version_equality() -> None:
    suite = ProbeSuite(
        probes=(
            AnchorPreservationProbe(
                probe_id="anchor",
                query="anchor",
                anchor=ItemReference(key="anchor", required_in=RequiredIn.both),
                max_rank=2,
            ),
        )
    )

    assessment = AssessmentHarness().run(VersionChangingAnchorAdapter(), suite)

    assert assessment.result is BehavioralResult.pass_


def test_identity_break_is_explicit_indeterminate() -> None:
    adapter = FixtureAdapter()
    adapter.store["candidate"].remove("anchor")
    suite = ProbeSuite(
        probes=(
            AnchorPreservationProbe(
                probe_id="anchor",
                query="anchor",
                anchor=ItemReference(key="anchor", required_in=RequiredIn.both),
                max_rank=2,
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert assessment.result is BehavioralResult.indeterminate
    assert assessment.probe_results[0].reasons == (IndeterminateReason.id_churn,)


def test_unsupported_adapter_does_not_fake_failure() -> None:
    adapter = FixtureAdapter(capability=AdapterCapability.unsupported_or_unknown)
    suite = ProbeSuite(
        probes=(
            ScopeIsolationProbe(
                probe_id="scope",
                query="scope",
                forbidden_scope_labels=("tenant:b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert assessment.result is BehavioralResult.indeterminate
    assert assessment.probe_results[0].reasons == (
        IndeterminateReason.adapter_unsupported,
    )
    assert assessment.coverage.indeterminate_rate == 1.0


def test_profile_and_suite_digests_are_bound() -> None:
    adapter = FixtureAdapter()
    suite = ProbeSuite(
        probes=(
            ScopeIsolationProbe(
                probe_id="scope",
                query="other-safe",
                forbidden_scope_labels=("tenant:b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert str(assessment.retriever_profile_digest).startswith("sha256:")
    assert str(assessment.probe_suite_digest).startswith("sha256:")
    assert len(str(assessment.retriever_profile_digest)) == 71


def test_unstable_repeatability_is_indeterminate() -> None:
    adapter = FixtureAdapter(unstable=True)
    suite = ProbeSuite(
        probes=(
            StateConditionedDifferentiationProbe(
                probe_id="state",
                query="state",
                context_a={"mood": "a"},
                context_b={"mood": "b"},
                a_required_keys=("state-a",),
                b_required_keys=("state-b",),
            ),
        )
    )

    assessment = AssessmentHarness().run(adapter, suite)

    assert assessment.result is BehavioralResult.indeterminate
    assert assessment.probe_results[0].reasons == (
        IndeterminateReason.repeatability_unstable,
    )


def test_probe_suite_cannot_vacuously_pass() -> None:
    with pytest.raises(ValidationError):
        ProbeSuite(probes=())


def test_probe_suite_requires_unique_probe_ids() -> None:
    with pytest.raises(ValidationError, match="unique probe_id"):
        ProbeSuite(
            probes=(
                ScopeIsolationProbe(
                    probe_id="scope",
                    query="other-safe",
                    forbidden_scope_labels=("tenant:b",),
                ),
                ScopeIsolationProbe(
                    probe_id="scope",
                    query="scope",
                    forbidden_scope_labels=("tenant:b",),
                ),
            )
        )


def test_state_conditioned_probe_requires_distinct_contexts() -> None:
    with pytest.raises(ValidationError, match="distinct context_a and context_b"):
        StateConditionedDifferentiationProbe(
            probe_id="state",
            query="state",
            context_a={"mood": "a"},
            context_b={"mood": "a"},
            require_distinct_ordering=True,
        )


def test_state_reference_drift_aborts_assessment() -> None:
    suite = ProbeSuite(
        probes=(
            ScopeIsolationProbe(
                probe_id="scope",
                query="other-safe",
                forbidden_scope_labels=("tenant:b",),
            ),
        )
    )

    with pytest.raises(RuntimeError, match="state reference changed during assessment"):
        AssessmentHarness().run(DriftingStateAdapter(), suite)
