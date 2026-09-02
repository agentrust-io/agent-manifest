from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

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
    ProbeSuite,
    RequiredIn,
    RetrievedItem,
    RetrievalRequest,
    RetrieverProfile,
    RuntimeObservation,
    ScopeIsolationProbe,
    StateConditionedDifferentiationProbe,
    StateReference,
    canonical_model_hash,
)


def _hash(char: str) -> str:
    return "sha256:" + char * 64


def _correction_probe() -> CorrectionPrecedenceProbe:
    return CorrectionPrecedenceProbe(
        probe_id="corr",
        query="correction",
        superseded=ItemReference(key="old", required_in=RequiredIn.both),
        correction=ItemReference(key="new", required_in=RequiredIn.candidate),
    )


def _anchor_probe() -> AnchorPreservationProbe:
    return AnchorPreservationProbe(
        probe_id="anchor",
        query="anchor",
        anchor=ItemReference(key="anchor", required_in=RequiredIn.both),
        max_rank=2,
    )


def _state_probe() -> StateConditionedDifferentiationProbe:
    return StateConditionedDifferentiationProbe(
        probe_id="state",
        query="state",
        context_a={"mood": "a"},
        context_b={"mood": "b"},
        a_required_keys=("state-a",),
        b_required_keys=("state-b",),
    )


def _passing_suite() -> ProbeSuite:
    return ProbeSuite(
        probes=(
            _correction_probe(),
            _anchor_probe(),
            ScopeIsolationProbe(
                probe_id="scope",
                query="safe",
                forbidden_scope_labels=("tenant:b",),
            ),
            _state_probe(),
        )
    )


class FixtureAdapter:
    """Table-driven adapter used to isolate harness behavior."""

    def __init__(
        self,
        *,
        capability: AdapterCapability = AdapterCapability.deterministic,
        mode: str = "pass",
    ) -> None:
        self._profile = RetrieverProfile(
            implementation_id="fixture-table",
            implementation_version="1",
            adapter_version="0.1",
            adapter_capability=capability,
            distance_metric="fixture-order",
            index_implementation="fixture-table",
            top_k=4,
            truncation_rule="none",
            tie_policy=(
                "item_key_lexical"
                if capability is AdapterCapability.deterministic
                else None
            ),
        )
        self.mode = mode
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

    @staticmethod
    def _item(
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

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]:
        self.calls += 1
        if self.mode == "mutate-request":
            request.context["mutated"] = "yes"

        if request.query == "correction":
            if state_name == "baseline":
                return [self._item("old", 1), self._item("anchor", 2)]
            if self.mode == "correction-missing":
                return [self._item("old", 1), self._item("anchor", 2)]
            if self.mode == "correction-outranked":
                return [self._item("old", 1), self._item("new", 2)]
            return [
                self._item("new", 1),
                self._item("old", 2),
                self._item("anchor", 3),
            ]

        if request.query == "anchor":
            if state_name == "baseline":
                return [self._item("anchor", 1), self._item("other", 2)]
            if self.mode == "anchor-missing":
                return [self._item("other", 1)]
            if self.mode == "anchor-demoted":
                return [
                    self._item("other", 1),
                    self._item("tenant-b", 2),
                    self._item("anchor", 3),
                ]
            return [self._item("other", 1), self._item("anchor", 2)]

        if request.query == "scope":
            scopes = ("tenant:b",)
            if self.mode == "scope-label-flap" and self.calls % 2 == 0:
                scopes = ()
            return [self._item("tenant-b", 1, scopes), self._item("other", 2)]

        if request.query == "safe":
            return [self._item("other", 1)]

        if request.query == "state":
            if self.mode == "state-collapse":
                return [self._item("state-a", 1), self._item("state-b", 2)]
            if request.context.get("mood") == "a":
                return [self._item("state-a", 1), self._item("state-b", 2)]
            return [self._item("state-b", 1), self._item("state-a", 2)]

        return []

    def runtime_observation(self) -> RuntimeObservation | None:
        return RuntimeObservation(runtime_id="fixture-table-1", indexed_item_count=7)


class KeywordAdapter:
    """Independent token-overlap retriever for abstraction portability checks."""

    _documents = {
        "baseline": {
            "old": ("correction old current", ()),
            "anchor": ("anchor identity continuity", ()),
            "other": ("safe general other", ()),
            "tenant-b": ("private tenant b", ("tenant:b",)),
        },
        "candidate": {
            "old": ("correction old obsolete", ()),
            "new": ("correction new current preferred", ()),
            "anchor": ("anchor identity continuity", ()),
            "other": ("safe general other", ()),
            "tenant-b": ("private tenant b", ("tenant:b",)),
            "state-a": ("state mood a", ()),
            "state-b": ("state mood b", ()),
        },
    }

    def __init__(self) -> None:
        self._profile = RetrieverProfile(
            implementation_id="fixture-keyword",
            implementation_version="1",
            adapter_version="0.1",
            adapter_capability=AdapterCapability.deterministic,
            tokenizer_id="whitespace-lower/1",
            query_preprocessing=(
                "lowercase",
                "whitespace-tokenize",
                "append-context-values",
            ),
            distance_metric="token-overlap-desc",
            index_implementation="python-set-overlap",
            top_k=4,
            truncation_rule="top-k",
            tie_policy="score_desc_then_item_key_lexical",
        )

    @property
    def profile(self) -> RetrieverProfile:
        return self._profile

    def state_reference(self, state_name: str) -> StateReference:
        return StateReference(
            checkpoint_digest=_hash("8" if state_name == "baseline" else "9"),
            retrieval_state_digest=_hash("a" if state_name == "baseline" else "b"),
            indexed_item_count=len(self._documents[state_name]),
        )

    def contains_item_key(self, state_name: str, item_key: str) -> bool:
        return item_key in self._documents[state_name]

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]:
        query_terms = set(request.query.lower().split())
        query_terms.update(value.lower() for value in request.context.values())
        ranked: list[tuple[int, str, tuple[str, ...]]] = []
        for key, (text, scopes) in self._documents[state_name].items():
            score = len(query_terms.intersection(text.lower().split()))
            if score:
                ranked.append((score, key, scopes))
        ranked.sort(key=lambda row: (-row[0], row[1]))
        items: list[RetrievedItem] = []
        for rank, (_, key, scopes) in enumerate(
            ranked[: self.profile.top_k],
            start=1,
        ):
            digest_char = format((sum(key.encode()) % 15) + 1, "x")
            items.append(
                RetrievedItem(
                    item_key=key,
                    item_version_digest=_hash(digest_char),
                    rank=rank,
                    scope_labels=scopes,
                )
            )
        return items

    def runtime_observation(self) -> RuntimeObservation | None:
        return RuntimeObservation(runtime_id="fixture-keyword-1")


def test_same_invariant_suite_passes_two_independent_retrievers() -> None:
    for adapter in (FixtureAdapter(), KeywordAdapter()):
        assessment = AssessmentHarness().run(adapter, _passing_suite())
        assert assessment.result is BehavioralResult.pass_
        assert assessment.coverage.passed == 4


@pytest.mark.parametrize(
    ("mode", "needle"),
    (
        ("correction-missing", "not retrieved"),
        ("correction-outranked", "did not outrank"),
    ),
)
def test_correction_failures_are_independent(mode: str, needle: str) -> None:
    assessment = AssessmentHarness().run(
        FixtureAdapter(mode=mode),
        ProbeSuite(probes=(_correction_probe(),)),
    )
    assert assessment.result is BehavioralResult.fail
    assert needle in assessment.probe_results[0].violations[0]


@pytest.mark.parametrize(
    ("mode", "needle"),
    (
        ("anchor-missing", "not retrieved"),
        ("anchor-demoted", "exceeds max_rank"),
    ),
)
def test_anchor_failures_are_independent(mode: str, needle: str) -> None:
    assessment = AssessmentHarness().run(
        FixtureAdapter(mode=mode),
        ProbeSuite(probes=(_anchor_probe(),)),
    )
    assert assessment.result is BehavioralResult.fail
    assert needle in assessment.probe_results[0].violations[0]


def test_state_conditioned_collapse_fails() -> None:
    assessment = AssessmentHarness().run(
        FixtureAdapter(mode="state-collapse"),
        ProbeSuite(probes=(_state_probe(),)),
    )
    assert assessment.result is BehavioralResult.fail
    assert any(
        "identical ordered item identities" in violation
        for violation in assessment.probe_results[0].violations
    )


def test_scope_label_changes_make_repeatability_unstable() -> None:
    probe = ScopeIsolationProbe(
        probe_id="scope",
        query="scope",
        forbidden_scope_labels=("unrelated-secret",),
    )
    assessment = AssessmentHarness().run(
        FixtureAdapter(mode="scope-label-flap"),
        ProbeSuite(probes=(probe,)),
    )
    assert assessment.result is BehavioralResult.indeterminate
    assert assessment.probe_results[0].reasons == (
        IndeterminateReason.repeatability_unstable,
    )


def test_non_required_confidentiality_failure_remains_visible() -> None:
    diagnostic = ScopeIsolationProbe(
        probe_id="scope",
        query="scope",
        forbidden_scope_labels=("tenant:b",),
        required=False,
    )
    assessment = AssessmentHarness().run(
        FixtureAdapter(),
        ProbeSuite(probes=(_correction_probe(), diagnostic)),
    )
    assert assessment.result is BehavioralResult.pass_
    assert assessment.security_flags.contains_confidentiality_failure is True


def test_unsupported_profile_may_omit_tie_policy() -> None:
    profile = RetrieverProfile(
        implementation_id="unsupported",
        implementation_version="1",
        adapter_version="1",
        adapter_capability=AdapterCapability.unsupported_or_unknown,
        distance_metric="unknown",
        index_implementation="unknown",
        top_k=1,
        truncation_rule="none",
    )
    assert profile.tie_policy is None


def test_deterministic_profile_requires_tie_policy() -> None:
    with pytest.raises(ValidationError):
        RetrieverProfile(
            implementation_id="deterministic",
            implementation_version="1",
            adapter_version="1",
            adapter_capability=AdapterCapability.deterministic,
            distance_metric="fixture",
            index_implementation="fixture",
            top_k=1,
            truncation_rule="none",
        )


def test_naive_assessed_at_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AssessmentHarness().run(
            FixtureAdapter(),
            ProbeSuite(probes=(_correction_probe(),)),
            assessed_at=datetime(2026, 8, 20, 12, 0, 0),
        )


def test_timezone_aware_assessed_at_is_preserved() -> None:
    assessed_at = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    assessment = AssessmentHarness().run(
        FixtureAdapter(),
        ProbeSuite(probes=(_correction_probe(),)),
        assessed_at=assessed_at,
    )
    assert assessment.assessed_at == assessed_at


def test_adapter_request_mutation_does_not_change_repeatability() -> None:
    assessment = AssessmentHarness().run(
        FixtureAdapter(mode="mutate-request"),
        ProbeSuite(probes=(_state_probe(),)),
    )
    assert assessment.result is BehavioralResult.pass_
    assert all(
        evidence.repeatability.observed_status.value == "stable"
        for evidence in assessment.invocation_evidence
    )


def test_profile_digest_changes_with_quantization() -> None:
    profile = FixtureAdapter().profile
    changed = profile.model_copy(update={"quantization": "int8"})
    assert canonical_model_hash(profile) != canonical_model_hash(changed)


def test_probe_suite_cannot_vacuously_pass() -> None:
    with pytest.raises(ValidationError):
        ProbeSuite(probes=())


def test_identity_churn_is_indeterminate() -> None:
    adapter = FixtureAdapter()
    adapter.store["candidate"].remove("anchor")
    assessment = AssessmentHarness().run(
        adapter,
        ProbeSuite(probes=(_anchor_probe(),)),
    )
    assert assessment.probe_results[0].reasons == (IndeterminateReason.id_churn,)
