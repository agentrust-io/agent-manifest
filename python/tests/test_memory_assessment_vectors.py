from __future__ import annotations

import json
from collections.abc import Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from agent_manifest._memory_assessment import (
    AssessmentHarness,
    BehavioralResult,
    ProbeSuite,
    RetrievedItem,
    RetrievalRequest,
    RetrieverProfile,
    RuntimeObservation,
    StateReference,
)
from tests.memory_assessment_vector_builder import build_reference_vectors


_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "memory_assessment"
    / "reference-vectors-v0.1.json"
)


def _request_key(
    query: str,
    context: dict[str, str],
) -> tuple[str, tuple[tuple[str, str], ...]]:
    return query, tuple(sorted(context.items()))


class VectorAdapter:
    """Adapter that executes the portable JSON reference vectors verbatim."""

    def __init__(self, vector: dict[str, Any], case: dict[str, Any]) -> None:
        self._profile = RetrieverProfile.model_validate(vector["profile"])
        self._baseline = deepcopy(vector["baseline"])
        self._candidate = deepcopy(vector["candidate"])
        responses = {
            _request_key(entry["query"], entry.get("context", {})): entry["items"]
            for entry in self._candidate["responses"]
        }
        for override in case.get("overrides", []):
            responses[
                _request_key(override["query"], override.get("context", {}))
            ] = override["items"]
        self._candidate["responses"] = [
            {"query": query, "context": dict(context), "items": items}
            for (query, context), items in responses.items()
        ]

    @property
    def profile(self) -> RetrieverProfile:
        return self._profile

    def _state(self, state_name: str) -> dict[str, Any]:
        if state_name == "baseline":
            return self._baseline
        if state_name == "candidate":
            return self._candidate
        raise KeyError(state_name)

    def state_reference(self, state_name: str) -> StateReference:
        state = self._state(state_name)
        return StateReference(
            checkpoint_digest=state["checkpoint_digest"],
            retrieval_state_digest=state["retrieval_state_digest"],
            indexed_item_count=len(state["item_keys"]),
        )

    def contains_item_key(self, state_name: str, item_key: str) -> bool:
        return item_key in self._state(state_name)["item_keys"]

    def retrieve(
        self,
        state_name: str,
        request: RetrievalRequest,
    ) -> Sequence[RetrievedItem]:
        key = _request_key(request.query, request.context)
        for response in self._state(state_name)["responses"]:
            if _request_key(response["query"], response.get("context", {})) != key:
                continue
            return [
                RetrievedItem(
                    item_key=item["key"],
                    item_version_digest=item["version"],
                    rank=item["rank"],
                    scope_labels=tuple(item.get("scope_labels", ())),
                )
                for item in response["items"]
            ]
        return []

    def runtime_observation(self) -> RuntimeObservation | None:
        return RuntimeObservation(runtime_id="reference-vector-table/1")


def _vectors() -> dict[str, Any]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _case_ids() -> list[str]:
    return [case["id"] for case in _vectors()["cases"]]


def test_committed_reference_vectors_match_builder() -> None:
    """The portable JSON must remain reproducible from its source builder."""

    assert _vectors() == build_reference_vectors(), (
        "committed MemoryCheckpointAssessment reference vectors differ from "
        "the deterministic builder; regenerate the JSON and review the diff"
    )


@pytest.mark.parametrize("case_id", _case_ids())
def test_reference_vector(case_id: str) -> None:
    vector = _vectors()
    case = next(case for case in vector["cases"] if case["id"] == case_id)
    suite = ProbeSuite.model_validate(vector["probe_suite"])
    assessment = AssessmentHarness().run(VectorAdapter(vector, case), suite)

    assert assessment.result.value == case["expected_result"]
    failed = sorted(
        result.probe_id
        for result in assessment.probe_results
        if result.result is BehavioralResult.fail
    )
    assert failed == sorted(case["expected_failed_probes"])
