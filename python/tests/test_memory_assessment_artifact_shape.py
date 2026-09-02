from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from agent_manifest._memory_assessment import (
    BehavioralResult,
    Coverage,
    InvocationEvidence,
    MaterialAccess,
    MemoryCheckpointAssessment,
    ObservedStatus,
    ProbeResult,
    RepeatabilityEvidence,
    SecurityFlags,
    SeverityClass,
    StateReference,
)


def _hash(char: str) -> str:
    return "sha256:" + char * 64


def _artifact() -> MemoryCheckpointAssessment:
    return MemoryCheckpointAssessment(
        baseline_state=StateReference(
            checkpoint_digest=_hash("a"),
            retrieval_state_digest=_hash("b"),
            indexed_item_count=3,
        ),
        candidate_state=StateReference(
            checkpoint_digest=_hash("c"),
            retrieval_state_digest=_hash("d"),
            indexed_item_count=4,
        ),
        probe_suite_digest=_hash("e"),
        retriever_profile_digest=_hash("f"),
        assessed_at=datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
        material_access=MaterialAccess.public,
        invocation_evidence=(
            InvocationEvidence(
                state_name="candidate",
                request_digest=_hash("1"),
                repeatability=RepeatabilityEvidence(
                    trials=20,
                    distinct_orderings_observed=1,
                    observed_status=ObservedStatus.stable,
                ),
            ),
        ),
        probe_results=(
            ProbeResult(
                probe_id="p1",
                required=True,
                result=BehavioralResult.pass_,
                severity=SeverityClass.behavioral,
            ),
        ),
        coverage=Coverage(
            required_probe_count=1,
            passed=1,
            failed=0,
            indeterminate=0,
            indeterminate_rate=0.0,
        ),
        security_flags=SecurityFlags(),
        result=BehavioralResult.pass_,
    )


def _dict() -> dict[str, object]:
    return deepcopy(_artifact().model_dump(mode="json"))


def test_artifact_json_round_trip_is_lossless() -> None:
    artifact = _artifact()
    encoded = artifact.model_dump_json(exclude_none=True)
    assert MemoryCheckpointAssessment.model_validate_json(encoded) == artifact


def test_artifact_json_schema_is_closed_and_versioned() -> None:
    schema = MemoryCheckpointAssessment.model_json_schema()

    assert schema["additionalProperties"] is False
    assert schema["properties"]["type"]["const"] == "MemoryCheckpointAssessment"
    assert schema["properties"]["version"]["const"] == "0.1"
    assert schema["properties"]["assessed_at"]["format"] == "date-time"

    required = set(schema["required"])
    assert {
        "baseline_state",
        "candidate_state",
        "probe_suite_digest",
        "retriever_profile_digest",
        "assessed_at",
        "material_access",
        "invocation_evidence",
        "probe_results",
        "coverage",
        "security_flags",
        "result",
    }.issubset(required)

    for definition in (
        "Coverage",
        "InvocationEvidence",
        "ProbeResult",
        "RepeatabilityEvidence",
        "RuntimeObservation",
        "SecurityFlags",
        "StateReference",
    ):
        assert schema["$defs"][definition]["additionalProperties"] is False


def test_behavioral_result_schema_has_only_three_outcomes() -> None:
    schema = MemoryCheckpointAssessment.model_json_schema()
    assert set(schema["$defs"]["BehavioralResult"]["enum"]) == {
        "pass",
        "fail",
        "indeterminate",
    }


def test_artifact_rejects_result_that_disagrees_with_required_probes() -> None:
    value = _dict()
    value["result"] = "fail"
    with pytest.raises(ValidationError, match="result does not match"):
        MemoryCheckpointAssessment.model_validate(value)


def test_artifact_rejects_coverage_that_disagrees_with_probe_results() -> None:
    value = _dict()
    coverage = value["coverage"]
    assert isinstance(coverage, dict)
    coverage["passed"] = 0
    coverage["failed"] = 1
    with pytest.raises(ValidationError, match="coverage.passed"):
        MemoryCheckpointAssessment.model_validate(value)


def test_artifact_rejects_duplicate_probe_ids() -> None:
    value = _dict()
    probe_results = value["probe_results"]
    assert isinstance(probe_results, list)
    probe_results.append(deepcopy(probe_results[0]))
    coverage = value["coverage"]
    assert isinstance(coverage, dict)
    coverage["required_probe_count"] = 2
    coverage["passed"] = 2
    with pytest.raises(ValidationError, match="unique probe_id"):
        MemoryCheckpointAssessment.model_validate(value)


def test_artifact_rejects_duplicate_invocation_evidence() -> None:
    value = _dict()
    invocation_evidence = value["invocation_evidence"]
    assert isinstance(invocation_evidence, list)
    invocation_evidence.append(deepcopy(invocation_evidence[0]))
    with pytest.raises(ValidationError, match="unique state/request pairs"):
        MemoryCheckpointAssessment.model_validate(value)


def test_artifact_rejects_vacuous_no_required_probe_result() -> None:
    value = _dict()
    probe_results = value["probe_results"]
    assert isinstance(probe_results, list)
    probe_results[0]["required"] = False
    coverage = value["coverage"]
    assert isinstance(coverage, dict)
    coverage.update(
        {
            "required_probe_count": 0,
            "passed": 0,
            "failed": 0,
            "indeterminate": 0,
            "indeterminate_rate": 0.0,
        }
    )
    with pytest.raises(ValidationError, match="at least one required probe result"):
        MemoryCheckpointAssessment.model_validate(value)


def test_artifact_rejects_hidden_confidentiality_failure() -> None:
    value = _dict()
    probe_results = value["probe_results"]
    assert isinstance(probe_results, list)
    probe_results[0].update(
        {
            "result": "fail",
            "severity": "confidentiality",
            "violations": ["forbidden scope retrieved"],
        }
    )
    coverage = value["coverage"]
    assert isinstance(coverage, dict)
    coverage.update({"passed": 0, "failed": 1})
    value["result"] = "fail"
    with pytest.raises(ValidationError, match="contains_confidentiality_failure"):
        MemoryCheckpointAssessment.model_validate(value)
