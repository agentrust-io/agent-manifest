"""Build the deterministic public MemoryCheckpointAssessment reference vectors.

The committed JSON is the portable artifact. This builder exists so a hand edit,
refactor, or future generator change cannot silently make the committed vectors
irreproducible.
"""
from __future__ import annotations

from typing import Any


HASHES = {
    "baseline": "sha256:" + "a" * 64,
    "candidate": "sha256:" + "b" * 64,
    "baseline_state": "sha256:" + "c" * 64,
    "candidate_state": "sha256:" + "d" * 64,
    "old": "sha256:" + "1" * 64,
    "new": "sha256:" + "2" * 64,
    "anchor": "sha256:" + "3" * 64,
    "other": "sha256:" + "4" * 64,
    "tenant-b": "sha256:" + "5" * 64,
    "state-a": "sha256:" + "6" * 64,
    "state-b": "sha256:" + "7" * 64,
}


def _item(
    key: str,
    rank: int,
    *,
    scope_labels: tuple[str, ...] = (),
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "key": key,
        "version": HASHES[key],
        "rank": rank,
    }
    if scope_labels:
        item["scope_labels"] = list(scope_labels)
    return item


def _response(
    query: str,
    items: list[dict[str, Any]],
    *,
    context: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "query": query,
        "context": context or {},
        "items": items,
    }


def _case(
    case_id: str,
    expected_result: str,
    failed: tuple[str, ...] = (),
    overrides: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return {
        "id": case_id,
        "expected_result": expected_result,
        "expected_failed_probes": list(failed),
        "overrides": list(overrides),
    }


def build_reference_vectors() -> dict[str, Any]:
    """Return the complete deterministic reference-vector bundle."""

    profile = {
        "implementation_id": "reference-vector-table",
        "implementation_version": "1",
        "adapter_version": "0.1",
        "adapter_capability": "deterministic",
        "distance_metric": "fixture-order",
        "index_implementation": "reference-vector-table",
        "top_k": 4,
        "truncation_rule": "top-k",
        "tie_policy": "rank_then_item_key_lexical",
    }

    probe_suite = {
        "version": "0.1",
        "probes": [
            {
                "kind": "correction_precedence",
                "probe_id": "corr",
                "query": "correction",
                "superseded": {"key": "old", "required_in": "both"},
                "correction": {"key": "new", "required_in": "candidate"},
            },
            {
                "kind": "anchor_preservation",
                "probe_id": "anchor",
                "query": "anchor",
                "anchor": {"key": "anchor", "required_in": "both"},
                "max_rank": 2,
            },
            {
                "kind": "scope_isolation",
                "probe_id": "scope-key",
                "query": "scope-key",
                "forbidden_item_keys": ["tenant-b"],
            },
            {
                "kind": "scope_isolation",
                "probe_id": "scope-label",
                "query": "scope-label",
                "forbidden_scope_labels": ["tenant:b"],
            },
            {
                "kind": "state_conditioned_differentiation",
                "probe_id": "state",
                "query": "state",
                "context_a": {"mood": "a"},
                "context_b": {"mood": "b"},
                "a_required_keys": ["state-a"],
                "b_required_keys": ["state-b"],
            },
        ],
    }

    baseline = {
        "checkpoint_digest": HASHES["baseline"],
        "retrieval_state_digest": HASHES["baseline_state"],
        "item_keys": ["old", "anchor", "other", "tenant-b"],
        "responses": [
            _response("correction", [_item("old", 1), _item("anchor", 2)]),
            _response("anchor", [_item("anchor", 1), _item("other", 2)]),
        ],
    }

    candidate = {
        "checkpoint_digest": HASHES["candidate"],
        "retrieval_state_digest": HASHES["candidate_state"],
        "item_keys": [
            "old",
            "new",
            "anchor",
            "other",
            "tenant-b",
            "state-a",
            "state-b",
        ],
        "responses": [
            _response("correction", [_item("new", 1), _item("old", 2)]),
            _response("anchor", [_item("other", 1), _item("anchor", 2)]),
            _response("scope-key", [_item("other", 1)]),
            _response("scope-label", [_item("other", 1)]),
            _response(
                "state",
                [_item("state-a", 1), _item("state-b", 2)],
                context={"mood": "a"},
            ),
            _response(
                "state",
                [_item("state-b", 1), _item("state-a", 2)],
                context={"mood": "b"},
            ),
        ],
    }

    cases = [
        _case("pass", "pass"),
        _case(
            "correction-missing",
            "fail",
            ("corr",),
            (_response("correction", [_item("old", 1)]),),
        ),
        _case(
            "correction-outranked",
            "fail",
            ("corr",),
            (_response("correction", [_item("old", 1), _item("new", 2)]),),
        ),
        _case(
            "anchor-missing",
            "fail",
            ("anchor",),
            (_response("anchor", [_item("other", 1)]),),
        ),
        _case(
            "anchor-demoted",
            "fail",
            ("anchor",),
            (
                _response(
                    "anchor",
                    [_item("other", 1), _item("tenant-b", 2), _item("anchor", 3)],
                ),
            ),
        ),
        _case(
            "scope-key-leak",
            "fail",
            ("scope-key",),
            (_response("scope-key", [_item("tenant-b", 1)]),),
        ),
        _case(
            "scope-label-leak",
            "fail",
            ("scope-label",),
            (
                _response(
                    "scope-label",
                    [_item("other", 1, scope_labels=("tenant:b",))],
                ),
            ),
        ),
        _case(
            "state-collapse",
            "fail",
            ("state",),
            (
                _response(
                    "state",
                    [_item("state-a", 1), _item("state-b", 2)],
                    context={"mood": "b"},
                ),
            ),
        ),
        _case(
            "state-required-missing",
            "fail",
            ("state",),
            (
                _response(
                    "state",
                    [_item("state-b", 1)],
                    context={"mood": "a"},
                ),
            ),
        ),
    ]

    return {
        "format": "MemoryCheckpointAssessmentReferenceVectors/0.1",
        "profile": profile,
        "probe_suite": probe_suite,
        "baseline": baseline,
        "candidate": candidate,
        "cases": cases,
    }
