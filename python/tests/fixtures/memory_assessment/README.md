# Memory checkpoint assessment reference vectors

These fixtures exercise `MemoryCheckpointAssessment/0.1`, the non-normative reference harness tracked by Agent Manifest issue #298.

They are reference vectors for the assessment implementation, not AgentTrust conformance vectors.

## What is included

`reference-vectors-v0.1.json` contains one deterministic retriever profile, one probe suite, a baseline state, a candidate state, and nine expected outcomes.

The cases cover:

- a clean pass;
- a missing correction;
- a correction ranked below the fact it supersedes;
- a missing anchor;
- an anchor demoted below its allowed rank;
- a forbidden item-key leak;
- a forbidden scope-label leak;
- collapsed state-conditioned retrieval;
- a missing state-conditioned required item.

The committed JSON is the reference artifact. `memory_assessment_vector_builder.py` produces the same bundle, and the test suite checks that the committed file still matches a fresh build. This makes accidental hand edits or refactors visible.

## What the vectors are meant to prove

The fixtures are intentionally small and deterministic. They should be understandable without a particular retrieval framework and should contain enough material for another implementation to reproduce the expected result.

The broader test suite covers behavior that does not need to live in the JSON bundle, including:

- unsupported adapters and `indeterminate` outcomes;
- repeatability instability;
- stable logical identity and identity churn;
- request/profile/suite mutation resistance;
- timezone requirements;
- confidentiality signaling;
- applicability-gate behavior;
- canonicalization boundaries;
- the same invariant suite exercised against two independently shaped deterministic retrievers.

## Independence rule

The assessment contract should describe retrieval behavior rather than one library's mechanics. For that reason, the hardening tests run the same invariant suite through two retrieval implementations that do not share retrieval logic.

A new vector should be added when it catches a materially different defect, not merely to increase case count.

## Canonicalization note

Assessment digests use the repository canonicalizer. Current upstream has corrected the UTF-16 key-ordering and exponent-formatting cases previously guarded here. The remaining U+2028 escaping defect is tracked by Agent Manifest #322 and remains a strict expected failure in the canonicalization dependency test.

Do not add an assessment-specific canonicalizer. The assessment should continue to use the project-wide primitive so interoperability fixes apply consistently across the repository.