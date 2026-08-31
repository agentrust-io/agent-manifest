# Memory checkpoint assessment

`MemoryCheckpointAssessment/0.1` is a non-normative reference assessment for the retrieval behavior of a candidate memory checkpoint. It is tracked in [issue #298](https://github.com/agentrust-io/agent-manifest/issues/298).

The problem is deliberately narrow. A checkpoint can be cryptographically valid, append-only, fresh, and within its update budget while still changing what the retriever selects in a harmful way. This assessment adds evidence about that retrieval behavior without changing the meaning of Agent Manifest verification.

## What the assessment answers

The assessment asks whether a candidate checkpoint preserves a declared set of retrieval invariants under a pinned retriever configuration.

It does **not** decide whether stored content is true, whether an application response is correct, whether a memory write was authorized, or whether a checkpoint is safe in every possible sense. It also does not approve a checkpoint. The deterministic result depends only on the declared probes and retrieval evidence, not on a probabilistic judge.

## Keep evidence and approval separate

The assessment artifact records facts about a run. The approval gate decides whether those facts satisfy an adopted policy.

That separation is important because a failed assessment can still be perfectly valid evidence. The checkpoint can remain cryptographically sound and its consistency proof can still verify. What changes is whether an approval action is allowed to proceed.

The reference implementation keeps five concerns distinct:

1. **Evidence validity**: is the assessment well formed and correctly bound to what it claims?
2. **Behavioral outcome**: did the required probes return `pass`, `fail`, or `indeterminate`?
3. **Applicability**: does this assessment match the checkpoint, probe suite, retriever profile, retrieval state, and evidence window required by the adopted gate?
4. **Gate result**: does this one assessment gate allow the approval process to continue?
5. **Audit history**: what actually happened, including an approval that should have been blocked?

## Approval decision tree

The gate is intentionally pass-only:

```text
Presented assessment evidence
|
+-- no applicable assessment
|   +-- gate is not satisfied
|
+-- applicable assessment exists
    |
    +-- any applicable result is fail
    |   +-- gate is not satisfied
    |   +-- checkpoint MUST NOT be approved while this gate applies
    |
    +-- any applicable result is indeterminate
    |   +-- gate is not satisfied
    |   +-- the required property was not established
    |
    +-- every applicable result is pass
        +-- this gate is satisfied
        +-- continue with the remaining approval checks
```

A `pass` does not grant approval. It only satisfies this one control.

A `fail` is not rewritten into an invalid checkpoint or an invalid assessment. It remains evidence, but an applicable failure blocks the approval action.

An `indeterminate` result also remains its own state. It means the behavioral property was not established. The gate fails closed operationally without pretending that an unestablished result is the same thing as a demonstrated behavioral failure.

Only probes marked `required` contribute to the aggregate behavioral result and therefore to this gate. Non-required probes are diagnostic. A non-required confidentiality probe can fail while the aggregate result remains `pass`; that failure is still recorded in `probe_results` and raises `security_flags.contains_confidentiality_failure`. A policy that intends confidentiality failures to block approval should mark those probes required and may also inspect the security flag directly.

When several applicable assessments are presented, any applicable `fail` or `indeterminate` keeps the gate closed. If both appear, the evaluator reports both reasons rather than collapsing them into one outcome.

## Why applicability matters

A control is easy to bypass if any vaguely related assessment can satisfy it. The gate therefore binds the evidence it expects.

An assessment is applicable only when it matches the policy requirements for:

- baseline checkpoint digest;
- candidate checkpoint digest;
- probe-suite digest;
- retriever-profile digest;
- baseline and candidate retrieval-state digests, when required;
- assessment time window, when required.

Assessment-window bounds are inclusive. Evidence timestamped exactly at `assessed_not_before` or `assessed_not_after` remains applicable.

This prevents three especially important bypasses: omitting the assessment, substituting a different probe suite, or assessing under a different retriever profile.

Evidence that does not match the gate is not declared invalid. It simply cannot satisfy that gate.

## Historical records remain truthful

A control violation should be visible after the fact.

If a valid checkpoint was approved despite an applicable failing assessment, the historical record should preserve both facts. Rewriting either artifact into invalidity would erase the evidence needed to show that the approval control was bypassed.

## Retriever profile

Retrieval behavior is only reproducible when the load-bearing retrieval path is pinned. `RetrieverProfile` therefore records, where applicable:

- implementation identity and version;
- adapter and harness version;
- embedding model identity and revision;
- quantization or precision mode;
- tokenizer identity;
- query preprocessing;
- distance metric;
- index implementation and build configuration;
- filtering rules;
- top-k and truncation behavior;
- reranker identity and configuration;
- deterministic tie policy;
- deterministic seed;
- declared opaque components.

A profile that claims deterministic behavior must declare a deterministic tie policy. The reference harness also records repeatability evidence and requires at least 20 trials for a result reported as stable or unstable.

The typed `index_build_config` and `reranker_config` maps use string, integer, boolean, or null scalar values in 0.1. Fractional settings should be encoded in a stable string form or represented as an opaque component rather than relying on implicit numeric coercion.

The harness snapshots the baseline and candidate state references before running probes and checks them again before emitting an assessment. If either reference changes during the run, no assessment artifact is emitted. This prevents retrieval evidence gathered from one state from being bound to a later checkpoint reference.

## Initial probe set

The 0.1 harness covers four behavioral invariants:

### Correction precedence

A correction should remain retrievable and should outrank the fact it supersedes when the probe requires that relationship.

### Anchor preservation

A declared continuity, identity, or safety anchor should remain retrievable within its allowed rank.

### Scope isolation

A retrieval must not expose an item key or scope label that the probe declares forbidden. Scope failures retain confidentiality severity rather than being flattened into a generic regression.

Scope isolation is intentionally a negative confidentiality property. An empty retrieval contains no forbidden material, so it satisfies this probe. That does **not** establish that retrieval is otherwise healthy. A suite that needs to prove liveness or useful retrieval should also include a positive invariant such as correction precedence, anchor preservation, or state-conditioned differentiation.

### State-conditioned differentiation

Distinct contexts that are expected to retrieve differently should continue to do so, including required and forbidden item checks for each context. The schema rejects a state-conditioned probe whose two contexts are identical.

Cross-state persistence is decided by stable logical item key, not semantic similarity. Item version digests are recorded and participate in repeatability fingerprints within a state, but 0.1 does not compare version digests between baseline and candidate. A content change under a stable key is therefore not, by itself, a failure of the current persistence checks.

Retrieval results must also contain unique ranks and unique logical item keys. Ambiguous duplicate identities are rejected before probe evaluation.

## `indeterminate` results

`indeterminate` is used when the harness cannot establish the behavioral property without falsely calling it a pass or a fail. Current reasons include:

- adapter capability is unsupported or unknown;
- repeatability was not run;
- repeatability was unstable;
- a baseline precondition was not met;
- stable logical identity could not be maintained across the transition.

Material availability is intentionally separate. A private run can still produce a behavioral `pass` or `fail`; restricted material limits independent rerun strength rather than changing what the run observed.

## Material access and reproducibility

The artifact currently records whether the underlying material is public, restricted, or unavailable to the verifier. That tells a relying party what access is available for an independent rerun.

Issue #298 also identified a useful higher-level distinction between `public-reproducible`, `restricted-reproducible`, and `attested-run-only` evidence. The 0.1 implementation does not serialize those modes yet because `attested-run-only` needs an agreed authenticated producer assertion. This contribution does not invent a new signature envelope to solve that separate provenance problem.

## Canonicalization dependency

Assessment digests use the repository canonicalization implementation rather than defining a second one.

Current `main` has fixed the UTF-16 key-ordering and exponent-formatting defects previously exercised by the assessment tests. The remaining U+2028 escaping issue is still tracked by Agent Manifest #322, so the assessment tests keep one strict expected failure for that live interoperability boundary.

Until that remaining defect is fixed, the implementation should not claim full RFC 8785 portability for inputs that exercise the unresolved escaping case.

## Scope of this contribution

The first contribution is intentionally limited to:

- typed assessment evidence models;
- a minimal retriever adapter protocol;
- the deterministic reference harness;
- reference positive and negative vectors;
- tests against independently shaped retriever implementations;
- the separate applicability gate;
- tests for omission, substitution, failure, indeterminate results, and historical evidence semantics.

It intentionally does not:

- change `spec/` or Agent Manifest conformance;
- expose an `approve_checkpoint()` API;
- turn `pass` into deployment authorization;
- turn `fail` into invalid evidence;
- collapse `indeterminate` into `fail`;
- add TRACE or runtime-evidence integration;
- introduce a new signing or envelope format.

That boundary keeps the assessment useful on its own and leaves later governance, provenance, and runtime integration work to separate proposals.
