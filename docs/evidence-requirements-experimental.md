# Signed evidence requirements (experimental)

This page is for people building verifiers that weigh several kinds of evidence about an agent, such as reports from the processor, the code that ran and the tool list. It describes an optional, experimental addition that lets whoever signs a manifest also sign a list of the evidence a checker should insist on. Most users can skip it.

Status: experimental, opt-in, not part of the v0.2 specification. The profile
name carries `experimental` so that it can be replaced, not extended, if the
design changes before adoption.

A relying party (the service deciding whether to trust the agent) that appraises an agent from several pieces of evidence (the
CPU platform, the code that ran, the tool catalog) keeps its own list of what
it requires. This profile lets the manifest issuer sign a second list inside
the manifest, so a verifier can tighten its own requirements with the
issuer's. The consumer is the composite component appraisal proposal in
[agentrust-io/trace-spec#439](https://github.com/agentrust-io/trace-spec/pull/439),
section 3 of `docs/rfcs/composite-component-appraisal.md`.

## Opting in

A manifest opts in with `"profile": "evidence-requirements-experimental-v1"`
and `"version": "0.2"`, which means it is signed as a COSE_Sign1 envelope. The
`evidence_requirements` block is then part of the signed payload, so changing
any field in it breaks the signature.

Nothing else changes. A manifest without the profile validates and verifies
exactly as before, and an `evidence_requirements` key on any other profile, or
with no profile, is rejected as an unknown field, the same result as a release
without this module. The profile also keeps the full-binding rule:
`system_prompt`, `policy_bundle` and `model_identity` are still required, and
`unbound_artifacts` is refused.

## The block

```json
"evidence_requirements": {
  "components": [
    {"component_id": "runtime.cpu", "component_type": "runtime", "required": true,
     "accepted_profiles": ["amd-snp-collateral-experimental-v1"],
     "accepted_appraisal_authorities": ["https://verifier.example.test"],
     "maximum_age_seconds": 300},
    {"component_id": "application.code", "component_type": "code", "required": true,
     "accepted_profiles": ["azure-snp-vtpm-ima-execution-experimental-v1"],
     "accepted_appraisal_authorities": ["https://verifier.example.test"],
     "maximum_age_seconds": 300}
  ],
  "required_bindings": [
    {"source": "runtime.cpu", "target": "application.code",
     "relationship": "same-workload", "accepted_methods": ["same-instance-v1"]}
  ],
  "combination_policy_ref": "urn:example:policy:v1"
}
```

Each component has a stable ID, a type from a fixed list, whether it is
required, the evidence profiles and appraisal authorities it accepts, and a
maximum evidence age of 1 to 86400 seconds. Two fields are optional:
`expected_observed_digest` (a `sha256:` digest the observation must match) and
`artifact_ref` (for example `artifacts.tool_manifest`), which must name an
artifact binding that is present in the same signed manifest.

Validation fails closed on duplicate component IDs, duplicate relationships, a
relationship to itself or to an undeclared component, an unknown relationship
method, a non-boolean `required`, and any unknown field. The models are frozen
and strict.

## Verifying

```python
from agent_manifest.evidence_requirements import verify_evidence_manifest

verified = verify_evidence_manifest(exact_cose_bytes, context, revocations)
```

The helper runs the normal `verify_manifest` first and raises unless the result
is `VALID`. It then refuses any manifest whose signed profile is not the
experimental one, including composition-only. It returns a frozen
`VerifiedRequirements` holding the SHA-256 digest of the exact COSE bytes, the
manifest ID, agent ID, `agent_instance_id` when present, the expiry as epoch
seconds (read with the verifier's own timestamp parser), the requirements, and
the per-artifact outcomes for the eight artifact bindings only. It carries no
mismatch detail, expected or actual hashes, or runtime evidence.

`manifest_digest()` takes an explicit media type. For
`application/agent-manifest+cose` it digests the complete envelope bytes. For
`application/agent-manifest+json` it takes a parsed v0.1 object and digests its
RFC 8785 form with nulls kept, detached signature and attachments included,
which is not the signing pre-image. Raw JSON bytes are refused, so a document
with duplicate keys cannot produce two readings. The trace-spec prototype
accepts only the COSE form.

## What it does not do

A signed declaration is intent, not proof of runtime state, and it adds no
trust anchor. The bridge in trace-spec#439
(`prototype.manifest_requirements.combine_requirements`) intersects the
declared profiles and authorities with the relying party's, keeps the shorter
age, treats a required flag on either side as required, and rejects a declared
component the relying party has not configured. A declared
`expected_observed_digest` that differs from a local pin is a mismatch, not an
override. Appraising component evidence and delegating to component appraisers
are also outside this module.
