# Agent Credentials integration

An Agent Manifest and an agent credential answer different questions. The manifest is the signed, pre-execution declaration of the deployment that was approved. A credential presents a claim to a relying party at a particular decision point. Runtime evidence connects that decision point to the exact manifest and agent instance involved.

This guide describes that three-layer bridge. It is informative: it does not add fields or conformance requirements to the Agent Manifest specification.

For the system-level view across Agent Card, registration, BOM, provenance,
attestation, and runtime evidence, see the [standards integration
landscape](standards-landscape.md).

## How the layers divide the problem

| Layer | Primary question | Typical evidence | What it does not prove |
|---|---|---|---|
| Agent credential | Who or what presents this claim, under whose authority, and for which decision? | Issuer, subject, audience, validity window, claim references | That the approved deployment is the one now executing |
| Agent Manifest | What deployment content was approved before execution? | Signed manifest, artifact bindings, attestation, issuer authorization | What changed or happened after the manifest was issued |
| Runtime evidence | What state was observed at a defined execution boundary? | Signed or attested event, manifest digest, agent-instance identifier, state fingerprint | That every relevant event was captured, or that observed behavior was correct |

The useful credential claim is therefore not a fresh assertion that repeats manifest fields. It is a reference to independently verifiable evidence:

1. the exact manifest that governed the operation;
2. the runtime-evidence record captured for the relevant agent instance; and
3. the boundary at which that evidence was captured.

## Integration point 1: bind the exact manifest

A credential should identify the exact manifest used for the access decision, not merely the latest manifest for the agent. Carry both the manifest identifier and a digest of the signed manifest bytes (or the signed COSE envelope for version 0.2).

```json
{
  "manifest_id": "01926b4c-79a0-7f3e-9c21-4e0f0a1b2c3d",
  "manifest_digest": "sha256:7e1f...9a02"
}
```

The identifier supports lookup. The digest prevents a different revision from being substituted under the same lookup path. The relying party still verifies the manifest normally, including issuer authorization, signature or COSE envelope, validity window, revocation status, artifact bindings, and required attestation.

## Integration point 2: capture state at a defined boundary

An execution boundary tells a producer when to capture runtime state. OCSF pull request [#1704](https://github.com/ocsf/ocsf-schema/pull/1704) proposes normalized `stop_reason_id` values on the `ai_operation` profile:

| Proposed value | Boundary meaning | Credential use |
|---|---|---|
| `Stop` (1) | The model reached a normal stopping point | Capture may describe the completed operation |
| `Length` (2) | Generation ended at a length or token limit | Treat state as truncated; do not present it as a normal completion |
| `Tool Use` (3) | Generation stopped to request a tool | Capture before the credential-gated tool decision |
| `Session Stop` (4) | The session or connection ended | Capture terminal state if the producer still has it |
| `Unknown` (0) | The producer cannot normalize the reason | Do not claim that a trustworthy boundary was reconstructed |

`Tool Use` is the important admission-control case: the producer captures evidence before the requested tool executes, and the relying party evaluates the credential before allowing the call.

The stop reason is a trigger and a description, not proof. It is producer-reported metadata. A relying party trusts the captured state only to the degree that the runtime record is signed or attested, its signer is authorized, its freshness is established, and its chain is intact. As of August 2026, OCSF #1704 remains open, so producers using these values are implementing a proposed mapping rather than a released core-schema contract.

## Integration point 3: make the runtime record the claim

The credential should carry the digest of, or a resolvable reference to, the signed runtime record. The record itself carries the correlation data and the measured state.

```json
{
  "credential_subject": "spiffe://trust.example/agent/payments-processor",
  "decision": {
    "purpose": "authorize tool invocation",
    "tool": "payments.issue_refund"
  },
  "manifest": {
    "id": "01926b4c-79a0-7f3e-9c21-4e0f0a1b2c3d",
    "digest": "sha256:7e1f...9a02"
  },
  "runtime_evidence": {
    "uri": "https://evidence.example/events/01926b4d-0001-7000-8000-000000000001",
    "digest": "sha256:c960...5d09",
    "agent_instance": "spiffe://trust.example/agent/payments-processor/01926b4c-1234-7abc-9def-000000000001",
    "boundary": "tool_use"
  }
}
```

The credential issuer signs its statement over these references. The relying party then verifies each layer independently:

1. verify the credential issuer, audience, validity, and authorization;
2. retrieve the exact manifest and match `manifest.digest`;
3. verify the manifest and establish the approved deployment identity;
4. retrieve the runtime record and match `runtime_evidence.digest`;
5. verify the runtime record's signer or attestation, freshness, and chain continuity;
6. confirm that the runtime record identifies the intended agent instance and manifest; and
7. apply the relying party's policy to the requested operation.

A `VALID` manifest is an input to step 7. It is not, by itself, authorization for the tool call.

## Integration point 4: preserve chain of custody

OCSF issue [#1724](https://github.com/ocsf/ocsf-schema/issues/1724) proposes an Agent Trust-Base Inventory class that applies the existing `record_integrity` profile per emission. That proposal is a natural carrier for repeated state snapshots, but it is not yet an assigned OCSF event class.

Where a producer uses `record_integrity`, the evidence chain should:

- scope `chain_uid` to the agent instance;
- give every emission its own event identifier;
- omit `prev_event` on the genesis record;
- have each later `prev_event` reference and fingerprint its predecessor;
- identify the authority whose signing credential must be accepted; and
- emit a configuration change before a newly introduced dependency first executes when the record is used for admission control.

A cryptographically intact chain proves ordering and exposes modification of recorded entries. It does not prove completeness: a compromised producer may fail to emit an event. Consumers need an independent expectation for cadence or required boundaries if a missing emission must be detected.

## What this bridge does not cover

- It does not turn the manifest into a runtime monitor.
- It does not make a self-reported stop reason trustworthy without signed or attested evidence.
- It does not make every intermediate model state reproducible or attestable.
- It does not prove that runtime evidence is complete or behaviorally correct.
- It does not authorize an operation merely because the manifest verifies as `VALID`.
- It does not place credential material, private keys, tokens, or bearer secrets into the manifest or runtime record. Carry references, key identifiers, and granted scopes instead.
- It does not standardize the credential envelope. A verifiable credential, workload credential, or application-specific signed token can use the pattern if the relying party can authenticate its issuer and verify the referenced evidence.

## Current standards status

The bridge is usable as an integration pattern today, but two upstream OCSF pieces remain proposals:

- [`stop_reason_id` on `ai_operation` (#1704)](https://github.com/ocsf/ocsf-schema/pull/1704) defines the proposed boundary vocabulary.
- [Agent Trust-Base Inventory (#1724)](https://github.com/ocsf/ocsf-schema/issues/1724) proposes the runtime carrier and repeated-emission semantics.

Implementations should record the schema version or extension vocabulary they use and should not emit unassigned class number `5050` as though it were part of core OCSF.

## Related material

- [Standards integration landscape](standards-landscape.md) — record ownership,
  reference flow, lifecycle changes, and the end-to-end integration diagram
- [OCSF runtime-evidence crosswalk](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.2.md#64-crosswalk-ocsf-runtime-evidence) — identity and delegation correspondence in the Agent Manifest specification
- [Server-side verification](../tutorials/server-side-verification.md) — verifying a manifest at a relying party
- [A2A delegation chains](../tutorials/delegation-chains.md) — narrowing authority between principals
- [Agent Credentials RFC discussion](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/99)
- [CoSAI WS4 Agent Manifest review](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149)
