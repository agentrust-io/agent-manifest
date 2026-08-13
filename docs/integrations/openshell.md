# NVIDIA OpenShell integration

Agent Manifest binds the OpenShell and AGT deployment configuration approved
before execution. OpenShell OCSF logs and TRACE records describe what happened
after startup. Keep those roles separate and join them through stable identity
and matching artifact hashes.

## What to bind

Create the exact canonical composite policy bundle used by the OpenShell TRACE
adapter. It contains the effective OpenShell policy bytes and revision plus the
AGT Agent Control Specification manifest bytes. Bind its digest as
`artifacts.policy_bundle.hash`.

| Manifest artifact | OpenShell deployment input |
|---|---|
| `policy_bundle.hash` | Composite OpenShell and ACS policy bundle digest |
| `policy_bundle.enforcement_mode` | Weakest configured enforcement mode across both layers |
| `tool_manifest` | Resolved tools available to the agent, including `shell.execute` |
| `model_identity` | Model selected for this deployment |
| `supply_chain` | Immutable sandbox image and agent package provenance |
| `decision_trace` | Audit-chain root at manifest issuance, when available |

Do not put runtime OCSF events into the manifest. The manifest commits to the
approved deployment; TRACE commits to the execution transcript.

## Required joins

Use the same SPIFFE URI or DID as Agent Manifest `agent_id` and TRACE `subject`.
The runtime collector should also retain:

- manifest identifier;
- OpenShell sandbox identifier;
- effective policy revision;
- immutable workload image digest;
- composite policy bundle hash.

A verifier compares the manifest's approved policy and workload hashes with the
TRACE record built from OpenShell evidence. A mismatch means the runtime did not
execute the approved deployment and must fail verification.

## Assurance boundary

An OpenShell compute driver is not an Agent Manifest hardware attestation
provider. Use Level 0 unless the deployment supplies a supported quote and the
manifest signing key is demonstrably bound to its measured workload.

For runtime evidence construction, see the
[`agentrust-io/integrations` OpenShell adapter](https://github.com/agentrust-io/integrations/tree/main/integrations/openshell).
