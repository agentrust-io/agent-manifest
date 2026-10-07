# NVIDIA OpenShell integration

This page is for teams running agents inside NVIDIA OpenShell sandboxes. It shows how to link the setup you approved before the agent started to the records of what the agent did afterwards, so a checker can tell whether the sandbox ran the approved setup.

The two records have different jobs. Agent Manifest records the OpenShell and AGT configuration approved before execution. OpenShell's OCSF logs (a common security-event log format) and TRACE records describe what happened after startup. Keep those roles separate and join them through a shared identity and matching artifact hashes (fingerprints of exact file contents).

## What to bind

Build the exact combined policy bundle that the OpenShell TRACE adapter uses. It contains the OpenShell policy bytes actually in force and their revision, plus the bytes of the AGT Agent Control Specification (ACS) manifest. Put the hash of that bundle in
`artifacts.policy_bundle.hash`.

| Manifest artifact | OpenShell deployment input |
|---|---|
| `policy_bundle.hash` | Composite OpenShell and ACS policy bundle digest |
| `policy_bundle.enforcement_mode` | Weakest configured enforcement mode across both layers |
| `tool_manifest` | Resolved tools available to the agent, including `shell.execute` |
| `model_identity` | Model selected for this deployment |
| `supply_chain` | Immutable sandbox image and agent package provenance |
| `decision_trace` | Audit-chain root at manifest issuance, when available |

Do not put runtime OCSF events into the manifest. The manifest records the approved deployment; TRACE records what ran.

## Required joins

Use the same SPIFFE URI or DID (standard forms of workload or agent identity) as the Agent Manifest `agent_id` and the TRACE `subject`.
The runtime collector should also keep:

- manifest identifier;
- OpenShell sandbox identifier;
- effective policy revision;
- immutable workload image digest;
- composite policy bundle hash.

A verifier compares the approved policy and workload hashes in the manifest with the
TRACE record built from OpenShell evidence. A mismatch means the runtime did not
run the approved deployment, and verification must fail.

## Assurance boundary

An OpenShell compute driver does not count as an Agent Manifest hardware attestation
provider (a source of signed hardware reports). Use Level 0 unless the deployment supplies a supported hardware report (quote) and the
manifest signing key is shown to be tied to the measured workload.

For how to build the runtime records, see the
[`agentrust-io/integrations` OpenShell adapter](https://github.com/agentrust-io/integrations/tree/main/integrations/openshell).
