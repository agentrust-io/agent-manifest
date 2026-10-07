# Delegation and HITL approvals

Delegation is when one agent hands part of a task to another agent (agent-to-agent, or A2A); each hand-off is a signed hop that can only narrow what the next agent may do. HITL (human in the loop) approvals are records signed by a person who approved an action. These functions create and check both.

A2A delegation chain signing, verification, and HITL approval records. See [Tutorial: A2A delegation chains](../tutorials/delegation-chains.md) and [Tutorial: HITL approval workflows](../tutorials/hitl-approval-workflows.md).

## Delegation chain

::: agent_manifest._delegation.DelegationHopSigner

::: agent_manifest._delegation.verify_delegation_chain

## HITL approvals

::: agent_manifest._delegation.HitlApprovalSigner

::: agent_manifest._delegation.verify_hitl_approval
