# Agent Governance Toolkit Integration

This page is for teams using the Microsoft Agent Governance Toolkit (AGT), which checks agent actions against rules while they run. It shows how to feed a checked manifest into AGT's decision. The manifest tells AGT what the agent was approved to run; AGT still decides whether to allow each requested action.

## Establish the evidence boundary

Start with the [runnable manifest gate](index.md#run-a-local-verification-gate). Give it the issuer keys you approved, the values actually in use at runtime, and the current revocation list. Reject missing or mismatched evidence before the protected action runs.

Record the check result, and what it covered, next to the policy decision. Do not turn a level the agent reports about itself into a trusted score, and do not assume `VALID` means hardware evidence was checked. Hardware evidence needs the SDK's appraisal inputs, supplied separately, and your application's own rules for accepting it.

## Connect the runtime

Pick the connection point in your deployed [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) version: the service boundary that approves a tool call, a delegation or a session. Pass the checked result into that decision and keep the policy evidence that comes out. This page does not define a universal `agt.trust` API or a score formula.

Tie the decision evidence to the same manifest ID and the same action being approved. A valid signature or a signed audit-log root does not prove that logging was complete, that outputs were correct, or that the action finished. For tool access enforced at a gateway, see [cMCP session binding](../tutorials/cmcp-session-binding.md).

## Validate your integration

Use an accepted manifest as the case that should pass. Then confirm that unknown keys, revoked IDs, changed artifacts and missing required hardware checks each stop the protected action. Confirm the application never turns a failed or incomplete check into a permissive trust score.
