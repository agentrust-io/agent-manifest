# Agent Governance Toolkit Integration

Use Agent Manifest as evidence input to the application's governance decision. It binds declared composition and configured verification inputs; a governance runtime separately decides whether to permit the requested operation.

## Establish the evidence boundary

Start with the [runnable manifest gate](index.md#run-a-local-verification-gate). Supply approved issuer keys, actual runtime artifact observations, and current revocation state. Reject missing or mismatched evidence before invoking the protected operation.

Record the verification result and evidence scope alongside the policy decision. Do not convert a self-reported attestation level into a trusted score or assume `VALID` means hardware was appraised. Hardware evidence needs the SDK's independently supplied appraisal inputs and the application's acceptance policy.

## Connect the runtime

Choose the integration point in your deployed [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) version: the service boundary that authorizes a tool call, delegation, or session. Pass the verified result into that decision and preserve the resulting policy evidence. This page does not define a universal `agt.trust` API or score formula.

Bind decision evidence to the same manifest ID and operation being authorized. A valid signature or an audit-chain commitment does not prove complete logging, correct outputs, or completed execution. For gateway-enforced tool access, see [cMCP session binding](../tutorials/cmcp-session-binding.md).

## Validate your integration

Use an accepted manifest as the positive control. Then verify that unknown keys, revoked IDs, changed artifacts, and missing required appraisal prevent the protected operation. Confirm the application does not turn a failed or incomplete verification into a permissive trust score.
