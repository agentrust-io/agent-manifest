# ADR-0006: HITL approval mechanism design

**Status**: Accepted  
**Date**: 2026-05-20  
**Spec section**: Section 3.5 (Human-in-the-Loop Approvals)

## Context

EU AI Act Article 14 requires that high-risk AI systems support meaningful human oversight — including the ability for humans to intervene, override, or refuse to deploy the system's outputs. For agentic AI, this translates to: a human must be able to approve or block high-risk actions before they execute.

The manifest needs a mechanism to record this approval in a tamper-evident, verifiable way that:

1. Proves a specific human approved a specific action for a specific agent
2. Binds the approval to a time window, so it cannot be reused indefinitely
3. Is verifiable without an online call to an approval service at verification time
4. Does not require the original manifest issuer's key to record the approval

## Decision

Embed a **`hitl_record`** field directly in the manifest JSON. Each approval within the record is signed by the **approver's Ed25519 key** over the canonical form of `{manifest_id, approved_at, approved_scope, approver_id}`. The approval record is attached before the agent presents the manifest to a relying party.

The `approved_scope` within the approval is distinct from the manifest's `delegation_chain` scope — it captures what the human explicitly authorised (e.g., `max_notional_usd: 500_000`) rather than what the issuer delegated.

## Rationale

**Offline verifiability.** The approval signature can be verified by any party that holds the approver's public key — no call to an approval service is required at verification time. This is critical for air-gapped environments and for audit: the manifest file alone is sufficient evidence of the approval.

**Approver binding.** The signature covers `approver_id` (a SPIFFE URI or DID), which links the approval to a specific person's key. A compromised agent cannot forge an approval from a different approver — the signature would fail.

**Time-bounded approval.** `approval_duration_seconds` inside `approved_scope` limits how long the approval is valid. The verifier checks whether `approved_at + approval_duration_seconds > now`. An approver cannot issue a permanent blank cheque.

**Manifest binding.** The signature covers `manifest_id`, preventing approval replay: an approval for agent A cannot be copied into agent B's manifest.

**Separation from the manifest signature.** The manifest signature (Ed25519 over the full manifest JSON) and the HITL approval signature (Ed25519 over the approval fields) are independent. The agent can collect approvals from multiple approvers and attach them without re-signing the manifest — only the `hitl_record.approvals` array changes, not the signed fields.

## Alternatives considered

**Webhook-based approval at verification time**: The verifier calls an approval API to check status. Rejected because it creates an online dependency — a down approval service means no verification, which is an availability risk in production and an audit gap (the approval record is not embedded in the evidence pack).

**Out-of-band approval token (JWT)**: The approver issues a separate JWT that the agent presents alongside the manifest. Rejected because it requires managing a separate token format, a separate public key registry, and token revocation — all problems the manifest already solves.

**Approval via manifest re-signing**: The approver co-signs the entire manifest (multi-signature). Rejected because it requires the approver to hold the manifest issuer's key or participate in a multi-party signing protocol, which is operationally complex and creates key custody issues.

**Separate approval manifest**: A second manifest document that references the first. Rejected because it fragments the evidence — verifiers would need to fetch and verify two documents, and the audit trail requires keeping both in sync.

## Consequences

- Agents that require HITL must implement an approval workflow before presenting the manifest. The SDK provides `HitlApprovalSigner` to sign approvals; the workflow UI is out of scope for the spec.
- In production, approver keypairs should be hardware-backed (FIDO2/passkey, HSM). The spec does not mandate this but the tutorial notes it as strongly recommended.
- The `required_approvals` count is enforced by the verifier, not the SDK. A manifest with `required_approvals: 2` but only one approval in the record results in `HitlResult.APPROVAL_INSUFFICIENT`.
- Approval expiry is checked at verification time, not at approval time. An agent that presents an approval 90 minutes after `approval_duration_seconds: 3600` will be rejected. Agents must re-obtain approval for long-running actions.
- The `hitl_record` field is excluded from the manifest signing pre-image (like `attestation`) — this allows approvals to be attached after the manifest is issued and signed.

## References

- EU AI Act Article 14: Human oversight
- Spec Section 3.5: HITL approval record schema
- [FIDO2 / WebAuthn](https://fidoalliance.org/fido2/) — recommended approver key backing
