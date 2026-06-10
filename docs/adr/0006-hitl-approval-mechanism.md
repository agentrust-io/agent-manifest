# ADR-0006: Human-in-the-Loop (HITL) embedded approval record design

**Status**: Accepted  
**Date**: 2026-06-07  
**Spec section**: Section 3.5 (Human-in-the-Loop Approvals)

## Context

EU AI Act Article 14 requires that high-risk AI systems support meaningful human oversight, including the ability for humans to intervene or refuse to allow an agent's outputs before they take effect. For agentic AI, this means a human must be able to approve or block high-risk actions before execution.

The manifest needs a mechanism to record this approval in a tamper-evident, verifiable way that:

1. Proves a specific human approved a specific action for a specific agent
2. Binds the approval to a time window so it cannot be reused indefinitely
3. Is verifiable at any point without an online call to an approval service
4. Cannot be forged by the manifest issuer

## Decision

Embed a **`hitl_record`** field directly in the manifest JSON. The record contains one or more approval entries, each with the following fields: `approver_id` (human-attributable identity  -  see Amendment below), `approved_at` (ISO 8601 timestamp), `evidence_hash` (SHA-256 of the canonical form of the action being approved), `approval_duration_seconds` (validity window), and `revocation_signature` (Ed25519 signature by the approver over the canonical approval fields).

The approval record is **signed by the approver's key**, not the manifest issuer's key.

Verification semantics: a manifest with a HITL requirement is `APPROVED` only when all of the following hold:
- The `approver_id` appears in the verifier's allowed approver set
- `approved_at + approval_duration_seconds > now` (approval has not expired)
- The `evidence_hash` matches the SHA-256 of the action being approved
- The `revocation_signature` verifies against the approver's published public key

A missing `hitl_record` when one is required produces `INVALID`, not an unattested pass. The HITL gate cannot be bypassed silently.

## Rationale

**Offline verifiability.** Approval evidence travels with the manifest. Any verifier holding the approver's public key can check the approval without contacting an external service. This is essential for air-gapped environments and for producing a complete audit pack  -  the manifest file alone proves the approval happened.

**Approver binding via separate signature.** The approval signature covers `approver_id`, `manifest_id`, `approved_at`, and `evidence_hash`. A compromised agent cannot forge an approval from a different approver. The issuer cannot manufacture approvals  -  the approver's private key is required.

**Separation of duties.** The manifest issuer signs the manifest; the approver signs the approval. These are structurally independent. The issuer may not know the approver's key, and the approver does not need to re-sign the manifest. Agents can collect approvals from multiple approvers and attach them to the `hitl_record` array without triggering a re-sign of the manifest itself.

**Time-bounded approvals.** `approval_duration_seconds` prevents permanent blank cheques. A 3600-second approval window means the agent must re-obtain approval for actions that run beyond one hour.

**Evidence hash binding.** The `evidence_hash` field pins the approval to a specific action description. An approval for "transfer $50,000 to account X" cannot be replayed for "transfer $5,000,000 to account Y" because the hashes differ.

The `hitl_record` field is excluded from the manifest signing pre-image (alongside `attestation`) so that approvals can be attached after the manifest is issued, without invalidating the issuer's signature.

## Alternatives considered

**Webhook-based approval at verification time**: The verifier calls an external approval API on every verify call to check current status. Rejected because it creates an online dependency  -  a down approval service means verification fails in production, and the approval evidence is not embedded in the audit pack. Air-gapped deployments cannot use this pattern at all.

**OAuth 2.0 PKCE for human identity**: Use a browser-based OAuth flow to identify the approver. Rejected because it introduces a browser and redirect URI dependency into a machine-native security path. SPIFFE URIs and DIDs are more appropriate for workload and operator identity in server-side environments.

**Out-of-band approval token (separate JWT)**: The approver issues a JWT presented alongside the manifest. Rejected because it requires managing a separate token format, a separate public key registry, and token revocation  -  all problems the manifest already solves.

**Approval via manifest re-signing (multi-signature)**: The approver co-signs the entire manifest. Rejected because it requires the approver to participate in a multi-party signing protocol or hold the issuer key material, which creates key custody problems and breaks the separation of duties rationale.

## Consequences

- Agents that require HITL must implement an approval workflow before presenting the manifest. The SDK provides `HitlApprovalSigner` to construct and sign approval records; the approval UI is out of scope for the spec.
- The `required_approvals` count is enforced by the verifier. A manifest with `required_approvals: 2` but only one valid approval record results in `HitlResult.APPROVAL_INSUFFICIENT`.
- Approval expiry is checked at verification time, not at approval collection time. An agent that collects an approval and then presents the manifest 90 minutes later with `approval_duration_seconds: 3600` will be rejected. Long-running actions must implement re-approval logic.
- Approver keypairs should be hardware-backed (FIDO2/passkey or HSM) in production. The spec does not mandate this but the operational guidance notes it as strongly recommended.

## References

- EU AI Act Article 14: Human oversight requirements
- Spec Section 3.5: HITL approval record schema and verification semantics
- [FIDO2 / WebAuthn](https://fidoalliance.org/fido2/)  -  recommended backing for approver keys
- ADR-0009: SPIFFE URIs as the canonical identity format for machine workload identity (`agent_id`, `issuer`)  -  does not apply to `approver_id`

---

## Amendment  -  2026-06-10: `approver_id` must not use SPIFFE SVIDs

**Resolved by:** issue #40

The original **Decision** section referenced `approver_id` as a "SPIFFE URI or DID of the approver". This was incorrect. Issue #40 clarified:

> `approver_id` MUST be a human-attributable identity. SPIFFE SVIDs MUST NOT be used as `approver_id` values: SPIFFE SVIDs identify machine workloads, not natural persons.

Preferred forms for `approver_id`:
- Email URI: `mailto:approver@example.com`
- OIDC subject claim paired with issuer URI
- W3C DID bound to a hardware authenticator (e.g. FIDO2 passkey)

SPIFFE URIs remain the correct format for `agent_id` and `issuer` (see ADR-0009), but are explicitly prohibited for `approver_id`. The "DID of the approver" language in the original Decision is retained only when the DID is hardware-bound (e.g. `did:key` backed by a FIDO2 authenticator); a software-only DID is discouraged for the same reason SPIFFE is prohibited.
