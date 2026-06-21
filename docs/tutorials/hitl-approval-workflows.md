# HITL Approval Workflows

Human-in-the-loop (HITL) approval lets an agent record that a human explicitly authorised a high-risk action and cryptographically binds that authorisation to the manifest. The EU AI Act Article 14 requires "appropriate human oversight measures" for high-risk AI systems; a signed HITL record is one concrete way to demonstrate compliance.

After this tutorial you will be able to:

- Configure a manifest to require human approval
- Build and attach a signed `HITLRecord` to a manifest
- Verify that the approval is present, unexpired, and from an authorised approver
- Understand what triggers `HitlResult.MISSING` and `HitlResult.EXPIRED`

## Prerequisites

```bash
pip install agent-manifest
```

---

## Why HITL belongs in the manifest

A plain timestamp field in a database can be backdated or deleted. The HITL record in an agent manifest is different:

1. The approver signs over `{manifest_id, approved_at, approved_scope, approver_id}` with their own key
2. That signature is embedded in the manifest
3. The manifest itself is then signed by the agent's key

Removing or altering the approval breaks both signatures. Verifiers can reject the manifest without contacting any external system.

---

## Configure the HITL requirement

Set `hitl_record.required = True` when building the manifest. Leave `approvals` empty - it is filled in after the human signs off. The `required` flag is covered by the issuer signature; the `approvals` list is normalized to `[]` in the signing pre-image so approvals can attach post-issuance (spec Section 3.6).

```python
from agent_manifest import Manifest, ArtifactBindings, CryptoProfile
from agent_manifest._types import ManifestId
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)
manifest_id = str(ManifestId.generate())

manifest = Manifest(
    manifest_id=manifest_id,
    agent_id="spiffe://finance.acme.com/agent/trading/prod",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=4),
    issuer="spiffe://finance.acme.com/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(),
    hitl_record={
        "required": True,
        "approvals": [],   # filled in after human approval
    },
)
```

---

## Build the evidence hash

The `evidence_hash` field binds the approval to a specific action or dataset, not just to the manifest. Compute it by hashing the action description in a stable, reproducible way.

```python
import hashlib
import json

action = {
    "action": "execute_trade",
    "amount_usd": 500000,
    "symbol": "AAPL",
}
evidence_hash = "sha256:" + hashlib.sha256(
    json.dumps(action, sort_keys=True).encode()
).hexdigest()
```

---

## Get human approval and sign it

In production this step happens through an approval workflow - a Slack bot, web UI, or dedicated approval service. The approver authenticates with their FIDO2 key, reviews the action, and the system signs on their behalf.

```python
from agent_manifest import generate_ed25519
from agent_manifest._delegation import HitlApprovalSigner

# In production: load the approver's key from their FIDO2 or HSM session
approver_kp = generate_ed25519()

approved_at = datetime.now(timezone.utc).isoformat()
approved_scope = {
    "artifacts": ["tool_manifest", "policy_bundle"],
    "risk_tier": "high",
    "approval_duration_seconds": 3600,  # approval valid for 1 hour
    "conditions": [
        "action=execute_trade",
        "max_notional_usd <= 500000",
        f"evidence_hash={evidence_hash}",
    ],
}

approver = HitlApprovalSigner(keypair=approver_kp)
approval_sig = approver.sign_approval(
    manifest_id=manifest_id,
    approved_at=approved_at,
    approved_scope=approved_scope,
    approver_id="mailto:jane.doe@finance.acme.com",
)
```

---

## Attach the approval and sign the manifest

```python
from agent_manifest._signing import Ed25519Signer

agent_kp = generate_ed25519()

manifest_dict = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
manifest_dict["hitl_record"]["approvals"] = [{
    "approval_id":            "019236ab-0000-7000-8000-0000000000a1",  # UUID v7
    "approver_id":            "mailto:jane.doe@finance.acme.com",
    "approver_identity_type": "email",
    "approver_role":          "trading-desk-supervisor",
    "approved_at":            approved_at,
    "approved_scope":         approved_scope,
    "approval_signature":     approval_sig,
    "approval_method":        "hardware-key",
    "evidence_uri":           "https://approvals.finance.acme.com/records/trade-500k",
}]

signer = Ed25519Signer(agent_kp)
manifest_dict["signature"] = signer.sign(manifest_dict)
```

---

## Verify HITL with `verify_manifest()`

Pass `enforce_hitl=True` in the `VerificationContext` so the verifier treats a missing or expired approval as a hard failure.

```python
from agent_manifest._verify import (
    HitlResult,
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

# Fail-closed: VALID requires the issuer's key in trusted_keys. Without
# trusted keys the result is UNVERIFIABLE - never VALID.
ctx = VerificationContext(
    enforce_hitl=True,
    trusted_keys={agent_kp.key_id: agent_kp.public_b64url()},
)
result = verify_manifest(manifest_dict, ctx, RevocationStore())

assert result.fields_verified.hitl_record == HitlResult.APPROVED
assert result.result == OverallResult.VALID
print(f"HITL status: {result.fields_verified.hitl_record}")  # APPROVED
```

---

## Failure modes

### Missing approval

When `required = True` but `approvals` is empty and `enforce_hitl=True`, the result is `MISMATCH` with `HitlResult.MISSING`:

```python
no_approval_manifest = dict(manifest_dict)
no_approval_manifest["hitl_record"] = {
    "required": True,
    "approvals": [],
}

ctx = VerificationContext(enforce_hitl=True)
result = verify_manifest(no_approval_manifest, ctx, RevocationStore())

assert result.fields_verified.hitl_record == HitlResult.MISSING
assert result.result == OverallResult.MISMATCH
```

### Expired approval

When `approval_duration_seconds` has elapsed since `approved_at`, the verifier sets `HitlResult.EXPIRED`. This always propagates to `MISMATCH` regardless of `enforce_hitl`:

```python
import time

expired_scope = {**approved_scope, "approval_duration_seconds": 1}
expired_sig = approver.sign_approval(
    manifest_id=manifest_id,
    approved_at=approved_at,
    approved_scope=expired_scope,
    approver_id="mailto:jane.doe@finance.acme.com",
)

expired_manifest = dict(manifest_dict)
expired_manifest["hitl_record"]["approvals"][0]["approved_scope"] = expired_scope
expired_manifest["hitl_record"]["approvals"][0]["approval_signature"] = expired_sig

time.sleep(2)  # wait for the 1-second approval to expire

result = verify_manifest(expired_manifest, VerificationContext(), RevocationStore())
assert result.fields_verified.hitl_record == HitlResult.EXPIRED
assert result.result == OverallResult.MISMATCH
```

### Approval from an unauthorised approver

The verifier checks that the approval signature is cryptographically valid but does not enforce which `approver_id` values are acceptable - that is your policy. After calling `verify_manifest`, check the `approver_id` against your authorised set:

```python
AUTHORISED_APPROVERS = {
    "mailto:jane.doe@finance.acme.com",
    "mailto:bob.smith@finance.acme.com",
}

result = verify_manifest(manifest_dict, VerificationContext(enforce_hitl=True), RevocationStore())

if result.fields_verified.hitl_record == HitlResult.APPROVED:
    for approval in manifest_dict["hitl_record"]["approvals"]:
        if approval["approver_id"] not in AUTHORISED_APPROVERS:
            raise PermissionError(
                f"Approval from unauthorised approver: {approval['approver_id']}"
            )
```

---

## Production guidance

| Concern | Recommendation |
|---------|----------------|
| Approver key storage | FIDO2 hardware key or HSM; software keys are for development only |
| Approval UI | Hash the `approved_scope` dict from your UI before presenting it to the approver for signing |
| Multiple approvers | Add one entry per approver to `approvals`; each is independently signed and verified |
| Approval duration | 1-4 hours; require re-approval for long-running jobs rather than extending the window |
| Audit trail | Log each `approval_signature` and `evidence_uri` in your SIEM alongside the manifest ID |
| EU AI Act Art. 14 | Document that `approved_scope` maps to the specific AI system output that was reviewed |

---

## Summary

This tutorial walked through signing a HITL approval with an approver's key, embedding it in a manifest, and verifying it with `enforce_hitl=True`. The signed approval binds the human review to a specific action scope and expires automatically. See [Revocation and key rotation](revocation-and-key-rotation.md) to revoke a manifest if an approver's key is compromised, and [Server-side verification](server-side-verification.md) to enforce HITL at the relying party.
