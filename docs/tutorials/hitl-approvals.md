# HITL approval workflows

Human-in-the-loop (HITL) approval lets an agent record that a human explicitly authorised a high-risk action  -  and cryptographically binds that approval to the manifest. After this tutorial you will be able to:

- Create a manifest that requires human approval
- Record a signed approval from a human approver
- Verify that the approval is present, unexpired, and cryptographically valid
- Understand what triggers `HITL_MISSING` and `HITL_EXPIRED`

## Prerequisites

```bash
pip install agent-manifest
```

## Why sign the approval?

A plain timestamp field can be forged. The HITL approval is signed by the **approver's key** over the canonical form of `{manifest_id, approved_at, approved_scope, approver_id}`. This proves:

1. The named approver actually saw this exact manifest
2. The approval was given at a specific time
3. The approval covers a specific scope  -  not a blank cheque

---

## Step 1: Generate keypairs

```python
from agent_manifest import generate_ed25519

agent_kp = generate_ed25519()     # the agent's signing key
approver_kp = generate_ed25519()  # the human approver's key (use FIDO2 in production)
```

---

## Step 2: Build a manifest that requires approval

Set `hitl_record.required = True` and leave `approvals` empty  -  the agent will fill this in after getting human sign-off.

```python
from agent_manifest import Manifest, ArtifactBindings, CryptoProfile
from agent_manifest._types import ManifestId
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)
manifest_id = str(ManifestId.generate())

manifest = Manifest(
    manifest_id=manifest_id,
    agent_id="spiffe://trust.example/agent/trading/prod",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=4),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(),
    hitl_record={
        "required": True,
        "approvals": [],          # filled in below
    },
)
```

---

## Step 3: Get human approval and sign it

In production this happens through an approval workflow (Slack bot, web UI, etc.). Here it is expressed as code:

```python
from agent_manifest._delegation import HitlApprovalSigner

approver = HitlApprovalSigner(keypair=approver_kp)
approved_at = datetime.now(timezone.utc).isoformat()

approved_scope = {
    "artifacts": ["tool_manifest", "policy_bundle"],
    "risk_tier": "high",
    "approval_duration_seconds": 3600,   # approval is valid for 1 hour
    "conditions": ["action=execute_trade", "max_notional_usd <= 500000"],
}

approval_sig = approver.sign_approval(
    manifest_id=manifest_id,
    approved_at=approved_at,
    approved_scope=approved_scope,
    approver_id="mailto:alice@example.com",
)
```

---

## Step 4: Attach the approval to the manifest

```python
from agent_manifest._signing import Ed25519Signer

signed_manifest = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
signed_manifest["hitl_record"]["approvals"] = [{
    "approval_id":            "019236ab-0000-7000-8000-0000000000a1",  # UUID v7
    "approver_id":            "mailto:alice@example.com",
    "approver_identity_type": "email",
    "approver_role":          "trading-desk-supervisor",
    "approved_at":            approved_at,
    "approved_scope":         approved_scope,
    "approval_signature":     approval_sig,
    "approval_method":        "hardware-key",
    "evidence_uri":           "https://approvals.example.com/records/execute-trade",
}]

signer = Ed25519Signer(agent_kp)
signed_manifest["signature"] = signer.sign(signed_manifest)
```

---

## Step 5: Verify the approval

```python
from agent_manifest._delegation import verify_hitl_approval

approval = signed_manifest["hitl_record"]["approvals"][0]

verify_hitl_approval(
    approval=approval,
    manifest_id=manifest_id,
    approver_public_key=approver_kp.public_bytes,
)
print("HITL approval is valid")
```

To verify using the full manifest verifier:

```python
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest
)

# Fail-closed: VALID requires the issuer's key in trusted_keys. Without
# trusted keys the result is UNVERIFIABLE - never VALID.
ctx = VerificationContext(
    enforce_hitl=True,
    trusted_keys={agent_kp.key_id: agent_kp.public_b64url()},
)
result = verify_manifest(signed_manifest, ctx, RevocationStore())

assert result.fields_verified.hitl_record.value == "APPROVED"
assert result.result == OverallResult.VALID
```

---

## Failure modes

### Missing approval (`HITL_MISSING`)

```python
# Manifest requires HITL but approvals list is empty
manifest_no_approval = {
    **signed_manifest,
    "hitl_record": {"required": True, "approvals": []},
}
ctx = VerificationContext(enforce_hitl=True)
result = verify_manifest(manifest_no_approval, ctx, RevocationStore())
# result.fields_verified.hitl_record == HitlResult.MISSING
# result.result == OverallResult.MISMATCH  (when enforce_hitl=True)
```

### Expired approval (`HITL_EXPIRED`)

```python
import time

# The approval_duration_seconds has elapsed
old_scope = {**approved_scope, "approval_duration_seconds": 1}  # 1 second
old_approval_sig = approver.sign_approval(
    manifest_id=manifest_id,
    approved_at=approved_at,
    approved_scope=old_scope,
    approver_id="mailto:alice@example.com",
)
time.sleep(2)

manifest_expired = dict(signed_manifest)
manifest_expired["hitl_record"]["approvals"][0]["approved_scope"] = old_scope
manifest_expired["hitl_record"]["approvals"][0]["approval_signature"] = old_approval_sig

result = verify_manifest(manifest_expired, VerificationContext(), RevocationStore())
# result.fields_verified.hitl_record == HitlResult.EXPIRED
```

### Tampered approval (signature mismatch)

```python
from cryptography.exceptions import InvalidSignature

tampered = dict(approval)
tampered["approved_scope"] = {**approved_scope, "max_notional_usd": 10_000_000}

try:
    verify_hitl_approval(tampered, manifest_id, approver_kp.public_bytes)
except InvalidSignature:
    print("Approval signature invalid  -  scope was tampered")
```

---

## Production guidance

| Concern | Recommendation |
|---------|----------------|
| Approver key storage | FIDO2 hardware key or HSM  -  software keys are only for development |
| Approval UI | Generate the `approved_scope` dict from your UI, sign on the server with the approver's key after authentication |
| Multiple approvers | Add one entry per approver to `approvals`; each is independently signed and verified |
| Approval duration | Keep short (1–4 hours); for long-running jobs, re-approve rather than extending |
| Audit | Store each `approval_signature` in your audit log with the approver's public key |

---

## What's next

- [Tutorial: Revocation and key rotation](revocation.md)  -  revoke a manifest if the approver's key is compromised
- [Tutorial: Server-side verification](server-side-verification.md)  -  enforce HITL at the relying party with `enforce_hitl=True`
