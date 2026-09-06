# Verify a Human Approval Record

Require an approval, authenticate it against an independently trusted approver key, and reject a changed approval method. The example uses a synthetic human identity and a software key; it demonstrates verification mechanics, not an actual human decision or hardware key custody.

## Run the example

Complete the [first-manifest guide](../getting-started.md), append this block to `first_manifest.py`, and run it again.

```python
from datetime import datetime, timezone
from agent_manifest._delegation import HitlApprovalSigner

approver = generate_ed25519()
approver_id = "mailto:reviewer@example.test"
approved_record = copy.deepcopy(record)
approved_record["hitl_record"] = {"required": True, "approvals": []}
approved_record["signature"] = Ed25519Signer(keypair).sign(approved_record)
approval_context = context.model_copy(update={
    "enforce_hitl": True,
    "approver_public_keys": {approver_id: approver.public_b64url()},
})
missing = verify_manifest(approved_record, approval_context, RevocationStore())
assert missing.result.value != "VALID"
assert missing.fields_verified.hitl_record.value == "MISSING"
print("PASS: missing required approval rejected")

approval = {
    "approval_id": "019236ab-cdef-7000-8000-000000000004",
    "approver_id": approver_id,
    "approver_identity_type": "email",
    "approver_role": "demo-reviewer",
    "approved_at": datetime.now(timezone.utc).isoformat(),
    "approved_scope": {
        "artifacts": ["system_prompt"],
        "risk_tier": "low",
        "approval_duration_seconds": 600,
        "conditions": [],
    },
    "approval_method": "software-key",
    "evidence_uri": "https://example.test/synthetic-approval",
}
approval["approval_signature"] = HitlApprovalSigner(approver).sign_approval(
    manifest_id=approved_record["manifest_id"],
    approved_at=approval["approved_at"],
    approved_scope=approval["approved_scope"],
    approver_id=approver_id,
    approval_method=approval["approval_method"],
)
approved_record["hitl_record"]["approvals"] = [approval]
accepted = verify_manifest(approved_record, approval_context, RevocationStore())
assert accepted.result.value == "VALID", accepted.model_dump_json()
print("PASS: trusted software approval accepted")

changed_approval = copy.deepcopy(approved_record)
changed_approval["hitl_record"]["approvals"][0]["approval_method"] = "hardware-key"
rejected = verify_manifest(changed_approval, approval_context, RevocationStore())
assert rejected.result.value != "VALID"
assert rejected.signature_verified  # The issuer signature still verifies.
print("PASS: relabeled approval rejected independently of issuer signature")
```

Expect three additional `PASS` lines. The recipient retains the approver key separately; receiving a key alongside an approval does not authorize that key.

## Understand the two signatures

The issuer signs the HITL requirement. The signing preimage normalizes `approvals` to an empty list, allowing approvals to attach after issuance. Adding or removing an approval therefore does not by itself break the issuer signature. Each approval needs its own signature and the receiving policy must enforce its presence.

The approval signature binds the manifest ID, approver ID, approval timestamp, scope, and supplied approval method. Role labels and evidence links are not substitutes for independently authenticated authority. A `hardware-key` string alone does not prove hardware custody; use a trusted approval service and the required evidence for that claim.

## Apply it to a real workflow

Authenticate the human and establish their authority over the requested action before issuing the approval. Configure trusted approver keys, expiry handling, required scope, and `enforce_hitl` on the recipient. Check operation-specific authorization before allowing side effects, including retries.

A signed approval is one evidence artifact. It does not, by itself, establish regulatory compliance, appropriate human oversight, or that an approved action completed. See [revocation](revocation-and-key-rotation.md) for withdrawing manifests and [the integration gate](../integrations/index.md#run-a-local-verification-gate) for rejection handling.
