# HITL-approved manifest example

This example shows a manifest with a populated `hitl_record`  -  a cryptographically signed human approval for a high-risk action.

## Files

| File | Description |
|------|-------------|
| `manifest-with-hitl.json` | Manifest with `required_approvals: 1` and a populated `hitl_record` |
| `verify.sh` | Shows the manifest is VALID with the approval present and INVALID without it |

## The `hitl_record` structure

```json
{
  "required_approvals": 1,
  "approval_method": "hardware-key",
  "approvals": [
    {
      "approved_at": "2026-06-05T09:00:00Z",
      "approver_id": "mailto:alice@acme.example",
      "approved_scope": {
        "tools": ["execute_payment"],
        "data_classifications": ["pii"],
        "approval_expiry": "2026-06-05T09:30:00Z"
      },
      "approval_signature": "BASE64URL_PLACEHOLDER"
    }
  ]
}
```

### What is signed

The `approval_signature` is an Ed25519 signature over the RFC 8785 canonical form of:

```json
{
  "manifest_id": "...",
  "approved_at": "2026-06-05T09:00:00Z",
  "approved_scope": {...},
  "approver_id": "mailto:alice@acme.example"
}
```

This proves that `alice` deliberately approved **this exact scope** for **this exact manifest** at **this exact time**. The approval cannot be reused for a different manifest or a different scope.

### Approval expiry

The `approval_expiry` in `approved_scope` is an additional bound within the manifest's own `expires_at`. A verifier running after `approval_expiry` returns `HITL_EXPIRED` even if the manifest itself has not expired.

## For auditors

This record satisfies:
- EU AI Act Article 14 (human oversight)
- HIPAA § 164.308(a)(5) (documented human review)
- GDPR Article 25 (data protection by design)

See [Compliance: EU AI Act](../../docs/compliance/eu-ai-act.md) for the full mapping.
