# Revocation example

This example shows the full revocation lifecycle:

1. A manifest is valid and passes verification
2. A revocation record is created and appended to the CRL
3. The same manifest fails verification with `REVOKED`

## Files

| File | Description |
|------|-------------|
| `valid-manifest.json` | A valid, unexpired manifest |
| `revocation-record.json` | The signed revocation record for this manifest |
| `crl.jsonl` | A JSON-Lines CRL file containing the revocation record |
| `demo.sh` | End-to-end demo: verify passes, revoke, verify fails |

## The revocation record format

```json
{
  "manifest_id": "019236ab-0000-7000-8000-000000000020",
  "revoked_at": "2026-06-05T10:00:00Z",
  "reason": "Signing key compromised",
  "revoked_by": "spiffe://trust.acme.co/security-team",
  "revocation_signature": "BASE64URL_PLACEHOLDER",
  "signer_key_id": "sha256:..."
}
```

The `revocation_signature` is an Ed25519 signature over the RFC 8785 canonical form of `{manifest_id, revoked_at, reason, revoked_by}`. Only the key holder can revoke a manifest — the signature proves the revocation is authentic.

## CRL format

The `crl.jsonl` file is append-only JSON-Lines: one `SignedRevocationRecord` per line. The file grows monotonically; records are never deleted. This makes it easy to serve from any static file host or object storage bucket.

```
{"manifest_id":"019236ab...","revoked_at":"2026-06-05T10:00:00Z",...}
{"manifest_id":"019236ab...","revoked_at":"2026-06-05T11:30:00Z",...}
```

See [Tutorial: Revocation and key rotation](../../docs/tutorials/revocation.md) for the full implementation.
