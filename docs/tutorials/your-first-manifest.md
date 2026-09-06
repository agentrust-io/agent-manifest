# Your First Agent Manifest

Start with the [complete first-manifest example](../getting-started.md). It builds a signed software manifest, verifies independently supplied artifact inputs, and rejects both an edited record and a changed prompt hash. Use that single maintained example for installation, code, and expected output.

## Understand the signed object

For the supported v0.1 JSON form, `Ed25519Signer.sign(manifest_dict)` returns a signature block, not a complete manifest. Assign it to `manifest_dict["signature"]`. Passing only that block to `verify_manifest()` discards the manifest's identity, artifacts, and version.

The v0.2 representation uses a COSE envelope. See the [signature envelope decision](../adr/0011-signature-envelope.md) before changing formats; do not treat COSE bytes as a JSON signature block.

## Supply trust separately

The recipient supplies approved issuer keys and expected runtime artifacts through `VerificationContext`. A public key or expected hash copied from an incoming manifest cannot establish its own authority. Schema validation checks structure; signature verification and artifact comparison establish different properties.

A valid signature alone can leave the result `INCOMPLETE` when required runtime inputs are absent. A missing trusted key produces `UNVERIFIABLE`. Only accept the result your application's verification policy explicitly allows.

## Keep private keys out of output

The demo retains its private key only in memory and saves a public key for later verification. Use your approved secret-management mechanism for persistent issuer keys. Avoid printing private key material into terminal history, CI output, or logs.

## Next steps

Use the [revocation tutorial](revocation-and-key-rotation.md) to reject an issued manifest, the [integration gate](../integrations/index.md#run-a-local-verification-gate) to test application behavior, or [HITL workflows](hitl-approval-workflows.md) for approval-specific requirements.
