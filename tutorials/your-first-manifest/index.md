# Your First Agent Manifest

This page explains what the [complete first-manifest example](https://manifest.agentrust-io.com/getting-started/index.md) is doing, so you avoid the common mistakes when you adapt it. Run that example first: it signs a manifest, checks it against values you supply, and rejects both an edited record and a changed prompt. Installation, code and expected output live there, in one maintained place.

## Understand the signed object

For the supported v0.1 JSON form, `Ed25519Signer.sign(manifest_dict)` returns only the signature block, and you attach it to the manifest yourself: assign it to `manifest_dict["signature"]`. If you pass only that block to `verify_manifest()`, the checker never sees the manifest's identity, parts or version.

The v0.2 format wraps the manifest in a binary envelope called COSE. See the [signature envelope decision](https://manifest.agentrust-io.com/adr/0011-signature-envelope/index.md) before switching formats; COSE bytes are not a JSON signature block.

## Supply trust separately

Whoever checks the manifest brings their own trust. They pass the signer keys they have approved, and the values of what is actually running, through `VerificationContext`. A public key or expected hash copied out of the incoming manifest proves nothing, because the manifest would be vouching for itself. Three checks answer three different questions: schema validation asks whether the record is well formed, the signature check asks who signed it, and the comparison asks whether it matches what is running.

A valid signature alone can still give `INCOMPLETE` when the values to compare are missing. A missing trusted key gives `UNVERIFIABLE`. Accept only the results your application's rules explicitly allow.

## Keep private keys out of output

The demo keeps its private (signing) key only in memory and saves the public key for later checks. For signing keys you keep, use your organisation's approved secret store. Never print private key material into terminal history, build output or logs.

## Next steps

Use the [revocation tutorial](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md) to reject an issued manifest, the [integration gate](https://manifest.agentrust-io.com/integrations/#run-a-local-verification-gate) to test application behavior, or [HITL workflows](https://manifest.agentrust-io.com/tutorials/hitl-approval-workflows/index.md) for approval-specific requirements.
