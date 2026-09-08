# Revocation and Key Rotation

Publish a signed revocation, load it using a separately trusted authority key, and reject the affected manifest. Revocation takes effect when each relying party receives and enforces the update; the SDK does not guarantee a propagation time or stop an already running agent.

## Run a local revocation example

First complete [your first manifest](../getting-started.md). Append the following block to `first_manifest.py` and run `python first_manifest.py` again. It uses that example's signed `record` and independently configured verification `context`.

The temporary directory makes this example repeatable and is removed when the block finishes. In a deployment, store the CRL durably and retain the revocation authority key through your approved key-management system.

```python
from tempfile import TemporaryDirectory
from cryptography.exceptions import InvalidSignature
from agent_manifest import generate_ed25519
from agent_manifest._revocation import FileCRL, sign_revocation
from agent_manifest._verify import RevocationRecord, RevocationStore

revocation_key = generate_ed25519()
# The relying party approves this key separately from the received CRL.
trusted_revoker = revocation_key.public_bytes
revoked_id = record["manifest_id"]

with TemporaryDirectory() as directory:
    crl_path = Path(directory) / "revocations.jsonl"
    writer = FileCRL(crl_path, trusted_signer_key=trusted_revoker)
    cached_reader = FileCRL(crl_path, trusted_signer_key=trusted_revoker)
    revocation = sign_revocation(
        manifest_id=revoked_id,
        reason="synthetic key-compromise exercise",
        revoked_by="spiffe://example.test/security",
        keypair=revocation_key,
    )
    writer.revoke(revocation)
    assert writer.is_revoked(revoked_id)
    # Separate FileCRL instances do not automatically refresh from disk.
    assert not cached_reader.is_revoked(revoked_id)

    reader = FileCRL(crl_path, trusted_signer_key=trusted_revoker)
    store = RevocationStore()
    for entry in reader.all_records():
        store.revoke(RevocationRecord(
            manifest_id=entry.manifest_id,
            revoked_at=entry.revoked_at,
            reason=entry.reason,
            revoked_by=entry.revoked_by,
        ))
    result = verify_manifest(record, context, store)
    assert result.result.value == "REVOKED"
    print("PASS: refreshed revocation state rejects the manifest")

    forged = sign_revocation(
        manifest_id="019236ab-cdef-7000-8000-000000000099",
        reason="untrusted authority",
        revoked_by="spiffe://example.test/stranger",
        keypair=generate_ed25519(),
    )
    try:
        writer.revoke(forged)
    except InvalidSignature:
        print("PASS: untrusted revocation signer rejected")
    else:
        raise RuntimeError("Untrusted revocation was accepted")
```

Expect two additional `PASS` lines. The first proves the refreshed store rejects the revoked ID. The second proves this configured writer rejects a record signed by another key. Neither measures fleet-wide propagation.

## Serve and refresh the CRL

`create_crl_router(crl)` in `agent_manifest._revocation` exposes the supplied `FileCRL` through FastAPI. It serves the object's in-memory cache; appending to the file from another process does not refresh that object. Updates made through that same object's `revoke()` method are visible to its router.

Configure `trusted_signer_key` on every reader and writer. Omitting it disables signature checks. The current file loader skips malformed or invalidly signed entries; it does not establish the completeness or freshness of the list. Your application must detect stale, truncated, unavailable, or unauthenticated revocation data according to its acceptance policy.

Build and replace each verifier's `RevocationStore` from authenticated updates. It is an in-memory store and does not fetch a CRL automatically. Define a refresh interval, maximum accepted age, failure policy, and monitoring for every replica. A response cache header alone does not make a verifier refresh.

When calling `verify_manifest`, supply independently trusted signing keys and required runtime observations through `VerificationContext`. Grant access only for the result your policy accepts; `UNVERIFIABLE`, `INCOMPLETE`, and failures must not fall through to success.

The CLI `manifest revoke` produces an unsigned record. It does not replace the signed-authority workflow above.

## Rotate keys without revoking the replacements

Revocation is indexed by `manifest_id`, not by signature bytes. Re-signing a manifest under a new key with the same ID leaves it subject to that ID's revocation. Reissue replacement manifests with new IDs, current validity windows, approved artifact bindings, and newly bound approvals or evidence where required.

For planned rotation, distribute and verify the new public-key trust configuration before switching issuers. Retire old IDs only after confirming replacement verification and revocation propagation. For compromise, withdraw the compromised authority and revoke affected IDs immediately according to the incident policy; do not deliberately keep accepting a compromised key for a fixed overlap period.

Follow the [key rotation runbook](../operations/key-rotation.md) for the operational sequence. Availability during rotation depends on your deployment and evidence distribution; this tutorial does not guarantee zero downtime.
