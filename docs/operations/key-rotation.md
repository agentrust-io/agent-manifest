# Signing Key Rotation Runbook

This runbook is for whoever owns the key that signs your agents' manifests. It walks through replacing that key, either on a schedule or because it may have leaked, so that services keep trusting your new manifests and stop accepting the old ones.

Treat planned rotation and a known compromise differently: a compromised key must not remain trusted just to preserve an overlap window.

## Establish the scope

First, list everything the old key touches. Inventory the signing key, affected manifest IDs, trusted revocation authority, issuer-key mappings (see [Issuer key authorization](issuer-key-authorization.md)), verification replicas, cached revocation state, and dependent evidence or approvals. Record the acceptance and availability criteria for this rollout.

## Prepare replacement manifests

Every service that checks manifests has to learn the new public key before you rely on it. Generate the new key through your approved key-management system. Distribute its public key and issuer authorization through the verifier's trusted configuration channel, and confirm each relying party has received it.

Issue replacements with new `manifest_id` values and current validity windows. Revocation is by manifest ID: re-signing an old ID with a new key does not protect it from that ID's revocation. Rebind approvals, attestation evidence, and other fields tied to the old manifest.

??? info "Technical detail: re-signing a v0.2 envelope"

    Use the supported builder and signing API for the chosen envelope version; a v0.2 COSE envelope is not a JSON dictionary with a replacement signature field.

Verify replacements against independently approved runtime artifacts and keys before deploying them. The [first-manifest example](../getting-started.md) demonstrates the required trust-input separation.

## Revoke affected IDs and refresh verifiers

Next, withdraw the old manifests and make sure every service has heard about it. Use the separately authorized revocation key to sign one record for each affected manifest ID. Publish authenticated revocation state and refresh every relying party's store. The [revocation tutorial](../tutorials/revocation-and-key-rotation.md) provides executable positive and negative checks.

??? info "Technical detail: why each replica needs an explicit refresh"

    `FileCRL` loads into memory at construction. The FastAPI router serves that object's cache; it does not reread the file on every request. A different process appending to disk does not update existing readers. `RevocationStore` also needs explicit refresh. Confirm the new state on each replica rather than assuming a cache header or elapsed interval made it propagate.

For a planned rotation, a bounded overlap is a deployment choice while both keys remain trusted. For a compromise, withdraw the compromised authority and enforce revocations under the incident policy immediately; record any availability impact.

## Confirm completion

- New manifests pass the intended verification policy on every relying party.
- Revoked old IDs fail, including when presented with a different signature.
- Unknown issuer keys, invalid revocation signatures, and stale or unavailable revocation state follow the configured failure policy.
- Logs record key IDs, manifest IDs, results, and rollout state without private key material.

Then retire the old private key using the key-management system's procedure. Retain public verification material and records required for historical evidence.

## Rollback

If planned rotation fails before retirement, roll back only to a key and manifest set still trusted under the incident policy. A compromised key is not a rollback option. Repair replacement issuance or verifier trust distribution and validate again.

Use the [monitoring guide](monitoring.md) for available instrumentation. Propagation time and downtime must be measured in your deployment; this runbook supplies no fixed timing guarantee.
