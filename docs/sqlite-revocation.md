# Local persistent revocation storage

`agent_manifest._sqlite_revocation.SQLiteCRL` is an opt-in backend for cooperating
processes on one host using standard-library SQLite. It preserves the signed
record format and JSON-array HTTP response.

```python
from agent_manifest._sqlite_revocation import SQLiteCRL
from agent_manifest._revocation import create_crl_router

# Provision once with the raw public key of the revocation authority.
crl = SQLiteCRL.initialize("revocations.sqlite", trusted_signer_key)
# On subsequent starts, open the existing database. Missing files raise.
crl = SQLiteCRL("revocations.sqlite", trusted_signer_key)
crl.revoke(signed_revocation_record)
router = create_crl_router(crl)
# Pass crl.verifier_store() to verify_manifest/create_router as revocation_store.
```

Writes become visible after commit. Identical records are idempotent. Distinct
records for one manifest are retained; reads return the last committed record,
matching the file backend's last-record convention. There is no un-revoke.
Returned records are detached. The verifier adapter rejects unsigned writes.

Every lookup authenticates all present history, including before returning
absence. This is linear work, suitable for bounded local inventories rather
than high-throughput services. Database errors, five-second lock timeouts and
signature failures propagate; callers should treat them as unavailable
verification, never as `not revoked`.

## Migration

Stop source writes, retain a backup, initialize a new database and call
`crl.import_jsonl("revocations.jsonl")`. The complete input is authenticated
before a single transaction inserts it. Invalid records abort the import.
The 50 MiB/one-million-record limits are preserved. The return value counts
validated input records, including duplicates. Replay does not duplicate
identical stored records. Switch readers only after successful import and an
application smoke test; keep the source backup.

## Limits and recovery

Use local storage with working SQLite locking and durability. Use SQLite's
backup API or a quiesced database copy. Initialization refuses existing paths,
including incomplete initialization left by a crash; inspect and recover that
file rather than silently replacing it.

Signatures cannot detect deleted rows, an empty valid database or rollback to
an older inventory. Completeness requires an independently authenticated
inventory/checkpoint. This does not provide multi-host HA, key rotation,
rollback detection or production deployment acceptance.

From `python/`, run `pytest tests/test_sqlite_revocation.py tests/test_revocation.py`.
Tests cover process visibility, concurrent writes, restart, uncommitted rollback,
replay, detached reads, storage corruption, signature failures, atomic migration
and router compatibility. They do not simulate power loss or storage hardware.
