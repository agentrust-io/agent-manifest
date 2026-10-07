# Audit log management

An audit log is the running record of what an agent decided and did. This guide is for teams who keep that record: where to store it, how long to keep it, how to search it, and how to publish proof of it to a public transparency log (a public, append-only log that anyone can check).

A manifest can capture a fingerprint of the audit log as it stood when the manifest was signed; the log entries themselves are stored elsewhere. Whoever produces the log defines its format, and whoever relies on it has to check that fingerprint and the evidence behind it.

---

## What the audit chain contains

The entries are linked so that changing an old one changes the fingerprint of the whole log. Each entry appended to the audit chain is a leaf in a Merkle tree (a structure that combines many hashes into a single root hash). The `audit_chain_root` in `artifacts.decision_trace` commits the agent to the state of the chain at manifest issuance.

The following is an illustrative, application-defined entry, not an SDK schema. Its identifiers and hashes are abbreviated, and the attestation level is only a declaration:

```json
{
  "entry_id": "uuid-v7",
  "timestamp": "2026-06-05T09:15:00Z",
  "agent_id": "spiffe://trust.acme.co/agent/payment-processor/prod",
  "manifest_id": "019236ab-...",
  "action": "execute_payment",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "attestation_level": 2
}
```

The chain root advances after each append. An inclusion proof can establish that an entry belongs to a particular authenticated tree root without exposing the other entries. It does not independently establish when the event occurred or whether the event description is true.

---

## Storage options

Where you keep the log depends on volume, how long you must keep it, and how you need to search it.

| Option | Best for | Retention | Query capability |
|--------|---------|-----------|-----------------|
| Append-only file (`audit.jsonl`) | Development | Short-term | `grep`, `jq` |
| Object storage (S3/GCS) + Athena | High-volume production | Long-term | SQL |
| TimescaleDB | Time-series queries | Long-term | Time-range, agent_id |
| Loki | Observability-integrated | Configurable | LogQL |
| Rekor (public transparency log) | Immutability audit | Permanent | Rekor query API |

Choose storage controls for the applicable retention and access requirements. Object versioning can help recover overwritten data but does not, by itself, establish immutable retention. Review the data you would disclose before using any public transparency log.

---

## Retention policy

How long to keep records is a legal and privacy decision for your organization, not something this project sets. Define retention by record category, jurisdiction, contract, and the purpose for which the data was collected. Agent Manifest does not prescribe a universal retention period or certify that an audit store meets those obligations.

Document the applicable retention and deletion rules with the responsible legal and privacy owners. Separate private payloads from shareable commitments; publishing a hash or record to a public log can make later deletion impractical. Configure access controls, backups, holds, and deletion verification for each storage system, then test those procedures.

---

## Querying the audit log

### By agent_id

```python
import json
from pathlib import Path
from datetime import datetime, timezone

def query_by_agent(log_path: Path, agent_id: str, since: datetime):
    entries = []
    for line in log_path.read_text().splitlines():
        entry = json.loads(line)
        ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        if entry["agent_id"] == agent_id and ts >= since:
            entries.append(entry)
    return entries
```

### Find records declaring Level 0 access to PII

```python
def find_unattested_pii_access(log_path: Path):
    for line in log_path.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("attestation_level") == 0 and \
           "pii" in entry.get("data_classifications", []):
            yield entry
```

### SQL on a PostgreSQL-compatible store

Adapt these queries to your stored schema. The illustrative JSON above does not include `verification_result`; record that field explicitly if you want verdict queries.

```sql
-- All actions by a specific agent in the last 24 hours
SELECT * FROM audit_log
WHERE agent_id = 'spiffe://trust.acme.co/agent/payment-processor/prod'
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Count recorded non-VALID verdicts per agent per hour
SELECT
  date_trunc('hour', timestamp) AS hour,
  agent_id,
  COUNT(*) AS invalid_count
FROM audit_log
WHERE verification_result <> 'VALID'
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC;
```

---

## Transparency evidence

Publishing to a transparency log lets outsiders confirm a record existed without seeing your private log. Keep the private audit store and public transparency evidence separate. An audit entry, a signed tree root, a manifest signature, and a log receipt are distinct objects with different verification steps.

??? info "Technical detail: publishing to Rekor and verifying inclusion"

    To publish a commitment, define the exact bytes and their digest, sign those bytes with the intended key, and use the log's supported entry format. Supply a real signature and the corresponding public key or certificate; base64-encoding a payload does not create a signature. A signature on the manifest's signing preimage is not automatically a signature on a separately serialized audit-root object.

    Use maintained Sigstore tooling and its [Rekor documentation](https://docs.sigstore.dev/logging/overview/) for publication and verification. Review the data disclosed before publishing. This guide does not submit anything to a public log.

    Retrieving an entry and comparing its digest is a content lookup, not inclusion-proof verification. The recipient must authenticate the relevant signed log evidence, verify the proof against an accepted checkpoint/root, and confirm that the verified entry commits to the expected signed object. Apply the log's trust, freshness, and consistency policy; an entry identifier alone establishes none of these properties.

Only after independently appraising transparency evidence should the application supply verified entry IDs or receipt hashes to `VerificationContext`, bound to the exact manifest ID. See [server-side verification](../tutorials/server-side-verification.md#add-revocation-and-evidence-appraisal).

## Interpret audit signals

Some patterns in the log are worth a closer look. None of them proves tampering on its own.

| Signal | What to investigate |
|--------|---------------------|
| Expected activity has no corresponding entries | Compare workload expectations with collection and delivery health; an idle agent can legitimately produce no events. |
| A record declares a lower attestation level than policy requires | Appraise the underlying evidence and policy; the declared integer alone is not a hardware verdict. |
| A current root differs from the root signed at issuance | Check whether the log advanced legitimately and whether the required continuity evidence is available. A difference alone does not prove tampering. |
| Entries cannot be authenticated or consistency cannot be established | Reject the evidence for decisions that require those properties, retain diagnostics, and investigate the cause. |

The SDK can report `EXTENDED` for a decision trace when the current root differs and the required continuity evidence verifies. Configure the recipient's current root and continuity inputs; do not suppress mismatches or assume every new root is acceptable. See the [verification API](../api-reference/verification.md).

Use the [monitoring guide](monitoring.md) to distinguish rejected evidence from unexpected verifier failures.
