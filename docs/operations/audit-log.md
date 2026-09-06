# Audit log management

A manifest can commit to an audit-chain state; the actual entries are stored separately. The producer must define the chain format, and recipients must authenticate the root and verify the corresponding evidence. This guide covers storing, retaining, querying, and submitting audit entries to a public transparency log.

---

## What the audit chain contains

Each entry appended to the audit chain is a leaf in a Merkle tree. The `audit_chain_root` in `artifacts.decision_trace` commits the agent to the state of the chain at manifest issuance.

A typical audit entry contains:

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

The chain root advances after each append. A verifier can prove any entry was recorded before a given root using a Merkle inclusion proof  -  without reading any other entries.

---

## Storage options

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

Define retention by record category, jurisdiction, contract, and the purpose for which the data was collected. Agent Manifest does not prescribe a universal retention period or certify that an audit store meets those obligations.

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

### By attestation level (find Level 0 agents accessing sensitive data)

```python
def find_unattested_pii_access(log_path: Path):
    for line in log_path.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("attestation_level", 0) == 0 and \
           "pii" in entry.get("data_classifications", []):
            yield entry
```

### SQL on Athena / TimescaleDB

```sql
-- All actions by a specific agent in the last 24 hours
SELECT * FROM audit_log
WHERE agent_id = 'spiffe://trust.acme.co/agent/payment-processor/prod'
  AND timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Count INVALID results per agent per hour
SELECT
  date_trunc('hour', timestamp) AS hour,
  agent_id,
  COUNT(*) AS invalid_count
FROM audit_log
WHERE verification_result = 'INVALID'
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC;
```

---

## Submitting to Rekor

Rekor is a public transparency log for software supply chain artefacts. Submitting the audit chain root to Rekor creates a permanent, publicly auditable record that the root existed at a specific time.

```python
import httpx
import base64
import json

REKOR_URL = "https://rekor.sigstore.dev"

def submit_to_rekor(audit_chain_root: str, manifest_id: str, signed_manifest: dict) -> str:
    """Submit the audit chain root to Rekor. Returns the entry UUID."""
    payload = json.dumps({
        "manifest_id": manifest_id,
        "audit_chain_root": audit_chain_root,
    }).encode()

    entry = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": audit_chain_root.removeprefix("sha256:"),
                }
            },
            "signature": {
                "content": base64.b64encode(payload).decode(),
                "publicKey": {
                    "content": base64.b64encode(
                        signed_manifest["signature"]["signature_value"].encode()
                    ).decode()
                }
            }
        }
    }

    response = httpx.post(f"{REKOR_URL}/api/v1/log/entries", json=entry)
    response.raise_for_status()
    uuid = list(response.json().keys())[0]
    return uuid
```

### Verifying inclusion proofs

```python
def verify_rekor_inclusion(entry_uuid: str, audit_chain_root: str) -> bool:
    """Confirm the audit chain root is in the Rekor log."""
    response = httpx.get(f"{REKOR_URL}/api/v1/log/entries/{entry_uuid}")
    response.raise_for_status()
    entry = list(response.json().values())[0]
    body = json.loads(base64.b64decode(entry["body"]))
    return body["spec"]["data"]["hash"]["value"] == audit_chain_root.removeprefix("sha256:")
```

---

## Alert conditions

| Condition | Signal | Response |
|-----------|--------|----------|
| No entries from a known agent for > 1 hour | Agent may be down or bypassing audit | Page on-call |
| Entry with `attestation_level=0` for a Level 2+ manifest | Attestation downgrade | Immediate investigation |
| Merkle root mismatch between audit log and manifest | Tampered audit log | Incident response |
| Entry volume drops to zero | Audit pipeline failure | Page on-call |

See [Monitoring guide](monitoring.md) for the full alerting setup.
