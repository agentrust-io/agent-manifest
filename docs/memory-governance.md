# Agent Memory Governance

In the `agent-manifest` specification, the concept of a "good" versus a "bad" or "weak" memory is strictly defined by **cryptographic integrity, drift, and freshness**, rather than semantic usefulness.

A "good" memory perfectly matches an explicitly approved baseline state and is within its allowed lifespan. A "bad" memory has drifted from its approved state (tampered with or evolved without oversight) or has expired.

According to **Section 3.2.6 (Memory Baseline Binding)** of the Agent Manifest spec, the following constraints govern agent memory state:

## 1. The Approved State (`snapshot_hash`)

The ultimate arbiter of a valid memory is the `snapshot_hash`. This is the SHA-256 (or SHAKE-256) hash of the RFC 8785 canonical JSON serialization of the memory store's key-value map.

- If the running agent's memory matches this hash, the memory is valid.
- If it deviates, a "drift" has occurred, and the memory is considered unapproved.

## 2. The Penalty for Bad Memory (`drift_policy`)

If a memory diverges from its `snapshot_hash`, the `drift_policy` dictates how the system reacts:

- **`deny-on-drift`**: The strictest policy (required for Level 2 compliance). If memory changes without re-approval, all tool calls are rejected, a `MEMORY_DRIFT_DETECTED` event is fired, and operator acknowledgment is required.
- **`alert-on-drift`**: The agent continues to operate, but an alert is surfaced in every verification result.
- **`log-only`**: Only records the drift in the audit log (permitted only at Level 0 and 1).

## 3. Freshness and Expiration (`ttl_seconds`)

A perfectly intact memory becomes invalid if it exceeds its time-to-live. The manifest mandates a `ttl_seconds` field for persistent memory:

- **Minimum**: 3,600 seconds (1 hour)
- **Maximum**: 7,776,000 seconds (90 days)
  This enforces periodic re-approval of the memory state, preventing "alignment drift" where long-running agents slowly accumulate unreviewed memory changes that subtly corrupt behavior.

## 4. Memory Types (`memory_type`)

Governance rules vary depending on the memory type:

- **`session`**: Memory scoped to a single conversation. Checked against the baseline at startup, but exempt from drift detection while the session is active.
- **`persistent`**: Memory persisting across sessions. The `snapshot_hash` represents the last approved checkpoint, and drift checks are continuously enforced.
- **`shared`**: Memory shared across multiple instances of the same agent. A designated "owner" agent holds the authoritative `snapshot_hash`, which all other instances reference.

## Future Outlook: Stateful Checkpoints (v0.2 Roadmap)

In the v0.1 spec, memory is treated as a static baseline. Defining how an agent safely learns new facts during a persistent session without invalidating its manifest is the goal of the **Memory baseline checkpoint protocol** planned for **v0.2**. This will define how incremental memory updates (deltas) are bound and checkpointed without requiring the entire memory store to be re-hashed and re-approved from scratch.
