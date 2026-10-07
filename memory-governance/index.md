# Agent Memory Governance

Many agents keep a memory: notes and facts they carry from one task or conversation to the next. This page explains how Agent Manifest decides whether that memory is still the one someone approved. It is for people deploying long-running agents and for reviewers who need to know what a memory check does and does not tell them.

The test is simple. Memory is "good" when it is exactly the approved copy and has not passed its expiry time. It is "bad" when it has changed since approval (drifted, whether through tampering or unreviewed learning) or has expired. The check says nothing about whether the memory is useful or correct, only whether it is unchanged and current.

The rules come from **Section 3.2.6 (Memory Baseline Binding)** of the Agent Manifest spec:

## 1. The Approved State (`snapshot_hash`)

The `snapshot_hash` is a fingerprint of the approved memory. Any change to the memory, however small, gives a different fingerprint.

Technical detail: how the fingerprint is computed

The `snapshot_hash` is the SHA-256 (or SHAKE-256) hash of the RFC 8785 canonical JSON serialization of the memory store's key-value map. Canonical JSON writes the same data in exactly one byte order, so two copies of the same memory always hash the same.

- If the running agent's memory matches this hash, the memory is valid.
- If it deviates, a "drift" has occurred, and the memory is considered unapproved.

## 2. The Penalty for Bad Memory (`drift_policy`)

If the memory no longer matches its `snapshot_hash`, the `drift_policy` setting decides what happens next:

- **`deny-on-drift`**: The strictest policy (required for Level 2 compliance). If memory changes without re-approval, all tool calls are rejected, a `MEMORY_DRIFT_DETECTED` event is fired, and operator acknowledgment is required.
- **`alert-on-drift`**: The agent continues to operate, but an alert is surfaced in every verification result.
- **`log-only`**: Only records the drift in the audit log (permitted only at Level 0 and 1).

## 3. Freshness and Expiration (`ttl_seconds`)

Even unchanged memory stops being valid once its time-to-live runs out, so someone has to look at it and approve it again. The manifest requires a `ttl_seconds` field for persistent memory:

- **Minimum**: 3,600 seconds (1 hour)
- **Maximum**: 7,776,000 seconds (90 days) This forces regular re-approval, so a long-running agent cannot slowly pile up unreviewed memory changes that quietly alter how it behaves.

## 4. Memory Types (`memory_type`)

The rules differ by how long the memory lives and who shares it:

- **`session`**: Memory scoped to a single conversation. Checked against the baseline at startup, but exempt from drift detection while the session is active.
- **`persistent`**: Memory persisting across sessions. The `snapshot_hash` represents the last approved checkpoint, and drift checks are continuously enforced.
- **`shared`**: Memory shared across multiple instances of the same agent. A designated "owner" agent holds the authoritative `snapshot_hash`, which all other instances reference.

## Future Outlook: Stateful Checkpoints (v0.2 Roadmap)

In the v0.1 spec, memory is a fixed approved copy. An agent that learns something new therefore falls out of step with its manifest. The **Memory baseline checkpoint protocol** planned for **v0.2** aims to let an agent record small approved changes (deltas) as it goes, without re-fingerprinting and re-approving the whole memory each time.
