# Proposal: rollback detection for the local SQLite revocation store

Status: informative design draft following #525. No SDK, wire format or trust
policy changes are implemented here. The current authenticated store validates
present signed history; an old authentic database can still contain valid signatures.

## Threat and trust boundary

Assume an attacker can replace or delete the SQLite database and all adjacent
files. A digest, counter or checkpoint stored beside that database is therefore
insufficient. Detection needs an independently protected freshness anchor, whose
availability and recovery policy must be specified by the deployment owner.

The proposal is an optional verifier wrapper, not a claim that SQLite supplies
rollback protection. Preserve existing signed record and HTTP response formats.
Do not call a failed or uncertain read `not revoked`.

## Candidate anchor contract for discussion

An authenticated anchor would bind a store identity, committed generation and
commitment to the complete ordered history. The exact commitment encoding and
anchoring service are undecided. Store identity prevents substituting another
valid database; generation alone does not authenticate contents. A linear read
of authenticated records remains necessary unless another reviewed proof replaces it.

At read time, missing/unavailable/invalid anchor, an older database generation,
commitment mismatch or a different store identity produces an unavailable result,
not a negative revocation lookup. A database ahead of the anchor is also unresolved:
its commit may be legitimate, but advancing the anchor cannot be inferred by a reader.

## Crash-safe write choices to decide

There is no atomic transaction spanning arbitrary SQLite and external storage.
A candidate design stages a signed update locally, advances an external anchor
with compare-and-swap against the prior generation, then marks the local commit
complete. Every crash boundary needs an explicit recovery record and authenticated
reconciliation. No reader silently advances, resets or recreates an anchor.
A backup restore requires an operator-approved recovery path; availability loss
is preferable to reporting a stale store as current.

## Required decisions before implementation

- Choose the independently protected anchor and its authorization/availability model.
- Specify canonical commitment bytes, ordering, store identity and key rotation.
- Define compare-and-swap, multi-writer serialization and the crash recovery protocol.
- Define bootstrap and disaster recovery without an automatic trust reset.
- Decide whether callers can opt out, and how reduced assurance is exposed.

## Future acceptance evidence

Start with an independently pinned synthetic anchor and a valid signed history.
Test an older valid snapshot, removal of the latest entry, cross-store substitution,
anchor rollback, unavailable anchor, concurrent writers and crashes at each write
boundary. A valid latest snapshot succeeds. Every rejection has an independent
guard-removal control. These software tests do not establish a hardware counter,
remote service reliability, power-loss durability or production acceptance.
