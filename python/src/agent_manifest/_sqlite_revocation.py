"""Authenticated SQLite CRL for cooperating processes on one local host."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from ._revocation import (
    _MAX_CRL_BYTES,
    _MAX_CRL_RECORDS,
    CRLIntegrityError,
    SignedRevocationRecord,
    verify_revocation_signature,
)
from ._verify import RevocationRecord, RevocationStore


class SQLiteCRL:
    """Persist signed revocations with fresh reads and atomic commits.

    Initialization is explicit; opening a missing database fails. SQLite errors
    propagate, never becoming a non-revoked result. Signatures authenticate
    present records, not completeness: deletion and database rollback require
    an external inventory/checkpoint. Use local storage, not a network share.
    """

    def __init__(self, path: str | Path, trusted_signer_key: bytes) -> None:
        self._path = Path(path).resolve()
        self._key = trusted_signer_key
        with closing(self._connect()) as connection:
            connection.execute("SELECT manifest_id, record FROM revocations LIMIT 0")

    @classmethod
    def initialize(cls, path: str | Path, trusted_signer_key: bytes) -> SQLiteCRL:
        """Create a new database, refusing to overwrite an existing path."""
        target = Path(path).resolve()
        # Exclusive creation also prevents accidentally initializing a live DB.
        with target.open("xb"):
            pass
        with closing(sqlite3.connect(target)) as connection, connection:
            connection.execute(
                "CREATE TABLE revocations (sequence INTEGER PRIMARY KEY, "
                "manifest_id TEXT NOT NULL, record TEXT NOT NULL UNIQUE)"
            )
            connection.execute(
                "CREATE INDEX revocations_manifest ON revocations(manifest_id, sequence)"
            )
        return cls(target, trusted_signer_key)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _decode(self, manifest_id: str, payload: str) -> SignedRevocationRecord:
        try:
            record = SignedRevocationRecord.model_validate_json(payload)
            verify_revocation_signature(record, self._key)
            if record.manifest_id != manifest_id:
                raise ValueError("record/index manifest mismatch")
            return record
        except Exception as exc:
            raise CRLIntegrityError("Stored revocation failed authentication") from exc

    def revoke(self, record: SignedRevocationRecord) -> None:
        """Commit a signed record; replaying identical content is idempotent."""
        payload = record.model_dump_json()
        checked = self._decode(record.manifest_id, payload)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO revocations(manifest_id, record) VALUES (?, ?) "
                "ON CONFLICT(record) DO NOTHING", (checked.manifest_id, payload),
            )

    def all_records(self) -> list[SignedRevocationRecord]:
        """Authenticate all history and return the last committed record per ID."""
        records: dict[str, SignedRevocationRecord] = {}
        with closing(self._connect()) as connection:
            for manifest_id, payload in connection.execute(
                "SELECT manifest_id, record FROM revocations ORDER BY sequence"
            ):
                records[manifest_id] = self._decode(manifest_id, payload)
        return list(records.values())

    def get_record(self, manifest_id: str) -> SignedRevocationRecord | None:
        # Authenticate the complete inventory, including earlier records, before
        # returning absence. This intentionally favors integrity over throughput.
        return next((r for r in self.all_records() if r.manifest_id == manifest_id), None)

    def is_revoked(self, manifest_id: str) -> bool:
        return self.get_record(manifest_id) is not None

    def import_jsonl(self, path: str | Path) -> int:
        """Validate a bounded JSONL snapshot completely, then import atomically."""
        with Path(path).open("rb") as source:
            data = source.read(_MAX_CRL_BYTES + 1)
        if len(data) > _MAX_CRL_BYTES:
            raise ValueError("CRL exceeds size limit")
        lines = [line for line in data.splitlines() if line.strip()]
        if len(lines) > _MAX_CRL_RECORDS:
            raise ValueError("CRL exceeds record limit")
        records = []
        for line in lines:
            try:
                record = SignedRevocationRecord.model_validate_json(line)
            except Exception as exc:
                raise CRLIntegrityError("Malformed import record") from exc
            records.append(self._decode(record.manifest_id, record.model_dump_json()))
        with closing(self._connect()) as connection, connection:
            for record in records:
                connection.execute(
                    "INSERT INTO revocations(manifest_id, record) VALUES (?, ?) "
                    "ON CONFLICT(record) DO NOTHING",
                    (record.manifest_id, record.model_dump_json()),
                )
        return len(records)

    def verifier_store(self) -> RevocationStore:
        """Return an adapter accepted by verify_manifest and create_router."""
        return _SQLiteVerifierStore(self)


class _SQLiteVerifierStore(RevocationStore):
    def __init__(self, crl: SQLiteCRL) -> None:
        self._crl = crl

    def revoke(self, record: RevocationRecord) -> None:
        raise TypeError("Use SQLiteCRL.revoke with a signed record")

    def is_revoked(self, manifest_id: str) -> bool:
        return self._crl.is_revoked(manifest_id)

    def get_record(self, manifest_id: str) -> RevocationRecord | None:
        record = self._crl.get_record(manifest_id)
        if record is None:
            return None
        return RevocationRecord(
            manifest_id=record.manifest_id, revoked_at=record.revoked_at,
            reason=record.reason, revoked_by=record.revoked_by,
        )
