"""Durable CRL authentication, atomicity and cross-process visibility."""
import multiprocessing
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_manifest._revocation import (
    CRLIntegrityError,
    create_crl_router,
    sign_revocation,
)
from agent_manifest._signing import generate_ed25519
from agent_manifest._sqlite_revocation import SQLiteCRL

MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"


def _write(path, key, payload):
    from agent_manifest._revocation import SignedRevocationRecord
    SQLiteCRL(path, key).revoke(SignedRevocationRecord.model_validate_json(payload))


@pytest.fixture
def setup(tmp_path):
    key = generate_ed25519()
    path = tmp_path / "crl.sqlite"
    store = SQLiteCRL.initialize(path, key.public_bytes)
    return path, key, store, sign_revocation(MID, "compromised", "admin", key)


def test_concurrent_processes_and_restart(setup):
    path, key, store, record = setup
    records = [record, sign_revocation("other", "retired", "admin", key)]
    processes = [multiprocessing.get_context("spawn").Process(
        target=_write, args=(path, key.public_bytes, r.model_dump_json()),
    ) for r in records]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        if process.is_alive():
            process.terminate()
            process.join()
            pytest.fail("writer timed out")
        assert process.exitcode == 0
    assert {r.manifest_id for r in store.all_records()} == {MID, "other"}
    assert SQLiteCRL(path, key.public_bytes).is_revoked(MID)
    assert store.verifier_store().get_record(MID).reason == "compromised"


def test_idempotence_and_detached_records(setup):
    path, _, store, record = setup
    store.revoke(record)
    store.revoke(record)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT count(*) FROM revocations").fetchone()[0] == 1
    store.get_record(MID).reason = "changed"
    assert store.get_record(MID).reason == "compromised"


@pytest.mark.parametrize("same_time", [False, True])
def test_signed_selection_survives_sequence_swap_and_reverse_import(setup, tmp_path, same_time):
    path, key, store, _ = setup
    # Sign fixed fields using the actual authority, independently of SQLite's
    # sequence allocation. Swapping sequence values must not change selection.
    with patch("agent_manifest._revocation.datetime") as clock:
        clock.now.return_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first = sign_revocation(MID, "a-first", "admin", key)
        clock.now.return_value = datetime(2026, 1, 1 if same_time else 2, tzinfo=timezone.utc)
        selected = sign_revocation(MID, "z-selected", "admin", key)
    store.revoke(first)
    store.revoke(selected)
    assert store.get_record(MID) == selected
    assert store.verifier_store().get_record(MID).reason == "z-selected"
    with closing(sqlite3.connect(path)) as connection, connection:
        # Swap the two primary keys without transient uniqueness collisions.
        connection.execute("UPDATE revocations SET sequence=-sequence")
        connection.execute("UPDATE revocations SET sequence=3+sequence")
    assert SQLiteCRL(path, key.public_bytes).get_record(MID) == selected
    assert store.all_records() == [selected]
    assert store.is_revoked(MID)
    app = FastAPI()
    app.include_router(create_crl_router(store))
    assert TestClient(app).get("/.well-known/agent-manifest/revocation").json() == [
        selected.model_dump(mode="json")]
    other = SQLiteCRL.initialize(tmp_path / "import.sqlite", key.public_bytes)
    source = tmp_path / "reverse.jsonl"
    source.write_text(selected.model_dump_json() + "\n" + first.model_dump_json() + "\n")
    assert other.import_jsonl(source) == 2
    assert other.get_record(MID) == selected


def test_uncommitted_write_rolls_back(setup):
    path, _, store, record = setup
    connection = sqlite3.connect(path)
    connection.execute("INSERT INTO revocations(manifest_id,record) VALUES (?,?)",
                       (MID, record.model_dump_json()))
    assert not store.is_revoked(MID)
    connection.close()
    assert not store.is_revoked(MID)
    store.revoke(record)
    assert store.is_revoked(MID)


def test_missing_database_and_reinitialization(setup):
    path, key, store, _ = setup
    with pytest.raises(FileExistsError):
        SQLiteCRL.initialize(path, key.public_bytes)
    path.unlink()
    with pytest.raises(sqlite3.OperationalError):
        store.is_revoked(MID)
    with pytest.raises(sqlite3.OperationalError):
        SQLiteCRL(path, key.public_bytes)
    assert not path.exists()


@pytest.mark.parametrize("corruption", ["payload", "index", "schema", "file"])
def test_corruption_fails_closed_for_absent_id(setup, corruption):
    path, _, store, record = setup
    store.revoke(record)
    if corruption == "file":
        path.write_bytes(b"not sqlite")
    else:
        with closing(sqlite3.connect(path)) as connection, connection:
            if corruption == "payload":
                connection.execute("UPDATE revocations SET record='{}'")
            elif corruption == "index":
                connection.execute("UPDATE revocations SET manifest_id='another'")
            else:
                connection.execute("DROP TABLE revocations")
    with pytest.raises((CRLIntegrityError, sqlite3.DatabaseError)):
        store.is_revoked("absent")


def test_wrong_signer_and_atomic_import(setup, tmp_path):
    _, _, store, record = setup
    other = sign_revocation("other", "bad", "admin", generate_ed25519())
    with pytest.raises(CRLIntegrityError):
        store.revoke(other)
    source = tmp_path / "crl.jsonl"
    for invalid in [other.model_dump_json(), "{bad"]:
        source.write_text(record.model_dump_json() + "\n" + invalid)
        with pytest.raises(CRLIntegrityError):
            store.import_jsonl(source)
        assert store.all_records() == []
    source.write_text(record.model_dump_json() + "\n")
    assert store.import_jsonl(source) == 1
    assert store.is_revoked(MID)


def test_router_preserves_json_array_and_signature(setup):
    _, _, store, record = setup
    app = FastAPI()
    app.include_router(create_crl_router(store))
    client = TestClient(app)
    route = "/.well-known/agent-manifest/revocation"
    assert client.get(route + "/" + MID).status_code == 404
    store.revoke(record)
    assert client.get(route).json() == [record.model_dump(mode="json")]
    assert client.get(route + "/" + MID).json() == record.model_dump(mode="json")
