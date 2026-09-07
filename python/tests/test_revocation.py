"""Tests for _revocation: signed revocation records, file-backed CRL, FastAPI router.

Strategy:
  sign_revocation / verify_revocation_signature — cryptographic correctness:
    round-trip, tampered manifest ID, tampered reason, wrong key.
  FileCRL — file persistence: revoke, reload-from-disk, double-revoke, list, 404.
  create_crl_router — HTTP contract via FastAPI TestClient:
    list (empty and populated), get-found, get-404, signature fields present.
  No hardware or network required.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from agent_manifest._revocation import (
    CRLIntegrityError,
    FileCRL,
    SignedRevocationRecord,
    create_crl_router,
    sign_revocation,
    verify_revocation_signature,
)
from agent_manifest._signing import generate_ed25519

MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
MID2 = "018aaaaa-2c1d-7e5f-a8b9-0d1e2f3a4b5c"


# ---------------------------------------------------------------------------
# sign_revocation / verify_revocation_signature
# ---------------------------------------------------------------------------


def test_sign_revocation_returns_record():
    kp = generate_ed25519()
    rec = sign_revocation(MID, "key compromise", "security@example.com", kp)
    assert rec.manifest_id == MID
    assert rec.reason == "key compromise"
    assert rec.revoked_by == "security@example.com"
    assert rec.revocation_signature is not None
    assert rec.signer_key_id == kp.key_id


def test_sign_revocation_sets_revoked_at():
    kp = generate_ed25519()
    before = datetime.now(timezone.utc)
    rec = sign_revocation(MID, "test", "admin", kp)
    after = datetime.now(timezone.utc)
    assert before <= rec.revoked_at <= after


def test_sign_revocation_roundtrip_verifies():
    kp = generate_ed25519()
    rec = sign_revocation(MID, "policy violation", "admin@example.com", kp)
    verify_revocation_signature(rec, kp.public_bytes)  # must not raise


def test_verify_revocation_wrong_key_fails():
    kp1 = generate_ed25519()
    kp2 = generate_ed25519()
    rec = sign_revocation(MID, "test", "admin", kp1)
    with pytest.raises(InvalidSignature):
        verify_revocation_signature(rec, kp2.public_bytes)


def test_verify_revocation_tampered_manifest_id_fails():
    kp = generate_ed25519()
    rec = sign_revocation(MID, "test", "admin", kp)
    tampered = rec.model_copy(update={"manifest_id": MID2})
    with pytest.raises(InvalidSignature):
        verify_revocation_signature(tampered, kp.public_bytes)


def test_verify_revocation_tampered_reason_fails():
    kp = generate_ed25519()
    rec = sign_revocation(MID, "original reason", "admin", kp)
    tampered = rec.model_copy(update={"reason": "tampered reason"})
    with pytest.raises(InvalidSignature):
        verify_revocation_signature(tampered, kp.public_bytes)


def test_verify_revocation_tampered_revoked_by_fails():
    kp = generate_ed25519()
    rec = sign_revocation(MID, "test", "admin@example.com", kp)
    tampered = rec.model_copy(update={"revoked_by": "attacker@evil.com"})
    with pytest.raises(InvalidSignature):
        verify_revocation_signature(tampered, kp.public_bytes)


def test_verify_revocation_no_signature_fails():
    kp = generate_ed25519()
    rec = SignedRevocationRecord(
        manifest_id=MID,
        revoked_at=datetime.now(timezone.utc),
        reason="test",
        revoked_by="admin",
        revocation_signature=None,
    )
    with pytest.raises(Exception):
        verify_revocation_signature(rec, kp.public_bytes)


# ---------------------------------------------------------------------------
# FileCRL
# ---------------------------------------------------------------------------


def test_file_crl_empty_on_new_file(tmp_path):
    crl = FileCRL(tmp_path / "crl.jsonl")
    assert crl.all_records() == []
    assert not crl.is_revoked(MID)
    assert crl.get_record(MID) is None


def test_file_crl_handles_nonexistent_path(tmp_path):
    crl = FileCRL(tmp_path / "does_not_exist.jsonl")
    assert crl.all_records() == []
    assert not crl.is_revoked(MID)


def test_file_crl_revoke_and_is_revoked(tmp_path):
    kp = generate_ed25519()
    crl = FileCRL(tmp_path / "crl.jsonl")
    rec = sign_revocation(MID, "test", "admin", kp)
    crl.revoke(rec)
    assert crl.is_revoked(MID)
    assert not crl.is_revoked(MID2)


def test_file_crl_get_record(tmp_path):
    kp = generate_ed25519()
    crl = FileCRL(tmp_path / "crl.jsonl")
    rec = sign_revocation(MID, "reason", "admin@example.com", kp)
    crl.revoke(rec)
    got = crl.get_record(MID)
    assert got is not None
    assert got.manifest_id == MID
    assert got.reason == "reason"
    assert got.revoked_by == "admin@example.com"


def test_file_crl_all_records(tmp_path):
    kp = generate_ed25519()
    crl = FileCRL(tmp_path / "crl.jsonl")
    crl.revoke(sign_revocation(MID, "r1", "admin", kp))
    crl.revoke(sign_revocation(MID2, "r2", "admin", kp))
    recs = crl.all_records()
    assert len(recs) == 2
    ids = {r.manifest_id for r in recs}
    assert ids == {MID, MID2}


def test_file_crl_persists_to_disk(tmp_path):
    kp = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl1 = FileCRL(path)
    crl1.revoke(sign_revocation(MID, "disk test", "admin", kp))

    crl2 = FileCRL(path)
    assert crl2.is_revoked(MID)
    got = crl2.get_record(MID)
    assert got is not None
    assert got.reason == "disk test"


def test_file_crl_reload_multiple_records(tmp_path):
    kp = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl1 = FileCRL(path)
    crl1.revoke(sign_revocation(MID, "r1", "admin", kp))
    crl1.revoke(sign_revocation(MID2, "r2", "admin", kp))

    crl2 = FileCRL(path)
    assert len(crl2.all_records()) == 2
    assert crl2.is_revoked(MID)
    assert crl2.is_revoked(MID2)


def test_file_crl_double_revoke_overwrites_in_memory(tmp_path):
    kp = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path)
    crl.revoke(sign_revocation(MID, "first reason", "admin", kp))
    crl.revoke(sign_revocation(MID, "second reason", "admin", kp))
    assert crl.get_record(MID).reason == "second reason"
    assert len(crl.all_records()) == 1


def test_file_crl_signature_survives_roundtrip(tmp_path):
    kp = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl1 = FileCRL(path)
    rec = sign_revocation(MID, "sig test", "admin", kp)
    crl1.revoke(rec)

    crl2 = FileCRL(path)
    loaded = crl2.get_record(MID)
    assert loaded is not None
    verify_revocation_signature(loaded, kp.public_bytes)  # must not raise


def test_file_crl_rejects_untrusted_record_before_append(tmp_path):
    trusted = generate_ed25519()
    untrusted = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path, trusted_signer_key=trusted.public_bytes)

    with pytest.raises(InvalidSignature):
        crl.revoke(sign_revocation(MID, "untrusted", "attacker", untrusted))

    assert not crl.is_revoked(MID)
    assert not path.exists()


def test_revocation_rejects_mismatched_signer_key_id(tmp_path):
    trusted = generate_ed25519()
    record = sign_revocation(MID, "test", "admin", trusted).model_copy(
        update={"signer_key_id": "sha256:" + "0" * 64}
    )
    crl = FileCRL(tmp_path / "crl.jsonl", trusted_signer_key=trusted.public_bytes)

    with pytest.raises(InvalidSignature):
        crl.revoke(record)

    assert not crl.is_revoked(MID)


def test_file_crl_authenticated_load_fails_closed_on_tampered_record(tmp_path):
    # CRL-CLI-002 regression: a tampered record in an authenticated CRL must
    # raise, not be silently dropped so is_revoked() reports False.
    authority = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path, trusted_signer_key=authority.public_bytes)
    crl.revoke(sign_revocation(MID, "key compromise", "admin", authority))

    line = json.loads(path.read_text().splitlines()[0])
    sig = list(line["revocation_signature"])
    mid_idx = len(sig) // 2
    sig[mid_idx] = "A" if sig[mid_idx] != "A" else "B"
    line["revocation_signature"] = "".join(sig)
    path.write_text(json.dumps(line) + "\n")

    with pytest.raises(CRLIntegrityError):
        FileCRL(path, trusted_signer_key=authority.public_bytes)


def test_file_crl_authenticated_load_fails_closed_on_wrong_key(tmp_path):
    real_authority = generate_ed25519()
    untrusted_authority = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path, trusted_signer_key=untrusted_authority.public_bytes)
    crl.revoke(sign_revocation(MID, "test", "admin", untrusted_authority))

    with pytest.raises(CRLIntegrityError):
        FileCRL(path, trusted_signer_key=real_authority.public_bytes)


def test_file_crl_authenticated_load_fails_closed_on_malformed_line(tmp_path):
    authority = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    path.write_text("not valid json at all\n")

    with pytest.raises(CRLIntegrityError):
        FileCRL(path, trusted_signer_key=authority.public_bytes)


def test_file_crl_authenticated_load_one_bad_record_poisons_whole_file(tmp_path):
    # A single tampered/unverifiable line must invalidate the whole load,
    # not just be excluded otherwise attacker can tamper with the one
    # record they want suppressed while leaving others intact and still get
    # a (partially) trusted result.
    authority = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path, trusted_signer_key=authority.public_bytes)
    crl.revoke(sign_revocation(MID, "good record", "admin", authority))

    with open(path, "a") as f:
        f.write("garbage-not-json\n")

    with pytest.raises(CRLIntegrityError):
        FileCRL(path, trusted_signer_key=authority.public_bytes)


def test_file_crl_unauthenticated_load_still_skips_malformed_lines(tmp_path):
    # Backward-compatible dev-mode behavior (no trusted key) is unchanged:
    # malformed lines are best-effort skipped rather than raising.
    path = tmp_path / "crl.jsonl"
    kp = generate_ed25519()
    crl = FileCRL(path)
    crl.revoke(sign_revocation(MID, "test", "admin", kp))
    with open(path, "a") as f:
        f.write("not valid json\n")

    crl2 = FileCRL(path)  # must not raise
    assert crl2.is_revoked(MID)


def test_file_crl_authenticated_deleted_record_still_not_revoked(tmp_path):
    # Documents a known, NOT-fixed limitation: per-record signatures can't
    # detect deletion of a valid line. This pins current behavior so a
    # future change can't silently claim more than it delivers without a
    # test change forcing a conscious decision.
    authority = generate_ed25519()
    path = tmp_path / "crl.jsonl"
    crl = FileCRL(path, trusted_signer_key=authority.public_bytes)
    crl.revoke(sign_revocation(MID, "key compromise", "admin", authority))

    path.write_text("")  # delete the record

    crl2 = FileCRL(path, trusted_signer_key=authority.public_bytes)  # must not raise
    assert not crl2.is_revoked(MID)


def test_file_crl_authenticated_missing_file_same_as_deleted_record(tmp_path):
    # A CRL path that never existed and a CRL file that existed and was then
    # emptied are indistinguishable to FileCRL, even in authenticated mode:
    # __init__ only calls _load() when the path exists, so a missing file
    # never reaches the fail-closed signature-verification path at all and
    # is silently treated as "zero revocations," exactly like the emptied
    # file in test_file_crl_authenticated_deleted_record_still_not_revoked.
    # This pins that the two cases share the same (documented) completeness
    # limitation, so a party who can delete the whole CRL file gets the same
    # silent un-revocation as one who can only blank its contents -
    # CRLIntegrityError is never raised in either case.
    authority = generate_ed25519()
    missing_path = tmp_path / "never_existed.jsonl"
    assert not missing_path.exists()

    crl = FileCRL(missing_path, trusted_signer_key=authority.public_bytes)  # must not raise
    assert crl.all_records() == []
    assert not crl.is_revoked(MID)


# ---------------------------------------------------------------------------
# FastAPI CRL router
# ---------------------------------------------------------------------------

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

require_fastapi = pytest.mark.skipif(
    not FASTAPI_AVAILABLE, reason="fastapi not installed"
)


def _make_client(tmp_path, records=None):
    kp = generate_ed25519()
    crl = FileCRL(tmp_path / "crl.jsonl")
    for mid, reason in (records or []):
        crl.revoke(sign_revocation(mid, reason, "admin", kp))
    app = FastAPI()
    app.include_router(create_crl_router(crl))
    return TestClient(app)


@require_fastapi
def test_crl_list_empty(tmp_path):
    client = _make_client(tmp_path)
    r = client.get("/.well-known/agent-manifest/revocation")
    assert r.status_code == 200
    assert r.json() == []


@require_fastapi
def test_crl_list_returns_all_records(tmp_path):
    client = _make_client(tmp_path, [(MID, "r1"), (MID2, "r2")])
    r = client.get("/.well-known/agent-manifest/revocation")
    assert r.status_code == 200
    ids = {rec["manifest_id"] for rec in r.json()}
    assert ids == {MID, MID2}


@require_fastapi
def test_crl_list_record_has_required_fields(tmp_path):
    client = _make_client(tmp_path, [(MID, "key compromise")])
    r = client.get("/.well-known/agent-manifest/revocation")
    assert r.status_code == 200
    rec = r.json()[0]
    assert "manifest_id" in rec
    assert "reason" in rec
    assert "revoked_at" in rec
    assert "revoked_by" in rec
    assert "revocation_signature" in rec
    assert "signer_key_id" in rec


@require_fastapi
def test_crl_get_record_found(tmp_path):
    client = _make_client(tmp_path, [(MID, "key compromise")])
    r = client.get(f"/.well-known/agent-manifest/revocation/{MID}")
    assert r.status_code == 200
    body = r.json()
    assert body["manifest_id"] == MID
    assert body["reason"] == "key compromise"


@require_fastapi
def test_crl_get_record_not_found(tmp_path):
    client = _make_client(tmp_path)
    r = client.get(f"/.well-known/agent-manifest/revocation/{MID}")
    assert r.status_code == 404
    assert r.json()["detail"]["error_code"] == "NOT_REVOKED"


@require_fastapi
def test_crl_get_record_not_found_message_contains_id(tmp_path):
    client = _make_client(tmp_path)
    r = client.get(f"/.well-known/agent-manifest/revocation/{MID}")
    assert MID in r.json()["detail"]["error_message"]


@require_fastapi
def test_crl_get_one_does_not_match_another(tmp_path):
    client = _make_client(tmp_path, [(MID, "revoked"), (MID2, "also revoked")])
    r = client.get(f"/.well-known/agent-manifest/revocation/{MID}")
    assert r.status_code == 200
    assert r.json()["manifest_id"] == MID
    assert r.json()["manifest_id"] != MID2


@require_fastapi
def test_crl_router_missing_fastapi(monkeypatch):
    import builtins
    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "fastapi":
            raise ImportError("fastapi not installed")
        return original_import(name, *args, **kwargs)

    crl = FileCRL(Path("/tmp/unused.jsonl"))
    monkeypatch.setattr(builtins, "__import__", mock_import)
    with pytest.raises(ImportError, match="FastAPI"):
        create_crl_router(crl)
