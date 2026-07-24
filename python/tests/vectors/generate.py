"""Generate the language-neutral Agent Manifest conformance vectors.

The vectors in this directory are a portable contract for the verification
engine (spec Section 5). They are designed so *any* implementation, in any
language, can load a manifest + verification context and assert the same
``VerificationResult`` that the Python reference SDK produces.

Design rules that keep the vectors stable and portable:

* **Fixed signing key.** All signed vectors use one Ed25519 key derived from
  the seed ``00 01 02 ... 1f``. The public key (and key_id) is written to
  ``keys.json`` so other languages can verify signatures without re-running
  this script. Ed25519 is deterministic (RFC 8032), so signatures are
  reproducible byte-for-byte.
* **Time-stable expectations.** Expiry/TTL/HITL windows use absolute dates far
  in the past or far in the future, so a vector's expected result does not
  change with wall-clock time for roughly the next century.
* **Self-contained context.** Each vector carries the full
  ``VerificationContext`` under ``context`` (1:1 with the SDK model), plus
  optional ``revoke: true`` to seed the revocation store before verifying.

Run from the repo's ``python/`` directory:

    python -m tests.vectors.generate

This rewrites the ``AM-VEC-*.json``, ``index.json`` and ``keys.json`` files.
The generated files are committed; regenerate only when the engine's normative
behaviour changes, and review the diff.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from agent_manifest._canonicalize import canonicalize
from agent_manifest._delegation import DelegationHopSigner
from agent_manifest._signing import Ed25519Signer, ed25519_from_private_bytes

HERE = Path(__file__).parent

# Fixed key: seed bytes 00 01 02 ... 1f. Deterministic, never use in production.
SEED = bytes(range(32))
KP = ed25519_from_private_bytes(SEED)

# The public key and key_id are published verbatim. They are public, non-secret
# values, so they are declared here as plain constants rather than derived from
# the keypair at write time — this keeps the (private-key-bearing) KP object out
# of every value that gets serialized to disk. The assertion below guarantees
# the constants stay in lockstep with the fixed seed.
KEY_ID = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
PUBLIC_KEY_B64URL = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
assert (KP.key_id, KP.public_b64url()) == (KEY_ID, PUBLIC_KEY_B64URL), (
    "fixed signing key drifted from the published public key/key_id constants"
)
TRUSTED_KEYS = {KEY_ID: PUBLIC_KEY_B64URL}

# Stable absolute timestamps (never "now").
ISSUED_AT = "2025-01-01T00:00:00Z"
FAR_FUTURE = "2099-12-31T23:59:59Z"
FAR_PAST = "2000-01-01T00:00:00Z"
# ~100 years in seconds: a HITL/memory approval that stays valid for the life
# of these vectors without ever being "approved in the future".
CENTURY_SECONDS = 100 * 365 * 24 * 3600

SP_HASH = "sha256:" + "a" * 64
PB_HASH = "sha256:" + "b" * 64
TRACE_ROOT = "sha256:" + "c" * 64
MEM_HASH = "sha256:" + "d" * 64
RAG_ROOT = "sha256:" + "e" * 64

MANIFEST_ID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
ISSUER = "spiffe://trust.example/signing-authority"


def _sign(manifest: dict[str, Any]) -> dict[str, Any]:
    sig = Ed25519Signer(KP).sign(manifest)
    # signed_at is not part of the signed pre-image; pin it for a stable diff.
    sig["signed_at"] = ISSUED_AT
    manifest["signature"] = sig
    return manifest


def base_manifest(**overrides: Any) -> dict[str, Any]:
    m: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": ISSUED_AT,
        "expires_at": FAR_FUTURE,
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": SP_HASH},
            "policy_bundle": {"hash": PB_HASH},
            "model_identity": {
                "model_hash": None,
                "version": "claude-3",
                "deployment_type": "api",
            },
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    m.update(overrides)
    return _sign(m)


def base_context(**overrides: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "system_prompt_hash": SP_HASH,
        "policy_bundle_hash": PB_HASH,
        "model_version": "claude-3",
        "trusted_keys": dict(TRUSTED_KEYS),
    }
    ctx.update(overrides)
    return ctx


def _vector(
    vid: str,
    description: str,
    spec_refs: list[str],
    manifest: dict[str, Any],
    context: dict[str, Any],
    expected: dict[str, Any],
    *,
    revoke: bool = False,
) -> dict[str, Any]:
    v: dict[str, Any] = {
        "id": vid,
        "description": description,
        "spec_refs": spec_refs,
        "manifest": manifest,
        "context": context,
        "expected": expected,
    }
    if revoke:
        v["revoke"] = True
    return v


def build() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    # 001 - happy path
    vectors.append(_vector(
        "AM-VEC-001", "All bound artifacts match a signed, in-date manifest.",
        ["5.3"], base_manifest(), base_context(),
        {"result": "VALID", "signature_verified": True,
         "fields_verified": {"system_prompt": "MATCH", "policy_bundle": "MATCH",
                             "model_identity": "MATCH", "rag_corpus": "NOT_BOUND"}},
    ))

    # 002 - artifact hash mismatch
    vectors.append(_vector(
        "AM-VEC-002", "Runtime system_prompt hash differs from the bound hash.",
        ["5.3"], base_manifest(),
        base_context(system_prompt_hash="sha256:" + "9" * 64),
        {"result": "MISMATCH", "signature_verified": True,
         "fields_verified": {"system_prompt": "MISMATCH"}},
    ))

    # 003 - expired
    vectors.append(_vector(
        "AM-VEC-003", "Manifest expires_at is in the past.",
        ["5.3"], base_manifest(expires_at=FAR_PAST), base_context(),
        {"result": "EXPIRED"},
    ))

    # 004 - revoked (takes precedence over everything else)
    vectors.append(_vector(
        "AM-VEC-004", "Manifest id is present in the revocation store.",
        ["4.4", "5.3"], base_manifest(), base_context(),
        {"result": "REVOKED"}, revoke=True,
    ))

    # 005 - no signature block at all
    m = base_manifest()
    del m["signature"]
    vectors.append(_vector(
        "AM-VEC-005", "Unsigned manifest must never be VALID (fail-closed).",
        ["5.3"], m, base_context(),
        {"result": "SIGNATURE_MISSING", "signature_verified": False},
    ))

    # 006 - signed but verifier holds no trusted keys
    vectors.append(_vector(
        "AM-VEC-006", "Signed manifest with no trusted keys is UNVERIFIABLE.",
        ["5.3"], base_manifest(), base_context(trusted_keys={}),
        {"result": "UNVERIFIABLE", "signature_verified": False},
    ))

    # 007 - unsupported version
    vectors.append(_vector(
        "AM-VEC-007", "Unsupported manifest version is rejected before verifying.",
        ["2.4"], base_manifest(version="0.2"), base_context(),
        {"result": "INCOMPATIBLE_VERSION"},
    ))

    # 008 - tampered after signing (signature no longer covers the bytes)
    m = base_manifest()
    m["agent_id"] = "spiffe://evil.example/agent/impostor"
    vectors.append(_vector(
        "AM-VEC-008", "agent_id altered after signing invalidates the signature.",
        ["5.3"], m, base_context(),
        {"result": "MISMATCH", "signature_verified": False},
    ))

    # 009 - HITL required + valid approval, enforced
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": ISSUED_AT,
            "approved_scope": {"approval_duration_seconds": CENTURY_SECONDS},
        }],
    })
    vectors.append(_vector(
        "AM-VEC-009", "Required HITL with an unexpired approval passes under enforce_hitl.",
        ["3.2.10", "5.3"], m, base_context(enforce_hitl=True),
        {"result": "VALID", "fields_verified": {"hitl_record": "APPROVED"}},
    ))

    # 010 - HITL enforced but record absent
    vectors.append(_vector(
        "AM-VEC-010", "enforce_hitl with no hitl_record fails closed.",
        ["3.2.10", "5.3"], base_manifest(hitl_record=None),
        base_context(enforce_hitl=True),
        {"result": "MISMATCH", "fields_verified": {"hitl_record": "MISSING"}},
    ))

    # 011 - HITL approval expired
    m = base_manifest(hitl_record={
        "required": True,
        "approvals": [{
            "approved_at": FAR_PAST,
            "approved_scope": {"approval_duration_seconds": 3600},
        }],
    })
    vectors.append(_vector(
        "AM-VEC-011", "Expired HITL approval is surfaced regardless of enforcement.",
        ["3.2.10"], m, base_context(),
        {"result": "MISMATCH", "fields_verified": {"hitl_record": "EXPIRED"}},
    ))

    # 012 - delegation chain present, no keys to verify it
    m = base_manifest(delegation_chain=[{
        "hop": 0,
        "principal_type": "human",
        "principal_id": "did:web:example",
        "delegated_at": ISSUED_AT,
        "scope_grant": {"max_delegation_depth": 3, "ttl_seconds": 3600},
        "delegation_signature": "sig",
    }])
    vectors.append(_vector(
        "AM-VEC-012", "Delegation chain with no public keys is UNVERIFIABLE.",
        ["3.4.1", "5.2"], m, base_context(),
        {"result": "UNVERIFIABLE", "fields_verified": {"delegation_chain": "UNVERIFIABLE"}},
    ))

    # 013 - memory baseline TTL expired
    m = base_manifest()
    m["artifacts"]["memory_baseline"] = {
        "snapshot_hash": MEM_HASH,
        "approved_at": FAR_PAST,
        "ttl_seconds": 3600,  # schema minimum; far-past approval means it is long expired
    }
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-013", "Memory baseline past its TTL is reported EXPIRED.",
        ["3.2.6"], m, base_context(memory_snapshot_hash=MEM_HASH),
        {"result": "VALID", "fields_verified": {"memory_baseline": "EXPIRED"}},
    ))

    # 014 - decision trace matches
    m = base_manifest()
    m["artifacts"]["decision_trace"] = {"audit_chain_root": TRACE_ROOT}
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-014", "Decision-trace audit chain root matches the runtime root.",
        ["3.2.7"], m, base_context(audit_chain_root=TRACE_ROOT),
        {"result": "VALID", "fields_verified": {"decision_trace": "MATCH"}},
    ))

    # 015 - RAG corpus poisoning scan flagged
    m = base_manifest()
    m["artifacts"]["rag_corpus"] = {
        "merkle_root": RAG_ROOT,
        "poisoning_scan": {"result": "flagged"},
    }
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-015", "RAG corpus with a flagged poisoning scan fails verification.",
        ["3.2.5.1"], m, base_context(rag_corpus_merkle_root=RAG_ROOT),
        {"result": "MISMATCH"},
    ))

    # 016 - bound artifact with no runtime hash, under strict verification
    m = base_manifest()
    m["artifacts"]["tool_manifest"] = {"catalog_hash": "sha256:" + "f" * 64}
    _sign(m)
    vectors.append(_vector(
        "AM-VEC-016", "Bound tool_manifest with no runtime hash is INCOMPLETE in strict mode.",
        ["5.3"], m, base_context(strict_artifact_verification=True),
        {"result": "INCOMPLETE", "fields_verified": {"tool_manifest": "NOT_BOUND"}},
    ))

    # 017 - attestation enforced but no attestation block present
    vectors.append(_vector(
        "AM-VEC-017", "enforce_attestation with no attestation block is ATTESTATION_UNAVAILABLE.",
        ["3.3"], base_manifest(), base_context(enforce_attestation=True),
        {"result": "ATTESTATION_UNAVAILABLE", "attestation_verified": False},
    ))

    # 018 - attestation block whose reported hash matches the manifest hash
    m = base_manifest()
    subset = {k: v for k, v in m.items() if k not in ("attestation", "transparency_log_entry")}
    attest_hash = "sha256:" + hashlib.sha256(canonicalize(subset)).hexdigest()
    m["attestation"] = {"platform": "tpm", "manifest_hash_in_report": attest_hash}
    vectors.append(_vector(
        "AM-VEC-018", "Attestation report hash matching the canonical manifest hash verifies.",
        ["3.3"], m, base_context(),
        {"result": "VALID", "attestation_verified": True},
    ))

    # 019 - a fully signed, verifiable single-hop delegation chain.
    # The chain root principal must equal the manifest signing identity (issuer),
    # so a valid chain cannot be grafted onto an unrelated manifest.
    hop_signer = DelegationHopSigner(KP)
    scope_grant = {"max_delegation_depth": 3, "ttl_seconds": 3600}
    hop = {
        "hop": 0,
        "principal_type": "system",
        "principal_id": ISSUER,
        "delegated_at": ISSUED_AT,
        "scope_grant": scope_grant,
    }
    hop["delegation_signature"] = hop_signer.sign_hop(
        hop=0, principal_id=ISSUER, principal_type="system",
        delegated_at=ISSUED_AT, scope_grant=scope_grant, manifest_id=MANIFEST_ID,
    )
    m = base_manifest(delegation_chain=[hop])
    vectors.append(_vector(
        "AM-VEC-019", "Signed single-hop delegation chain bound to the manifest issuer verifies.",
        ["3.4.1", "5.2"], m,
        base_context(delegation_public_keys={ISSUER: PUBLIC_KEY_B64URL}),
        {"result": "VALID", "fields_verified": {"delegation_chain": "VALID"}},
    ))

    return vectors


def main() -> None:
    vectors = build()

    # Only the PUBLIC key is published — verifiers need nothing else. The signing
    # key is the fixed SEED (bytes 00..1f) hardcoded in this script, so the suite
    # stays reproducible without ever writing private key material to disk.
    keys = {
        "algorithm": "Ed25519",
        "note": "Test-only deterministic key (signing seed = bytes 00..1f, see generate.py). Never use in production.",
        "key_id": KEY_ID,
        "public_key_b64url": PUBLIC_KEY_B64URL,
    }
    (HERE / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")

    index = {
        "suite": "agent-manifest-verification",
        "spec_version": "0.1",
        "description": "Language-neutral verification conformance vectors. "
                       "Each vector: a manifest, a VerificationContext, and the "
                       "expected VerificationResult.",
        "signing_key": "keys.json",
        "vectors": [
            {"id": v["id"], "file": f"{v['id']}.json", "description": v["description"]}
            for v in vectors
        ],
    }
    (HERE / "index.json").write_text(json.dumps(index, indent=2) + "\n")

    for v in vectors:
        out = copy.deepcopy(v)
        (HERE / f"{v['id']}.json").write_text(json.dumps(out, indent=2) + "\n")

    print(f"Wrote {len(vectors)} vectors + index.json + keys.json to {HERE}")


if __name__ == "__main__":
    main()
