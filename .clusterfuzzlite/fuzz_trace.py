#!/usr/bin/python3
"""Fuzz TRACE envelope and evidence pack appraisal.

verify_trace_envelope() and verify_evidence_pack() take JSON documents from
whoever presents the evidence and return a status. Neither documents an
exception: a caller reads `.status`, so anything raised on untrusted input is a
crash in the caller. Python's json module also accepts NaN and Infinity, which
RFC 8785 cannot represent, so those reach the canonicalizer too.

Two modes. The first feeds an arbitrary JSON document. The second overlays a
fuzzed JSON object on a correctly signed pack, so the fuzzer starts past the
structural checks and reaches the signature, embedded-result and envelope code.

Properties checked beyond "does not raise":
  * the status is a TraceStatus;
  * a VERIFIED pack verified its outer signature, has no failures, and carries
    an embedded result that says VALID for the pack's own manifest.
"""
import copy
import json
import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agent_manifest._signing import Ed25519KeyPair, _b64url_encode
    from agent_manifest._trace import (
        TraceStatus,
        evidence_pack_pre_image,
        trace_signing_pre_image,
        verify_evidence_pack,
        verify_trace_envelope,
    )

# Fixed, published test key: this target signs its own seed pack and nothing else.
_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_KP = Ed25519KeyPair(private_key=_PRIV, public_key=_PRIV.public_key())
_TRUSTED = {_KP.key_id: _KP.public_b64url()}
_MANIFEST_ID = "0192f3a0-0000-7000-8000-000000000001"


def _seed_pack() -> dict:
    envelope = {
        "trace_id": "0192f3a0-0000-7000-8000-00000000000a",
        "agent_id": "spiffe://example.org/agent/billing",
        "agent_manifest_id": _MANIFEST_ID,
        "manifest_verification_result": "VALID",
        "tool_id": "org.example.tools.invoice-lookup",
        "policy_hash": "sha256:" + "a1" * 32,
        "catalog_hash": "sha256:" + "b2" * 32,
        "decision": "allow",
        "decision_reason": "permit",
        "payload_classification": "internal",
        "egress_destination": "api.example.com",
        "hitl_required": False,
        "hitl_approval_id": None,
        "timestamp": "2026-08-03T12:00:00Z",
        "tee_measurement": "sha256:" + "cd" * 32,
        "signature": "",
    }
    envelope["signature"] = _b64url_encode(_PRIV.sign(trace_signing_pre_image(envelope)))
    pack = {
        "manifest": {
            "manifest_id": _MANIFEST_ID,
            "artifacts": {"policy_bundle": {"hash": "sha256:" + "a1" * 32}},
        },
        "verification_result": {"result": "VALID", "manifest_id": _MANIFEST_ID},
        "trace_envelopes": [envelope],
        "attestation_report": _b64url_encode(b"raw-attestation-bytes"),
    }
    pack["pack_signature"] = {
        "algorithm": "Ed25519",
        "key_id": _KP.key_id,
        "signature_value": _b64url_encode(_PRIV.sign(evidence_pack_pre_image(pack))),
    }
    return pack


_SEED = _seed_pack()


def _check_pack(result, pack) -> None:
    assert isinstance(result.status, TraceStatus), result.status
    if result.status is TraceStatus.VERIFIED:
        assert result.signature_verified, "VERIFIED without an outer signature"
        assert not result.failures, result.failures
        embedded = pack["verification_result"]
        assert embedded["result"] == "VALID", embedded
        assert embedded["manifest_id"] == pack["manifest"]["manifest_id"], embedded


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    raw = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        return

    if mode == 0:
        _check_pack(verify_evidence_pack(doc, trusted_keys=_TRUSTED), doc)
    elif mode == 1:
        result = verify_trace_envelope(doc, trusted_keys=_TRUSTED)
        assert isinstance(result.status, TraceStatus), result.status
    else:
        if not isinstance(doc, dict):
            return
        pack = copy.deepcopy(_SEED)
        for key, value in doc.items():
            # Overlay one level down when the key names a pack member that is
            # itself an object, so single fields inside it get replaced.
            target = pack.get(key)
            if isinstance(target, dict) and isinstance(value, dict):
                target.update(value)
            else:
                pack[key] = value
        result = verify_evidence_pack(
            pack,
            trusted_keys=_TRUSTED,
            trace_key_id=_KP.key_id,
            result_key_id=_KP.key_id if len(raw) % 2 else None,
        )
        _check_pack(result, pack)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
