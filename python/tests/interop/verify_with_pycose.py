"""Cross-verify the SDK's COSE output with an independent implementation.

The conformance vectors exist so that an implementation the reference SDK did
not write agrees with it. Everything in ``tests/`` verifies the SDK against
itself, which cannot detect a shared misunderstanding of RFC 9052 - if
``_cose.py`` built the ``Sig_structure`` wrongly, its own verifier would
reproduce the same mistake and pass.

This script closes that gap: it hands SDK-built objects to `pycose`, a COSE
library with no relationship to this project, and asks it to parse and verify.

It checks fixtures rather than ``AM-VEC-COSE-001``, and the reason is a real
limitation rather than a convenience. The published vector declares ``alg`` as
``-19`` (ADR-0014), and **no COSE library implements RFC 9864 yet** - pycose
stops at `Unknown COSE attribute with value: -19`, exactly as it stops at
`-49` for ML-DSA-65. The fixtures carry ``-8``, which is the only identifier a
third party can currently verify, over structures built by the same
``Sig_structure`` builders. When a COSE library ships `-19`, these fixtures
should be deleted and this script pointed back at the vector.

It is NOT part of the pytest suite, deliberately. pycose 1.1.0 cannot decode a
COSE message when cbor2 6.x is installed - not even one it encoded itself -
and this SDK depends on cbor2 6.x. Forcing them into one environment would
mean pinning the SDK's serialization to satisfy a test-only dependency, which
is exactly the tail-wagging-the-dog that ADR-0013 rejected.

Run it in its own environment:

    python -m venv /tmp/interop && /tmp/interop/bin/pip install pycose "cbor2<6"
    /tmp/interop/bin/python python/tests/interop/verify_with_pycose.py

Expected output ends with: INTEROP CONFIRMED
"""
from __future__ import annotations

import base64
import json
import pathlib
import sys

from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519
from pycose.messages import Sign1Message, SignMessage

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors"


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _check_sign1() -> bool:
    """A COSE_Sign1 built by the SDK, verified by pycose."""
    fixture_path = pathlib.Path(__file__).parent / "cose_sign1_eddsa.json"
    if not fixture_path.exists():
        print("[COSE_Sign1] fixture missing - run generate_fixtures.py first")
        return False
    vector = json.loads(fixture_path.read_text())

    envelope = bytes.fromhex(vector["envelope_hex"])
    key = OKPKey(crv=Ed25519, x=_b64url(vector["ed25519_public_b64url"]))

    message = Sign1Message.decode(envelope)
    message.key = key

    print("[COSE_Sign1] fixture     : cose_sign1_eddsa.json")
    print(f"[COSE_Sign1] protected   : {message.phdr}")
    print(f"[COSE_Sign1] unprotected : {message.uhdr}")
    print(f"[COSE_Sign1] manifest_id : "
          f"{json.loads(message.payload.decode())['manifest_id']}")

    valid = message.verify_signature()

    def rejects(mutated: bytes) -> bool:
        try:
            other = Sign1Message.decode(mutated)
            other.key = key
            return other.verify_signature() is False
        except Exception:
            return True

    flipped = bytearray(envelope)
    flipped[-1] ^= 0x01
    tampered_sig = rejects(bytes(flipped))
    tampered_payload = rejects(envelope.replace(b'"0.2"', b'"9.9"'))

    print(f"[COSE_Sign1] verifies    : {valid}")
    print(f"[COSE_Sign1] rejects tampered signature/payload: "
          f"{tampered_sig}/{tampered_payload}")
    return valid and tampered_sig and tampered_payload


def _check_sign() -> bool:
    """The COSE_Sign layout: body header, per-signature header, Sig_structure.

    Ed25519 only. A real hybrid envelope cannot be checked this way because no
    COSE library implements ML-DSA-65 (`alg` -49) yet - pycose stops at
    "Unknown COSE attribute with value: -49". What this isolates is everything
    about COSE_Sign that is not algorithm-specific.
    """
    fixture_path = pathlib.Path(__file__).parent / "cose_sign_eddsa.json"
    if not fixture_path.exists():
        print("[COSE_Sign]  fixture missing - run generate_fixtures.py first")
        return False

    fixture = json.loads(fixture_path.read_text())
    envelope = bytes.fromhex(fixture["envelope_hex"])
    key = OKPKey(crv=Ed25519, x=_b64url(fixture["ed25519_public_b64url"]))

    message = SignMessage.decode(envelope)
    message.signers[0].key = key

    print(f"[COSE_Sign]  body header : {message.phdr}")
    print(f"[COSE_Sign]  signers     : {len(message.signers)}")
    print(f"[COSE_Sign]  signer[0]   : {message.signers[0].phdr}")

    valid = message.signers[0].verify_signature()

    def rejects(mutated: bytes) -> bool:
        try:
            other = SignMessage.decode(mutated)
            other.signers[0].key = key
            return other.signers[0].verify_signature() is False
        except Exception:
            return True

    flipped = bytearray(envelope)
    flipped[-1] ^= 0x01
    tampered_sig = rejects(bytes(flipped))
    tampered_payload = rejects(envelope.replace(b'"0.2"', b'"9.9"'))

    print(f"[COSE_Sign]  verifies    : {valid}")
    print(f"[COSE_Sign]  rejects tampered signature/payload: "
          f"{tampered_sig}/{tampered_payload}")
    return valid and tampered_sig and tampered_payload


def main() -> int:
    sign1_ok = _check_sign1()
    print()
    sign_ok = _check_sign()

    ok = sign1_ok and sign_ok
    print("\n" + ("INTEROP CONFIRMED" if ok else "INTEROP FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
