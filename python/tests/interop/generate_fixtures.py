"""Build the fixtures that ``verify_with_pycose.py`` checks.

Run with the SDK's own environment (cbor2 6.x); the interop script then runs
in a separate one (pycose, cbor2 5.x), because those two cannot coexist.

    python python/tests/interop/generate_fixtures.py

Why fixtures rather than the published vector
---------------------------------------------
Both fixtures declare ``alg`` as ``-8``, and the SDK no longer signs with
``-8`` - ADR-0014 moved production signing to the fully-specified ``-19``.
They are built here through the SDK's own ``Sig_structure`` builders with the
identifier overridden.

That is not a workaround to be cleaned up later; it is the current state of
the ecosystem, and worth stating plainly. **No COSE library implements
RFC 9864 yet.** pycose stops at `Unknown COSE attribute with value: -19`, just
as it stops at `-49` for ML-DSA-65. So the only identifier a third party can
currently verify is the deprecated one.

The structure under test is identical either way: the ``Sig_structure``, the
header encoding, the tag, and the four-element array do not depend on which
code point sits in the ``alg`` slot. Fixing the identifier at ``-8`` is what
keeps an outside opinion available at all, and the moment a COSE library ships
`-19` these fixtures should move to it and be replaced by the vector itself.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import cbor2

from agent_manifest._cose import (
    ALG_EDDSA,
    COSE_SIGN1_TAG,
    COSE_SIGN_TAG,
    HDR_ALG,
    HDR_CONTENT_TYPE,
    HDR_KID,
    HDR_TYP,
    MEDIA_TYPE_MANIFEST_COSE,
    MEDIA_TYPE_MANIFEST_JSON,
    _sig_structure_sign,
    _sig_structure_sign1,
    cose_payload,
)
from agent_manifest._signing import ed25519_from_private_bytes

HERE = pathlib.Path(__file__).parent
# The same fixed seed the conformance vectors use. Ed25519 is deterministic,
# so both fixtures are reproducible byte-for-byte.
SEED = bytes(range(32))

MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod",
    "version": "0.2",
    "issued_at": "2025-01-01T00:00:00Z",
    "expires_at": "2099-12-31T23:59:59Z",
    "issuer": "spiffe://trust.example/signing-authority",
    "crypto_profile": "standard",
}

_NOTE = (
    "alg is -8 because no COSE library implements RFC 9864 (-19) yet. The "
    "structure under test does not depend on the code point. See "
    "generate_fixtures.py."
)


def _write(name: str, envelope: bytes, public: bytes, description: str) -> None:
    (HERE / name).write_text(
        json.dumps(
            {
                "description": description,
                "note": _NOTE,
                "envelope_hex": envelope.hex(),
                "ed25519_public_b64url": base64.urlsafe_b64encode(public)
                .rstrip(b"=")
                .decode(),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {name} ({len(envelope)} envelope bytes)")


def main() -> None:
    keypair = ed25519_from_private_bytes(SEED)
    payload = cose_payload(MANIFEST)
    kid = hashlib.sha256(keypair.public_bytes).digest()

    # COSE_Sign1, through _sig_structure_sign1.
    protected = cbor2.dumps(
        {
            HDR_ALG: ALG_EDDSA,
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_KID: kid,
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )
    signature = keypair.private_key.sign(_sig_structure_sign1(protected, payload))
    _write(
        "cose_sign1_eddsa.json",
        cbor2.dumps(
            cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, payload, signature]),
            canonical=True,
        ),
        keypair.public_bytes,
        "COSE_Sign1 built through _sig_structure_sign1.",
    )

    # COSE_Sign, through _sig_structure_sign. One signer: the SDK emits
    # COSE_Sign only for hybrid, and no third party can appraise ML-DSA-65,
    # so this isolates the parts of the structure that are not
    # algorithm-specific - the body header, the per-signature header, and the
    # five-element Sig_structure that ties them together.
    body_protected = cbor2.dumps(
        {
            HDR_CONTENT_TYPE: MEDIA_TYPE_MANIFEST_JSON,
            HDR_TYP: MEDIA_TYPE_MANIFEST_COSE,
        },
        canonical=True,
    )
    sign_protected = cbor2.dumps({HDR_ALG: ALG_EDDSA, HDR_KID: kid}, canonical=True)
    entry_signature = keypair.private_key.sign(
        _sig_structure_sign(body_protected, sign_protected, payload)
    )
    _write(
        "cose_sign_eddsa.json",
        cbor2.dumps(
            cbor2.CBORTag(
                COSE_SIGN_TAG,
                [
                    body_protected,
                    {},
                    payload,
                    [[sign_protected, {}, entry_signature]],
                ],
            ),
            canonical=True,
        ),
        keypair.public_bytes,
        "COSE_Sign with one Ed25519 signer, built through _sig_structure_sign.",
    )


if __name__ == "__main__":
    main()
