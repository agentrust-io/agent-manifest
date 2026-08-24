"""Cross-repository RFC 8785 conformance guard (issue #322).

trace-spec's canonicalization-boundary vectors are signed Trust Records whose
signature verifies only over the RFC 8785 canonical bytes of every field
except ``signature``. They are a black-box check on
``agent_manifest._canonicalize.canonicalize`` from an independent producer:
a non-conformant canonicalizer computes different signing bytes here and the
signature stops verifying, which is exactly the failure issue #322 reported.

The vectors are not vendored in this repository yet -- see
``tests/interop/vectors/canonicalization-boundary/README.md`` for exact fetch
commands. This test skips cleanly with those instructions until the files
are present, and is not required for the rest of the suite to pass.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agent_manifest._canonicalize import canonicalize

_VECTORS_DIR = Path(__file__).parent / "vectors" / "canonicalization-boundary"
_README = _VECTORS_DIR / "README.md"


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _vector_files() -> list[Path]:
    return sorted(_VECTORS_DIR.glob("*.json"))


def test_canonicalize_matches_trace_spec_signature():
    files = _vector_files()
    if not files:
        pytest.skip(f"vectors not vendored yet; see {_README}")

    for path in files:
        vector = json.loads(path.read_text(encoding="utf-8"))
        record = vector["record"]
        jwk = vector["trusted_key"]
        body = {k: v for k, v in record.items() if k != "signature"}

        pre_image = canonicalize(body)
        public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(jwk["x"]))
        signature = _b64url_decode(record["signature"])

        try:
            public_key.verify(signature, pre_image)
        except InvalidSignature:
            pytest.fail(
                f"{path.name}: canonicalize() pre-image does not verify "
                "against trace-spec's own signature over this record"
            )
