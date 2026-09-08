#!/usr/bin/python3
"""Fuzz the COSE envelope decoders.

verify_cose_manifest() is the SDK's outermost untrusted entry point: it takes
raw envelope bytes from whoever presents a manifest and, before any signature is
checked, walks CBOR tags, a protected header, a crit list and a JSON payload.
Every one of those is attacker-chosen at that moment.

The property is that the documented contract holds for arbitrary bytes. The
docstring on verify_cose_manifest promises CoseStructureError, CoseVersionError,
CoseDowngradeError and CoseKeyError, all of which are CoseError; a caller writes
`except CoseError` and expects that to be enough. Anything else escaping means
it is not.

Deliberately fuzzed with an empty trusted-keys mapping. That is the documented
"structural checks still run, verified=False" path, which is the one reached
before any cryptographic decision, and so the one an attacker reaches first.
"""
import sys

import atheris

with atheris.instrument_imports():
    from agent_manifest._cose import (
        CoseError,
        attach_receipt,
        decode_cose_manifest,
        read_payload_manifest,
        verify_cose_manifest,
    )

_NO_TRUSTED_KEYS: dict[str, str] = {}


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)
    blob = fdp.ConsumeBytes(fdp.remaining_bytes())

    try:
        if choice == 0:
            verify_cose_manifest(blob, _NO_TRUSTED_KEYS)
        elif choice == 1:
            decode_cose_manifest(blob)
        elif choice == 2:
            read_payload_manifest(blob)
        else:
            attach_receipt(blob, b"\xa0")
    except CoseError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
