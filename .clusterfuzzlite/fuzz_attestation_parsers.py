#!/usr/bin/python3
"""Fuzz the attestation blob parsers.

These are the only functions in the SDK that read attacker-supplied binary at
fixed offsets with attacker-chosen declared lengths: an SNP report, a TDX quote
with four nested size fields, a TPM quote, and a TPMT_SIGNATURE whose algorithm
byte selects how the rest is read. A verifier is handed these before it has
decided whether to trust anything about them.

The property is that each parser fails closed: it either returns, or raises the
error type its own module declares. A struct.error, IndexError, MemoryError or
OverflowError reaching the caller means a length field was believed, and callers
written against the documented exception will not catch it.
"""
import sys

import atheris

with atheris.instrument_imports():
    from agent_manifest._snp_verify import SnpVerificationError, parse_hcl_report, parse_snp_report
    from agent_manifest._tdx_verify import (
        TdxVerificationError,
        parse_tdx_quote,
        parse_tdx_quote_signature,
    )
    from agent_manifest._tpm_verify import (
        TpmVerificationError,
        parse_tpm_attest,
        parse_tpm_nv_certify,
        parse_tpm_quote,
        parse_tpmt_signature,
    )

# (parser, the exception it is allowed to raise)
_TARGETS = [
    (parse_snp_report, SnpVerificationError),
    (parse_hcl_report, SnpVerificationError),
    (parse_tdx_quote, TdxVerificationError),
    (parse_tdx_quote_signature, TdxVerificationError),
    (parse_tpm_attest, TpmVerificationError),
    (parse_tpm_quote, TpmVerificationError),
    (parse_tpm_nv_certify, TpmVerificationError),
    (parse_tpmt_signature, TpmVerificationError),
]


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    parser, declared = _TARGETS[fdp.ConsumeIntInRange(0, len(_TARGETS) - 1)]
    blob = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        parser(blob)
    except declared:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
