# TPM 2.0 reference-simulator quote vectors

Quotes emitted by the official TCG / Microsoft TPM 2.0 reference implementation,
covering signature scheme and digest combinations that no hand-written fixture in
this repository exercised. They exist because `verify_tpm_quote` verified only
RSASSA/SHA-256 and silently returned `False` for everything else (issue #255);
these are the evidence that the other combinations now verify.

## Provenance

| | |
|---|---|
| Source | https://github.com/microsoft/ms-tpm-20-ref |
| Source SHA | `ee21db0a941decd3cac67925ea3310873af60ab3` |
| Simulator | TPM 2.0 revision 1.83 (`TPM2_PT_MANUFACTURER` = `"XYZ "`) |
| Generation tooling | tpm2-tools 5.6-1build4, tpm2-tss 4.0.1-7.1ubuntu5.1 |
| Classification | `REFERENCE_SIMULATOR_EVIDENCE` |

**These are NOT real hardware.** They are simulator output. Nothing here says
anything about what any physical TPM in any fleet actually emits; a vendor part
may never produce RSAPSS or SHA-384 quotes. What they establish is only that a
quote in that shape, signed by a TPM that follows the reference implementation,
verifies. The real-hardware vector in `tests/test_tpm_hardware_vector.py` remains
the separate, stronger claim.

## Contents

Every `*-attest.bin` is a raw `TPMS_ATTEST` (magic `0xff544347`, `TPM_GENERATED`)
and every `*-tpmt-signature.bin` is a marshalled `TPMT_SIGNATURE`, both exactly as
the simulator produced them. Nothing was hand-assembled or re-encoded.

| Fixture prefix | sigAlg | hashAlg |
|---|---|---|
| `rsassa-sha256` | `0x0014` `TPM_ALG_RSASSA` | `0x000B` `TPM_ALG_SHA256` |
| `rsapss-sha256` | `0x0016` `TPM_ALG_RSAPSS` | `0x000B` `TPM_ALG_SHA256` |
| `rsassa-sha384` | `0x0014` `TPM_ALG_RSASSA` | `0x000C` `TPM_ALG_SHA384` |
| `ecdsa-sha384` | `0x0018` `TPM_ALG_ECDSA` | `0x000C` `TPM_ALG_SHA384` |

`nonce.hex` is the qualifying data (`-q`) passed to `tpm2_quote`, and is what
`expected_qualifying_data` must be given.

## The certificate chains are synthetic

`*-ak-chain.pem` and `*-root.pem` are **not** simulator output. The reference
simulator issues no AK certificate, and `verify_tpm_quote` requires a chain, so
each attestation key's public half — read back with `tpm2_readpublic -f pem`, so
it is the simulator's own key — was wrapped in a leaf certificate issued by a
throwaway local CA. The CA private key was never written to disk and is not
recoverable; these files are public certificates only.

That wrapper is load-bearing for nothing: it verifies identically for the vectors
that fail and the ones that pass, so it cannot be what any test result turns on.
