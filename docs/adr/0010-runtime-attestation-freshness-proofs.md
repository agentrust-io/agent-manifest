# ADR-0010: Runtime Attestation Freshness Proofs

**Status**: Accepted  
**Date**: 2026-06-24  
**Spec section**: Section 3.3.2 (new)

## Context

A Microsoft contributor reported that hardware attestation in the SDK is
boot-time only: `extend_manifest_hash()` runs once at agent startup, and no
hardware-signed evidence is produced during agent execution. This is accurate
and by design for v0.1, but leaves a gap for deployments that need continuous
proof that an agent has not drifted from its approved state after launch.

The gap matters because:

- A compromised process can modify the system prompt, policy bundle, or tool
  catalog in memory after the boot-time attestation has already passed.
- The boot-time `attestation` block in the manifest proves what was approved at
  launch; it does not prove what is running now.
- Regulated workloads (DORA Art. 9, EU AI Act Art. 15) and enterprise security
  teams increasingly expect continuous or challenge-response evidence, not just
  a one-time launch measurement.

### What hardware actually provides

TEE attestation hardware has two distinct fields:

| Field | Set by | Mutable after boot? |
|-------|--------|-------------------|
| `MEASUREMENT` / `MRTD` / PCR values | Hardware/firmware at launch | No — silicon-sealed |
| `REPORT_DATA` (SNP) / `REPORTDATA` (TDX) or qualifying data (TPM) | Caller (guest) software via IOCTL | Yes — guest-controlled, hardware-signed |

The boot measurement is immutable. However, the caller-controlled field can be
set to arbitrary bytes at any time by issuing a new IOCTL, and the hardware
signs both fields together. This means a fresh report with a new nonce in
`REPORT_DATA` proves:

1. **TEE identity** — the same boot measurement as at launch (hardware unchanged)
2. **Current state** — the nonce binds a specific context hash (state at this moment)
3. **Freshness** — a verifier-supplied nonce prevents replay of an old report

This is how PCC's stateless compute model and Azure Confidential Computing
implement periodic quote refresh.

## Decision

Add `attest_runtime_state(nonce: bytes, context_hash: str) -> RuntimeAttestationReport`
as an abstract method on `AttestationProvider`. All providers must implement it.

The method sets the caller-controlled hardware field to:
```
sha256(nonce || bytes.fromhex(context_hash.split(":")[-1]))
```
and fetches a fresh hardware-signed quote. The resulting `RuntimeAttestationReport`
carries `report_data_hash`, `context_hash`, `nonce_hex`, and the raw quote blob.

A companion `verify_runtime_report(report, nonce, context_hash)` function in
`_verify.py` checks the software-computable consistency (that `report_data_hash`
matches the expected derivation). Full hardware signature verification requires
platform vendor SDKs and is out of scope for the Agent Manifest SDK itself.

The boot-time `attestation` block in the manifest is unchanged. Runtime reports
are separate evidence artifacts — they are not appended to the manifest.

## Rationale

**Why caller-controlled REPORT_DATA, not a second launch measurement?**

Re-measuring the TEE is not possible after boot. The only way to get fresh
hardware-signed evidence is via the caller-controlled field. This is not a
workaround — it is the intended mechanism. SNP's `REPORT_DATA` (the guest-controlled
field, distinct from the host-set `HOST_DATA`) and TDX's `REPORTDATA` exist
specifically for this purpose.

**Why sha256(nonce || context_hash_bytes) rather than nonce alone?**

The nonce alone proves freshness but not state. Hashing nonce and context
together means the verifier can confirm both "this report is not a replay" and
"the agent was in this specific state when the report was generated."

**Why a separate `RuntimeAttestationReport` type rather than reusing `AttestationReport`?**

The two have different semantics:
- `AttestationReport` — boot-time, bound to manifest hash, one per agent lifetime
- `RuntimeAttestationReport` — on-demand, bound to runtime context + nonce, many per lifetime

Mixing them into one type would obscure which guarantee a caller is relying on.

**Why is TPM different?**

TPM PCR values accumulate and cannot be reset without a reboot. TPM runtime
re-attestation therefore uses `tpm2_quote` with qualifying data (the nonce +
context hash), which requires a pre-provisioned Attestation Key (AK).
SEV-SNP and TDX do not have this requirement — the IOCTL is available without
pre-provisioning any key material.

## Alternatives considered

**Option A — periodic re-launch of extend_manifest_hash()**  
Rejected. `extend_manifest_hash()` is designed for the boot-time path. Calling
it repeatedly would modify `self._report_bytes` and break the semantics of
`get_attestation_report()`, which should always return the boot-time report.
Keeping the two paths separate is cleaner.

**Option B — a `ContinuousVerificationConfig` attached to VerificationContext**  
Rejected for v0.1. Adding scheduling logic to the verification engine conflates
the protocol (what to check) with the policy (how often). The scheduling
decision belongs to the caller or a runtime enforcement layer (cMCP). The SDK
provides the primitive.

**Option C — no SDK support; defer entirely to cMCP**  
Rejected. The spec references `attest_runtime_state()` semantics in the
decision trace binding (section 3.2.7). Having the SDK implement the primitive
makes it testable, mockable, and usable without cMCP for callers who implement
their own enforcement loop.

## Consequences

- All existing `AttestationProvider` subclasses must implement
  `attest_runtime_state()`. The four built-in providers do so; third-party
  subclasses will get a `TypeError` at instantiation time until they add the
  method (expected — this is a protocol extension).
- `RuntimeAttestationReport` is exported from `agent_manifest` public API.
- `verify_runtime_report()` is exported from `agent_manifest` public API.
- The spec gains a new normative section 3.3.2 defining the runtime attestation
  report format and the `REPORT_DATA` derivation.
- The scheduling of `attest_runtime_state()` calls is intentionally left to the
  caller. The SDK makes no assumptions about call frequency.

## References

- AMD SEV-SNP: `REPORT_DATA` field, populated via the `user_data` member of `struct snp_report_req` — Linux kernel `sev-guest.h`
- Intel TDX: `REPORTDATA` field — Intel TDX Module Architecture Spec §3.3
- TPM 2.0: qualifying data in `TPM2_Quote` — TCG PC Client Platform Firmware Profile §4.2
- RFC 9334: RATS architecture (Attester / Verifier / Relying Party roles)
- ADR-0009: SPIFFE URI agent identity (related — establishes the attestation subject)
