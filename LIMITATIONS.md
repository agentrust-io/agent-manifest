# Known Limitations

This document describes what Agent Manifest does not do, and where layered defenses are needed. Honest scope boundaries prevent misplaced trust.

## What the manifest does not prevent

**Prompt injection at runtime**  
The manifest binds the system prompt hash at deployment. It cannot detect prompt injection that occurs during a session via user input, tool output, or RAG retrieval. For runtime injection defense, use a policy engine (e.g., AGT's PromptDefense Evaluator) in addition to the manifest.

**Model output manipulation**  
The manifest attests which model version was authorized. It cannot attest that the model's responses were unmanipulated. A compromised model API endpoint could return forged outputs while the manifest remains valid.

**Key compromise after attestation**  
If the manifest signing key is compromised after a manifest is issued, existing manifests remain cryptographically valid until they are explicitly revoked. Key monitoring and rapid revocation are the required controls — the manifest provides the revocation mechanism but cannot detect compromise itself.

**TEE side-channel attacks**  
Hardware attestation proves the manifest hash was measured in silicon. It does not protect against side-channel attacks (cache timing, power analysis) targeting the TEE itself. TEE-level side-channel defense is the responsibility of the TEE platform vendor.

**Operator-controlled revocation endpoint**  
The revocation endpoint is operated by the manifest issuer. A compromised or dishonest issuer could fail to publish revocation records. Transparency log integration (Rekor) provides a check — verifiers should require a transparency log entry for Level 1+ manifests.

**Policy correctness**  
The policy bundle hash attests that a specific Cedar/Rego/YAML policy was in force. It does not attest that the policy is correct or that it achieves the intended security outcome. Policy review is a separate control.

**Supply chain attacks before measurement**  
The container image digest is measured at TEE startup. Attacks that compromise the build pipeline before the final image is produced (e.g., compromised build runner, malicious dependency) are covered by SLSA provenance, not by the manifest attestation itself.

## What Level 0 does not provide

Level 0 (software-only signing) is suitable for development and staging. It does not satisfy:

- EU AI Act Art. 15 (cybersecurity) — requires Level 1+
- DORA Art. 9 — requires Level 1+ with HITL records
- Any claim of hardware-rooted trust — the signing key is held in software and can be extracted by a privileged operator

## What the SDK does not do

- **Evaluate Cedar policy** — the SDK stores and hashes Cedar bundles; evaluation requires the Cedar engine (included in AGT)
- **Store manifests** — the SDK produces and verifies manifest documents; storage, rotation, and distribution are the caller's responsibility
- **Replace a secrets manager** — signing private keys must be stored in a secrets manager (Azure Key Vault, AWS Secrets Manager, HSM); do not store them on disk without protection
- **Automatically rotate** — key rotation and manifest re-issuance must be triggered by the caller; the SDK provides the protocol but no scheduling

## Hardware attestation scope: boot-time binding only

Hardware attestation in this SDK proves **what was approved at agent startup**,
not what the agent is doing right now. Specifically:

- `extend_manifest_hash()` + `get_attestation_report()` run **once** at startup.
  The resulting report binds the manifest hash to the TEE's boot measurement
  (AMD SEV-SNP `MEASUREMENT`, Intel TDX `MRTD`, or TPM PCR values). After that
  call returns, the hardware is not consulted again by default.
- The boot measurement itself is **immutable** — it reflects the firmware and
  kernel image that were loaded when the TEE was initialised. No re-measurement
  of the TEE is possible after boot; this is a hardware property, not an SDK
  limitation.
- `verify_manifest()` checks the attestation block **once** at verification
  time (typically at deploy or during periodic audits). It does not continuously
  re-verify that the agent's runtime state still matches what was attested.

**What this means in practice:** an attacker who compromises the agent process
after startup (modifying the system prompt in memory, swapping the policy bundle,
injecting a tool) would not be detected by the boot-time attestation alone.

### Freshness proofs with `attest_runtime_state()`

For deployments that need to prove the agent has not drifted since startup, use
`attest_runtime_state(nonce, context_hash)`. This method issues a new hardware
quote on demand. The TEE sets its caller-controlled field
(`REPORT_DATA` on SEV-SNP, `REPORTDATA` on TDX, qualifying data on TPM) to
`sha256(nonce || context_hash_bytes)` and signs it together with the unchanged
boot measurement. A verifier that supplies the nonce and independently computes
`context_hash` can then confirm:

1. **TEE identity** — the boot measurement matches the expected launch digest
2. **Current state** — context_hash covers the live system prompt, policy, and tool catalog
3. **Freshness** — the nonce is unique per challenge, preventing replay

This is not a second boot measurement — the TEE firmware measurement never
changes. It is a hardware-signed freshness certificate that specific runtime
state was active in the same TEE at a specific moment.

Callers are responsible for deciding how often to call `attest_runtime_state()`
(e.g., every N tool calls, every M minutes, or on every verifier challenge). The
SDK provides the primitive; the scheduling and verification policy belong in the
caller or a runtime enforcement layer (e.g., cMCP).

**TPM note:** `attest_runtime_state()` on `TPMProvider` requires a
pre-provisioned Attestation Key (AK). See the docstring for provisioning steps.
SEV-SNP and TDX have no such requirement — the IOCTL is available to any process
with access to `/dev/sev-guest` or `/dev/tdx-guest`.

## Performance

Hardware attestation adds latency at agent startup (not per-request):

| Provider | Typical latency |
|----------|----------------|
| Software (Level 0) | < 1 ms |
| TPM | 50–200 ms |
| SEV-SNP | 10–50 ms |
| TDX | 10–50 ms |
| OPAQUE | 100–500 ms (network round-trip) |

Manifest verification (signature check + hash comparison) is < 5 ms in all cases.
