# Hardware Attestation (SEV-SNP, TDX, OPAQUE)

Hardware attestation binds the manifest to a cryptographic measurement from silicon  -  proving the agent was initialised inside a specific, unmodified trusted execution environment. After this tutorial you will be able to:

- Choose the right attestation provider for your infrastructure
- Extend the manifest hash into hardware using `SEVSNPProvider`, `TDXProvider`, or `OPAQUEProvider`
- Read and verify the attestation report
- Request periodic freshness proofs with `attest_runtime_state()`
- Use the auto-provider when the environment is not known at build time
- Write tests that work without hardware

> **What boot-time attestation proves — and doesn't prove**
>
> `extend_manifest_hash()` runs once at agent startup. It proves *which manifest
> was approved when the TEE was initialised* — it does not continuously monitor
> whether the agent's runtime state has changed since then. The TEE's boot
> measurement (`MEASUREMENT` on SEV-SNP, `MRTD` on TDX, PCR values on TPM) is
> hardware-immutable after launch; no re-measurement is possible.
>
> For a freshness proof that the agent is *currently* running the approved state,
> use [`attest_runtime_state()`](#runtime-state-attestation-freshness-proofs).

## Prerequisites

```bash
pip install agent-manifest              # core SDK
pip install "agent-manifest[server]"   # adds httpx for OPAQUEProvider
```

Hardware providers require the VM types listed in the table below. The `SoftwareProvider` fallback works everywhere.

---

## Conformance levels

| Level | Provider | Infrastructure requirement |
|-------|----------|--------------------------|
| 0 | *(none)* | Any  -  software signing only |
| 1 | `TPMProvider` | Linux host with TPM 2.0 |
| 2 | `SEVSNPProvider` | AMD EPYC (Milan+): Azure DCasv5, AWS C6a Nitro, GCP N2D |
| 2 | `TDXProvider` | Intel Xeon (Sapphire Rapids+): Azure DCedsv5, GCP C3 |
| 3 | `OPAQUEProvider` | Any  -  delegates to OPAQUE's managed TEE |

Level 2 provides the strongest locally-verifiable hardware guarantee. Level 3 adds a hardware-signed audit chain managed by OPAQUE inside their TEE.

---

## AMD SEV-SNP (Level 2)

### Prerequisites

- AMD EPYC Milan or Genoa CPU with SEV-SNP enabled in BIOS
- Linux kernel 5.19+ with `CONFIG_AMD_MEM_ENCRYPT=y`
- Running inside an SEV-SNP VM (Azure DCasv5, AWS C6a Nitro, or GCP N2D Confidential)
- `/dev/sev-guest` readable by the process (requires `CAP_SYS_ADMIN` or a dedicated udev rule)

### How it works

`SEVSNPProvider.extend_manifest_hash()` computes `SHA-256(manifest_pre_image)` and places the 32-byte digest in the first half of the `HOST_DATA` field of the SNP attestation report. `HOST_DATA` is 64 bytes reserved for user-defined binding data. Verifiers check that `HOST_DATA[:32]` matches the expected manifest hash.

### Usage

```python
import json
from agent_manifest._hw_providers import SEVSNPProvider
from agent_manifest._providers import AttestationUnavailableError

try:
    provider = SEVSNPProvider()
except AttestationUnavailableError as e:
    print(f"SEV-SNP not available: {e}")
    raise SystemExit(1)

with open("manifest.json") as f:
    manifest = json.load(f)

# Extends SHA-256(manifest_pre_image) into HOST_DATA
provider.extend_manifest_hash(manifest)

# Read the attestation report
report = provider.get_attestation_report()
print(f"Platform:      {report.platform}")             # "amd-sev-snp"
print(f"Manifest hash: {report.manifest_hash}")        # "sha256:..."
print(f"Measurement:   {report.raw['measurement']}")   # 48-byte hex

# Confirm the report binds to this manifest
assert provider.verify_manifest_in_report(report, manifest)
```

### What the report contains

| Field | Description |
|-------|-------------|
| `raw['host_data']` | 64 bytes: first 32 = SHA-256 of manifest pre-image, last 32 = zeros |
| `raw['measurement']` | 48-byte platform measurement covering firmware and kernel |
| `raw['vmpl']` | VMPL level (0 = highest privilege) |
| `raw['vcek_cert_chain_verified']` | Always `False` in the SDK  -  fetch the VCEK from AMD KDS to verify independently |

---

## Intel TDX (Level 2)

### Prerequisites

- Intel 4th Gen Xeon (Sapphire Rapids) or later with TDX enabled
- Linux kernel 6.2+ with TDX guest driver (`/dev/tdx-guest`)
- Running inside an Intel TDX Trust Domain (Azure DCedsv5 or GCP C3 Confidential)

### How it works

`TDXProvider.extend_manifest_hash()` places `SHA-256(manifest_pre_image)` in the `REPORTDATA` field of the TD report. RTMR[1] is the conventional application-level measurement register  -  RTMR[0] is owned by firmware.

### Usage

```python
from agent_manifest._hw_providers import TDXProvider

# rtmr_index=1 is the conventional choice for application measurements
provider = TDXProvider(rtmr_index=1)

provider.extend_manifest_hash(manifest)
report = provider.get_attestation_report()

print(f"Platform:    {report.platform}")             # "intel-tdx"
print(f"RTMR index:  {report.raw['rtmr_index']}")   # 1
print(f"Report data: {report.raw['report_data']}")   # 64-byte hex

assert provider.verify_manifest_in_report(report, manifest)
```

### RTMR index guidance

| RTMR | Conventional use |
|------|-----------------|
| 0 | TD-measured (firmware and boot)  -  do not use |
| 1 | OS and application-level measurements  -  use this |
| 2 | Available for additional software measurements |
| 3 | Available for additional software measurements |

---

## OPAQUE Managed TEE (Level 3)

OPAQUE runs attestation inside its own managed TEE and returns a signed TRACE claim. No local hardware is required.

### Prerequisites

- Set `OPAQUE_ATTESTATION_URL` to the OPAQUE attestation service base URL (must be `https://`)
- Optionally set `OPAQUE_API_KEY` for authenticated access
- `httpx` installed (`pip install "agent-manifest[server]"`)

### Usage

```python
import os
from agent_manifest._hw_providers import OPAQUEProvider

os.environ["OPAQUE_ATTESTATION_URL"] = "https://YOUR_OPAQUE_TENANT.attest.example.com"
# Replace with your Opaque attestation service URL (requires an Opaque account)
# os.environ["OPAQUE_API_KEY"] = "your-key"  # if required

provider = OPAQUEProvider()
provider.extend_manifest_hash(manifest)

report = provider.get_attestation_report()
print(f"Platform:      {report.platform}")      # "opaque"
print(f"Manifest hash: {report.manifest_hash}")
print(f"TRACE claim:   {report.raw}")

assert provider.verify_manifest_in_report(report, manifest)
```

### What the TRACE claim contains

```json
{
  "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
  "iat": 1749120000,
  "manifest_hash": "sha256:e3b0c44...",
  "audit_chain_root": "sha256:a1b2c3...",
  "tee_platform": "amd-sev-snp",
  "attestation_report_hash": "sha256:..."
}
```

The `audit_chain_root` anchors every decision the agent made to a Merkle chain held inside the OPAQUE TEE. This is the Level 3 guarantee  -  the signing key never leaves the TEE.

---

## Choosing the right level

| Use case | Recommended level | Provider |
|----------|------------------|---------|
| Development and local testing | 0 | `SoftwareProvider` |
| Enterprise internal deployment | 1 | `TPMProvider` |
| EU AI Act Art. 15 (cybersecurity) | 2 | `SEVSNPProvider` or `TDXProvider` |
| Financial services, regulated workloads | 2+ | `SEVSNPProvider` / `TDXProvider` |
| Full audit chain, OPAQUE-managed trust | 3 | `OPAQUEProvider` |
| Unknown environment, pick best available | any | `select_provider(level=N)` |

---

## Auto-detection

Use `select_provider()` when the environment is not known at build time. It probes in order: OPAQUE (if env var set) then SEV-SNP then TDX then TPM then software-only.

```python
from agent_manifest._auto_provider import select_provider
from agent_manifest._providers import AttestationUnavailableError

# Raises AttestationUnavailableError if level=1 and no hardware is available
try:
    provider = select_provider(level=1)
except AttestationUnavailableError:
    # Fallback to Level 0 in development
    provider = select_provider(level=0)

provider.extend_manifest_hash(manifest)
report = provider.get_attestation_report()
print(f"Attested on: {report.platform}")
# "amd-sev-snp" in an SEV-SNP VM
# "intel-tdx"   in a TDX Trust Domain
# "tpm"         on a Linux host with TPM
# "software"    everywhere else
```

---

## Mocked examples for developers without hardware

All providers raise `AttestationUnavailableError` if the hardware device is absent. In tests, mock the provider rather than skipping tests entirely.

```python
from unittest.mock import patch
from agent_manifest._providers import AttestationReport

mock_report = AttestationReport(
    platform="amd-sev-snp",
    manifest_hash="sha256:" + "aa" * 32,
    raw={
        "host_data": "cc" * 64,
        "measurement": "bb" * 48,
        "vmpl": 0,
        "vcek_cert_chain_verified": False,
    },
)

with patch(
    "agent_manifest._hw_providers.SEVSNPProvider.extend_manifest_hash"
), patch(
    "agent_manifest._hw_providers.SEVSNPProvider.get_attestation_report",
    return_value=mock_report,
):
    # your test code here
    pass
```

`SoftwareProvider` is useful for unit tests that exercise the attestation flow without mocking:

```python
from agent_manifest._auto_provider import SoftwareProvider

provider = SoftwareProvider()
provider.extend_manifest_hash(manifest)
report = provider.get_attestation_report()
# report.platform == "software"
# Note: "software" measurement is not accepted for Level 1+ conformance
```

Gate hardware-only tests with a skip marker:

```python
import os
import pytest

needs_sev_snp = pytest.mark.skipif(
    not os.path.exists("/dev/sev-guest"),
    reason="requires AMD SEV-SNP hardware",
)

@needs_sev_snp
def test_sev_snp_roundtrip():
    provider = SEVSNPProvider()
    provider.extend_manifest_hash(manifest)
    report = provider.get_attestation_report()
    assert provider.verify_manifest_in_report(report, manifest)
```

---

---

## Runtime state attestation (freshness proofs)

The boot-time attestation proves *what was approved at startup*. If you need to
prove the agent has not drifted since then — same system prompt, same policy,
same tool catalog — call `attest_runtime_state()` periodically or on each
verifier challenge.

### How it works

The hardware's caller-controlled field (`HOST_DATA` on SEV-SNP, `REPORTDATA`
on TDX, qualifying data on TPM) is set to:

```
sha256(nonce || context_hash_bytes)
```

The hardware signs this together with the **unchanged** boot measurement, so the
verifier receives a single quote that proves both TEE identity (from the
immutable measurement) and current state (from the fresh REPORT_DATA).

The boot measurement is not re-run — hardware makes that impossible. What changes
is only the caller-controlled field, which is what carries the freshness proof.

### Computing the context hash

```python
import hashlib, json

def compute_context_hash(
    system_prompt_hash: str,
    policy_hash: str,
    tool_catalog_hash: str,
) -> str:
    """sha256 of canonical JSON over the runtime context fields."""
    payload = json.dumps(
        {
            "system_prompt_hash": system_prompt_hash,
            "policy_hash": policy_hash,
            "tool_catalog_hash": tool_catalog_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()
```

Include every field the verifier needs to pin. Add `model_version` or
`rag_corpus_merkle_root` if those are also in scope.

### Requesting a fresh quote

```python
import os
from agent_manifest._hw_providers import SEVSNPProvider

provider = SEVSNPProvider()
provider.extend_manifest_hash(manifest)      # once at startup

# ... agent runs ...

# Verifier supplies a fresh nonce for each challenge
nonce = os.urandom(32)

context_hash = compute_context_hash(
    system_prompt_hash="sha256:aabbcc...",
    policy_hash="sha256:112233...",
    tool_catalog_hash="sha256:445566...",
)

rt_report = provider.attest_runtime_state(nonce, context_hash)

print(f"Platform:         {rt_report.platform}")        # "amd-sev-snp"
print(f"Nonce (hex):      {rt_report.nonce_hex}")
print(f"Context hash:     {rt_report.context_hash}")
print(f"REPORT_DATA hash: {rt_report.report_data_hash}")
# rt_report.quote — raw hardware quote blob; send to verifier for signature check
```

The same API works identically with `TDXProvider` and `OPAQUEProvider`. For
`SoftwareProvider` it produces a software-only binding (Level 0, not hardware
attested — useful in tests).

### TPM: Attestation Key required

`TPMProvider.attest_runtime_state()` uses `tpm2_quote`, which requires a
pre-provisioned Attestation Key (AK). Provision one before calling it:

```bash
tpm2_createprimary -c primary.ctx
tpm2_create -C primary.ctx -G rsa -u ak.pub -r ak.priv
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx
```

Then pass the path at construction:

```python
from agent_manifest._providers import TPMProvider

provider = TPMProvider(ak_context="/var/lib/agent-manifest/ak.ctx")
provider.extend_manifest_hash(manifest)

rt_report = provider.attest_runtime_state(nonce, context_hash)
```

SEV-SNP and TDX have no equivalent requirement — the IOCTL is available without
pre-provisioning any key material.

### How often to call it

The SDK provides the primitive; the scheduling policy is yours. Common patterns:

| Pattern | When to use |
|---------|-------------|
| Per verifier challenge | Highest assurance — verifier controls nonce freshness |
| Every N tool calls | Bounds the window of undetected drift |
| On a fixed interval (e.g., every 5 min) | Simpler to implement; interval sets the worst-case detection lag |
| At startup only | Equivalent to boot-time attestation — not a freshness proof |

For regulated workloads, let the verifier dictate the nonce and challenge
frequency rather than having the agent self-report.

### Mocking in tests

```python
from unittest.mock import patch
from agent_manifest._providers import RuntimeAttestationReport

mock_rt = RuntimeAttestationReport(
    platform="amd-sev-snp",
    report_data_hash="sha256:" + "aa" * 32,
    context_hash="sha256:" + "bb" * 32,
    nonce_hex="cc" * 32,
    raw={"measurement": "dd" * 48, "vcek_cert_chain_verified": False},
)

with patch(
    "agent_manifest._hw_providers.SEVSNPProvider.attest_runtime_state",
    return_value=mock_rt,
):
    rt_report = provider.attest_runtime_state(nonce, context_hash)
```

---

## What's next

- [Tutorial: Deploying the verification endpoint](deploying-the-verification-endpoint.md)  -  run the verifier in production alongside hardware-attested agents
- [Tutorial: Server-side verification](server-side-verification.md)  -  enforce minimum attestation level with `enforce_attestation=True`
- [Known Limitations](../../LIMITATIONS.md)  -  full scope of what attestation does and does not prove
