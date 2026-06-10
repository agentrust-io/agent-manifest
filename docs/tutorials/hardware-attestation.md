# Hardware Attestation (SEV-SNP, TDX, OPAQUE)

Hardware attestation binds the manifest to a cryptographic measurement from silicon  -  proving the agent is running inside a specific, unmodified trusted execution environment. After this tutorial you will be able to:

- Choose the right attestation provider for your infrastructure
- Extend the manifest hash into hardware using `SEVSNPProvider`, `TDXProvider`, or `OPAQUEProvider`
- Read and verify the attestation report
- Use the auto-provider when the environment is not known at build time
- Write tests that work without hardware

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

os.environ["OPAQUE_ATTESTATION_URL"] = "https://attest.opaque.co"
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

## What's next

- [Tutorial: Deploying the verification endpoint](deploying-the-verification-endpoint.md)  -  run the verifier in production alongside hardware-attested agents
- [Tutorial: Server-side verification](server-side-verification.md)  -  enforce minimum attestation level with `enforce_attestation=True`
