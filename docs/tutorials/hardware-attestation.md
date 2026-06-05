# Hardware attestation (SEV-SNP, TDX, OPAQUE)

Hardware attestation binds the manifest to a cryptographic measurement from silicon — proving the agent is running inside a specific, unmodified trusted execution environment. After this tutorial you will be able to:

- Choose the right provider for your infrastructure
- Extend the manifest hash into hardware (SEV-SNP, TDX, OPAQUE)
- Read and verify the attestation report
- Use the auto-provider when the environment is unknown at build time

## Prerequisites

```bash
pip install agent-manifest              # for OPAQUE (HTTP only)
pip install "agent-manifest[server]"    # adds httpx for OPAQUE
```

Hardware providers require the appropriate VM type — see the table below.

---

## Conformance levels and providers

| Level | Provider | Infrastructure |
|-------|----------|---------------|
| 0 | *(none — software signing only)* | Any |
| 1 | `TPMProvider` | Linux host with TPM 2.0 |
| 2 | `SEVSNPProvider` | AMD EPYC (Milan+): Azure DCasv5, AWS C6a Nitro, GCP N2D |
| 2 | `TDXProvider` | Intel Xeon (Sapphire Rapids+): Azure DCedsv5, GCP C3 |
| 3 | `OPAQUEProvider` | Any — delegates to OPAQUE's managed TEE |

Level 2 provides the strongest locally-verifiable hardware guarantee. Level 3 adds an audit chain signed inside the TEE by OPAQUE's infrastructure.

---

## AMD SEV-SNP (Level 2)

### Requirements

- AMD EPYC Milan or Genoa CPU with SEV-SNP enabled in BIOS
- Linux kernel 5.19+ with `CONFIG_AMD_MEM_ENCRYPT=y`
- Running inside an SEV-SNP VM
- `/dev/sev-guest` readable by the process (typically requires `CAP_SYS_ADMIN` or a udev rule)

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

# Load the manifest you want to attest
with open("manifest.json") as f:
    manifest = json.load(f)

# Extends SHA-256(manifest_pre_image) into HOST_DATA
provider.extend_manifest_hash(manifest)

# Read the hardware attestation report
report = provider.get_attestation_report()
print(f"Platform:      {report.platform}")          # "amd-sev-snp"
print(f"Manifest hash: {report.manifest_hash}")     # "sha256:..."
print(f"Measurement:   {report.raw['measurement']}")  # 48-byte PCR hex

# Confirm the report binds to this manifest
assert provider.verify_manifest_in_report(report, manifest)
```

### What is in the report

| Field | Description |
|-------|-------------|
| `raw.host_data` | 64 bytes: first 32 = SHA-256 of manifest pre-image, last 32 = zeros |
| `raw.measurement` | 48-byte platform measurement (covers firmware + kernel) |
| `raw.vmpl` | VMPL level (0 = highest privilege) |

---

## Intel TDX (Level 2)

### Requirements

- Intel 4th Gen Xeon (Sapphire Rapids) or later with TDX enabled
- Linux kernel 6.2+ with TDX guest driver (`/dev/tdx-guest`)
- Running inside an Intel TDX Trust Domain

### Usage

```python
from agent_manifest._hw_providers import TDXProvider

# rtmr_index=1 is the conventional application measurement register
provider = TDXProvider(rtmr_index=1)

provider.extend_manifest_hash(manifest)
report = provider.get_attestation_report()

print(f"Platform:    {report.platform}")        # "intel-tdx"
print(f"RTMR index:  {report.raw['rtmr_index']}")  # 1
print(f"Report data: {report.raw['report_data']}")  # 64-byte hex

assert provider.verify_manifest_in_report(report, manifest)
```

### RTMR index guidance

| RTMR | Conventional use |
|------|-----------------|
| 0 | TD-measured (firmware and boot) — do not use |
| 1 | OS and application-level measurements — use this |
| 2 | Available for software use |
| 3 | Available for software use |

---

## OPAQUE managed runtime (Level 3)

OPAQUE runs the attestation inside its own TEE and returns a signed TRACE claim. No local hardware is required — OPAQUE handles the silicon-level measurement on your behalf.

### Requirements

- `OPAQUE_ATTESTATION_URL` environment variable pointing to the OPAQUE attestation service
- Optionally `OPAQUE_API_KEY` for authenticated access
- `httpx` installed (`pip install "agent-manifest[server]"`)

### Usage

```python
import os
from agent_manifest._hw_providers import OPAQUEProvider

os.environ["OPAQUE_ATTESTATION_URL"] = "https://attest.opaque.co"
# os.environ["OPAQUE_API_KEY"] = "your-key"   # if required

provider = OPAQUEProvider()
provider.extend_manifest_hash(manifest)

report = provider.get_attestation_report()
print(f"Platform: {report.platform}")   # "opaque"
print(f"Manifest hash: {report.manifest_hash}")
print(f"TRACE claim: {report.raw}")     # eat_profile, iat, audit_chain_root, ...

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

The `audit_chain_root` anchors every decision the agent made to a Merkle chain held inside the OPAQUE TEE — this is the Level 3 guarantee.

---

## Auto-provider: pick the best available hardware

Use `_auto_provider.py` when the environment is not known at build time — it tries each provider in order and falls back to software-only.

```python
from agent_manifest._auto_provider import SoftwareProvider

# Falls back gracefully: OPAQUE → TDX → SEV-SNP → TPM → software
provider = SoftwareProvider()
provider.extend_manifest_hash(manifest)
report = provider.get_attestation_report()

print(f"Attested on: {report.platform}")
# "amd-sev-snp" in an SEV-SNP VM
# "intel-tdx"   in a TDX Trust Domain
# "tpm"         on a Linux host with TPM
# "software"    everywhere else
```

---

## Testing without hardware

All providers raise `AttestationUnavailableError` if the hardware is absent. In tests, mock the provider:

```python
from unittest.mock import patch, MagicMock
from agent_manifest._providers import AttestationReport

mock_report = AttestationReport(
    platform="amd-sev-snp",
    manifest_hash="sha256:" + "aa" * 32,
    raw={"measurement": "bb" * 48, "host_data": "cc" * 64, "vmpl": 0},
)

with patch("agent_manifest._hw_providers.SEVSNPProvider.extend_manifest_hash"), \
     patch("agent_manifest._hw_providers.SEVSNPProvider.get_attestation_report",
           return_value=mock_report):
    # your test code
    pass
```

Or gate the test on hardware availability:

```python
import os, pytest

NEEDS_SEV_SNP = pytest.mark.skipif(
    not os.path.exists("/dev/sev-guest"),
    reason="requires AMD SEV-SNP hardware",
)

@NEEDS_SEV_SNP
def test_sev_snp_roundtrip():
    provider = SEVSNPProvider()
    provider.extend_manifest_hash(manifest)
    report = provider.get_attestation_report()
    assert provider.verify_manifest_in_report(report, manifest)
```

---

## What's next

- [Tutorial: Deploying the verification endpoint](deploy-verifier.md) — run the verifier in production alongside your hardware-attested agents
- [Tutorial: Server-side verification](server-side-verification.md) — enforce minimum attestation level with `enforce_attestation=True`
