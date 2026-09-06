# Hardware attestation

Choose a provider, bind a manifest digest to platform evidence, and appraise the result. Start with a local software example, then select the hardware path for your guest.

A matching digest alone does not authenticate hardware or establish that current inputs were measured correctly. Hardware appraisal needs approved roots, measurements, and freshness policy. The local example below does not exercise silicon.

## Run the API locally

Complete the [first-manifest tutorial](../getting-started.md), append this block to `first_manifest.py`, and run it again. It demonstrates a digest binding and a nonce/context binding using software only.

```python
import hashlib
import json
import secrets
from agent_manifest._auto_provider import SoftwareProvider

provider = SoftwareProvider()
provider.extend_manifest_hash(record)
report = provider.get_attestation_report()
assert report.platform == "software"
assert provider.verify_manifest_in_report(report, record)
modified = copy.deepcopy(record)
modified["artifacts"]["model_identity"]["version"] = "different"
assert not provider.verify_manifest_in_report(report, modified)
print("PASS: software binding matches the record and rejects an edited record")

# These observations belong to the demo's trusted configuration collector.
runtime_inputs = {
    "system_prompt_hash": prompt_hash,
    "policy_hash": context.policy_bundle_hash,
    "model_version": context.model_version,
}
context_bytes = json.dumps(runtime_inputs, sort_keys=True, separators=(",", ":")).encode()
context_hash = "sha256:" + hashlib.sha256(context_bytes).hexdigest()
nonce = secrets.token_bytes(32)  # In a service, the verifier issues this challenge.
runtime_report = provider.attest_runtime_state(nonce, context_hash)
assert runtime_report.platform == "software"
assert runtime_report.nonce_hex == nonce.hex()
assert runtime_report.context_hash == context_hash
second = provider.attest_runtime_state(secrets.token_bytes(32), context_hash)
assert second.report_data_hash != runtime_report.report_data_hash
print("PASS: a new nonce changes the software binding; no hardware proof was produced")
```

Expect two additional `PASS` lines. These assertions test software behavior. Copying the returned nonce or context into a response would not prove freshness or hardware authenticity.

## Select the hardware path

Use the guest's attestation interface to choose a provider. A CPU model or a confidential-VM marketing label alone is insufficient.

| Provider | Current SDK path | Verification boundary |
|----------|------------------|-----------------------|
| `SoftwareProvider` | Software digest and nonce binding; no device required | No hardware signature or isolation claim. |
| `SEVSNPProvider` | Non-paravisor SNP guest; kernel configfs-TSM `sev_guest` provider | Manifest digest goes into guest-controlled `REPORT_DATA`. Request VCEK verification and appraise approved measurements and platform policy. |
| `TDXProvider` | Non-paravisor TDX guest; configfs-TSM `tdx_guest` provider and quote-generation path | Manifest digest goes into quote `REPORTDATA`. Request DCAP quote verification and appraise approved measurements and platform policy. |
| `AzureCVMProvider` | Azure SNP through the vTPM/HCL path | Follow the vTPM quote, attestation-key binding, and SNP chain. The guest does not directly control SNP `REPORT_DATA`. |
| `TPMProvider` | TPM tools and a provisioned attestation key | A TPM quote supplies measured-state evidence; it does not isolate the agent's process memory. |
| `OPAQUEProvider` | Disabled in the current SDK; construction raises `AttestationUnavailableError` | No usable managed-service verification path is implemented. |

The direct SNP and TDX providers use `/sys/kernel/config/tsm/report` and require permission to create report requests. See the [provider implementation and requirements](https://github.com/agentrust-io/agent-manifest/blob/main/python/src/agent_manifest/_hw_providers.py) for the current kernel and driver prerequisites. Azure TDX is not supported by this SDK's offline attestation path; see [platform limitations](../limitations.md).

For SNP, construct `SEVSNPProvider(require_vcek_verification=True, product="Milan")`, choosing the product for your actual platform. This fetches AMD verification material and needs network access and `httpx`. For TDX, use `TDXProvider(require_quote_verification=True)`. Import both from `agent_manifest._hw_providers`.

Then call `extend_manifest_hash(record)` and `get_attestation_report()`. The SNP result includes `raw["vcek_cert_chain_verified"]`; TDX includes `raw["quote_verified"]`. Both verification flags default to false when their constructor options are omitted. `TDXProvider` has no `rtmr_index` constructor argument; this binding uses `REPORTDATA` rather than extending an RTMR.

`verify_manifest_in_report()` checks the manifest binding. Treat it as one check in the appraisal, not a complete signature, certificate, freshness, and workload-policy verdict. The recipient must examine authenticated quote bytes and compare the measurements with its own allowlist.

## Runtime state attestation (freshness proofs)

`attest_runtime_state(nonce, context_hash)` binds caller-supplied context to a challenge. For direct SNP and TDX, the qualifying bytes are `SHA-256(nonce || context_hash_bytes)` and are placed in the report-data field. The SDK's `report_data_hash` is a SHA-256 digest of those qualifying bytes; it is not the raw report-data value.

A signed challenge binding establishes freshness only after the recipient verifies the quote, checks its outstanding nonce, and applies an expiry/replay policy. The provider does not read the agent's prompt, policy, tool catalog, or model for you. A trusted collector must measure the actual state and define the context-hash preimage with the verifier. Otherwise a fresh quote can bind a false self-report.

The runtime quote needs its own appraisal. Enabling VCEK or quote verification for `get_attestation_report()` does not automatically appraise every `attest_runtime_state()` result. Check returned evidence rather than inheriting a prior report's flags.

Choose challenge frequency according to the operation and stale-evidence policy. Periodic calls alone do not bound drift detection unless measurement collection, verification, and rejection are all enforced. A report also does not prove what happens after it was collected.

## Auto-detection

`select_provider(level=N)` is a convenience selector, not a conformance validator. The current order is an explicitly configured OPAQUE provider, Azure CVM, direct SNP, direct TDX, TPM, then software. Because OPAQUE is disabled, setting `OPAQUE_ATTESTATION_URL` currently raises instead of selecting a working managed provider.

Without a hardware candidate, requesting `level >= 1` raises `AttestationUnavailableError`. Do not silently retry with `level=0` in a path that requires hardware. For reproducible local tests, choose `SoftwareProvider()` directly rather than depending on the host's devices or environment variables.

## Apply an acceptance policy

A provider name does not establish a conformance level or regulatory compliance. Apply the [specification's conformance requirements](../spec/agent-manifest-v0.2.md), including artifact coverage, signature profile, required evidence, and recipient policy. Hardware appraisal and application authorization remain separate checks.

Pass independently appraised evidence into the verifier's context, bound to the exact manifest. Then require the full manifest result to be `VALID`; a successful hardware check cannot override a bad signature, expired record, revocation, or artifact mismatch. Continue with [server-side verification](server-side-verification.md).
