# Hardware attestation

Choose a provider, bind a manifest digest to platform evidence, and appraise the result. Start with a local software example, then select the hardware path for your guest.

A matching digest alone does not authenticate hardware or establish that current inputs were measured correctly. Hardware appraisal needs approved roots, measurements, and freshness policy. The local example below does not exercise silicon.

## Run the API locally

Complete the [first-manifest tutorial](https://manifest.agentrust-io.com/getting-started/index.md), append this block to `first_manifest.py`, and run it again. It demonstrates a digest binding and a nonce/context binding using software only.

```
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

from agent_manifest import parse_platform_info, appraise_platform_info, SnpVerificationError

# On real SEV-SNP hardware: parse_platform_info(parse_snp_report(report.quote).platform_info).
# PLATFORM_INFO (offset 0x40) sits inside the signed report body, so a mutated byte
# invalidates the signature just like a mutated measurement would - the field is
# authenticated. What verify_attestation_chain() does not do is interpret it: it has
# no opinion on whether SMT-on or an unconfirmed alias check is acceptable. That
# policy judgment is appraise_platform_info()'s job, as its own explicit step (see
# limitations.md).
good_platform_info = parse_platform_info(0b0010_0000)  # alias_check_complete set, SMT off
appraise_platform_info(good_platform_info, require={"alias_check_complete"}, forbid={"smt_enabled"})
print("PASS: platform policy satisfied (alias_check_complete set, SMT off)")

bad_platform_info = parse_platform_info(0b0000_0001)  # SMT on, alias_check_complete unset
try:
    appraise_platform_info(bad_platform_info, require={"alias_check_complete"}, forbid={"smt_enabled"})
    raise AssertionError("expected the platform policy to reject this report")
except SnpVerificationError:
    print("PASS: platform policy rejects an SMT-enabled report with no alias check")
```

Expect four `PASS` lines in total from this page (two from the software-binding example above, two from the platform-policy calls just added). Copying the returned nonce or context into a response would not prove freshness or hardware authenticity; the two new platform-policy assertions test policy logic decoded from literal bits, not a captured hardware report; that end-to-end path is exercised separately (linked below).

### Appraise platform state before trusting hardware evidence

`appraise_platform_info()` is not called by `verify_manifest()`, and is not called by `verify_attestation_chain()` either: see [platform limitations](https://manifest.agentrust-io.com/limitations/index.md). Neither function is invoked by the other; each is an appraisal the caller runs and hands to `verify_manifest()` as a result via `VerificationContext`. Combine the two appraisals (signature, chain and measurement; platform state) into a single pass/fail before deciding whether the manifest hash is trustworthy evidence. This is a composition sketch, not a runnable snippet: `report`, `expected_hash`, `context`, and `record` are whatever your own attestation flow already produced earlier in this tutorial:

```
hw_result = verify_attestation_chain(
    report, expected_manifest_hash=expected_hash, snp_report_bytes=report.quote,
    vcek_cert_der=vcek_der, cert_chain_pem=cert_chain_pem,
)

# Only attempt platform appraisal once hardware appraisal has already passed.
# A tampered or malformed report can fail hw_result.passed on its own; there
# is no reason to also risk parse_snp_report() raising on the same bad bytes
# before the caller ever reaches its decision, and no reason to trust
# PLATFORM_INFO from a report whose signature has not verified in the first
# place.
platform_ok = False
if hw_result.passed:
    platform_info = parse_platform_info(parse_snp_report(report.quote).platform_info)
    try:
        appraise_platform_info(platform_info, require={"alias_check_complete"}, forbid={"smt_enabled"})
        platform_ok = True
    except SnpVerificationError:
        platform_ok = False

if hw_result.passed and platform_ok:
    context.verified_attestation_manifest_hashes.add(expected_hash)
    context.attestation_evidence_manifest_id = record["manifest_id"]
```

No new field is needed on `VerificationContext` for this: `verify_manifest()` already gates `attestation_verified` (and, with `enforce_attestation=True`, the overall `VALID`/`ATTESTATION_UNAVAILABLE` result) purely on membership in `verified_attestation_manifest_hashes`. Calling `appraise_platform_info()` with no `require`/`forbid` at all or not calling it asserts nothing and reproduces prior behavior exactly, so adopting a platform policy is opt in and cannot regress an existing deployment that never sets one.

This composes two things the caller is already responsible for; `verify_manifest()` itself still has no idea PLATFORM_INFO exists. [`test_platform_info_verify_manifest.py`](https://github.com/agentrust-io/agent-manifest/blob/main/python/tests/test_platform_info_verify_manifest.py) is an integration-style test of this composition against a cryptographically self-consistent synthetic SEV-SNP chain (freshly generated keys and certificates shaped like the real VCEK/ASK/ARK hierarchy, not AMD-rooted hardware evidence), covering the accept case, a `require`-only failure, a `forbid`-only failure, that hardware appraisal failing correctly stops platform appraisal from being reached at all (checked with a monkeypatch, not just the final verdict, since a broken ordering can still land on the same verdict by coincidence), that a genuinely malformed report doesn't crash the corrected ordering, and confirming a `PLATFORM_INFO` byte flipped after signing invalidates the signature rather than silently changing the appraisal. The policy decision itself (only add the hash when both appraisals pass) is implemented by that test's own helper, the same way it would be in your caller code it is not new behavior added to `verify_manifest()`.

## Select the hardware path

Use the guest's attestation interface to choose a provider. A CPU model or a confidential-VM marketing label alone is insufficient.

| Provider           | Current SDK path                                                                     | Verification boundary                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `SoftwareProvider` | Software digest and nonce binding; no device required                                | No hardware signature or isolation claim.                                                                                                   |
| `SEVSNPProvider`   | Non-paravisor SNP guest; kernel configfs-TSM `sev_guest` provider                    | Manifest digest goes into guest-controlled `REPORT_DATA`. Request VCEK verification and appraise approved measurements and platform policy. |
| `TDXProvider`      | Non-paravisor TDX guest; configfs-TSM `tdx_guest` provider and quote-generation path | Manifest digest goes into quote `REPORTDATA`. Request DCAP quote verification and appraise approved measurements and platform policy.       |
| `AzureCVMProvider` | Azure SNP through the vTPM/HCL path                                                  | Follow the vTPM quote, attestation-key binding, and SNP chain. The guest does not directly control SNP `REPORT_DATA`.                       |
| `TPMProvider`      | TPM tools and a provisioned attestation key                                          | A TPM quote supplies measured-state evidence; it does not isolate the agent's process memory.                                               |
| `OPAQUEProvider`   | Disabled in the current SDK; construction raises `AttestationUnavailableError`       | No usable managed-service verification path is implemented.                                                                                 |

The direct SNP and TDX providers use `/sys/kernel/config/tsm/report` and require permission to create report requests. See the [provider implementation and requirements](https://github.com/agentrust-io/agent-manifest/blob/main/python/src/agent_manifest/_hw_providers.py) for the current kernel and driver prerequisites. Azure TDX is not supported by this SDK's offline attestation path; see [platform limitations](https://manifest.agentrust-io.com/limitations/index.md).

For SNP, construct `SEVSNPProvider(require_vcek_verification=True, product="Milan")`, choosing the product for your actual platform. This fetches AMD verification material and needs network access and `httpx`. For TDX, use `TDXProvider(require_quote_verification=True)`. Import both from `agent_manifest._hw_providers`.

Then call `extend_manifest_hash(record)` and `get_attestation_report()`. The SNP result includes `raw["vcek_cert_chain_verified"]`; TDX includes `raw["quote_verified"]`. Both verification flags default to false when their constructor options are omitted. `TDXProvider` has no `rtmr_index` constructor argument; this binding uses `REPORTDATA` rather than extending an RTMR.

SDK binding differs from the spec's launch-time profile

`SEVSNPProvider` and `TDXProvider` bind the manifest digest at runtime, from inside the guest, in the guest-controlled field: the first 32 bytes of `REPORT_DATA` (SNP) or `REPORTDATA` (TDX) carry `SHA-256(manifest pre-image)` and the remaining 32 bytes are zero. The GCP TDX captures in `python/tests/fixtures/hardware/gcp-tdx-2026-07-21/` show this: the digest is in `REPORTDATA` and `RTMR[3]` is all zeros.

[Specification section 3.3.1](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/index.md) defines the target launch-time binding instead: SNP `HOST_DATA` set by the launcher at `SNP_LAUNCH_FINISH`, a TDX `RTMR[3]` extend before workload code runs, and PCR15 on AWS Nitro. The SDK does not implement those profiles yet. An `attestation` block produced by these providers therefore does not meet the section 3.3.1 profile, and a verifier that expects `HOST_DATA` or `RTMR[3]` will not find the digest there. The runtime freshness binding in section 3.3.2 is separate and does not carry the manifest digest: the context object it hashes holds the policy bundle, system prompt, and tool catalog hashes, not the manifest.

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

A provider name does not establish a conformance level or regulatory compliance. Apply the [specification's conformance requirements](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/index.md), including artifact coverage, signature profile, required evidence, and recipient policy. Hardware appraisal and application authorization remain separate checks.

Pass independently appraised evidence into the verifier's context, bound to the exact manifest. Then require the full manifest result to be `VALID`; a successful hardware check cannot override a bad signature, expired record, revocation, or artifact mismatch. Continue with [server-side verification](https://manifest.agentrust-io.com/tutorials/server-side-verification/index.md).
