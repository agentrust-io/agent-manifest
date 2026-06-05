# AGT (Agent Governance Toolkit) integration

Agent-manifest and AGT (Agent Governance Toolkit) are complementary layers of an agent governance stack. This guide explains how they fit together and shows the integration points.

## How they divide the problem

| Concern | agent-manifest | AGT |
|---------|---------------|-----|
| **Who is this agent?** | SPIFFE identity, signed manifest | — |
| **What has it been bound to?** | Artifact hashes (model, prompt, tools) | — |
| **Is it attested?** | TPM / SEV-SNP / TDX / OPAQUE | — |
| **Can it be trusted right now?** | Revocation check, expiry | Trust score (time-decayed, context-sensitive) |
| **What can it do?** | Delegation chain scope | Policy engine (YAML, structural typing) |
| **What has it done?** | Merkle audit chain root | Observability, GovernanceEventSink |
| **What happens if it goes wrong?** | Revoke the manifest | Recovery ring, kill-switch |

Agent-manifest answers the **identity and provenance** question. AGT answers the **policy and observability** question. Together they cover the full governance stack.

---

## Integration point 1: Attestation level → AGT trust score

AGT's trust score is a time-decayed real number (0.0–1.0) per agent. Feed the manifest's attestation level into the trust score calculation so hardware-attested agents start with a higher baseline than software-only agents.

```python
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore, OverallResult
from agt.trust import TrustScoreEngine, AttestationEvidence   # AGT SDK

REVOCATION_STORE = RevocationStore()
trust_engine = TrustScoreEngine()

def compute_initial_trust(manifest: dict) -> float:
    """Compute the starting trust score based on manifest attestation."""
    result = verify_manifest(manifest, VerificationContext(), REVOCATION_STORE)

    if result.result != OverallResult.VALID:
        return 0.0    # revoked or expired → no trust

    attestation = manifest.get("attestation") or {}
    level = attestation.get("level", 0)

    # Map attestation level to initial trust score
    level_to_score = {0: 0.40, 1: 0.65, 2: 0.85, 3: 0.95}
    base_score = level_to_score.get(level, 0.40)

    evidence = AttestationEvidence(
        manifest_id=manifest["manifest_id"],
        attestation_level=level,
        manifest_hash=attestation.get("manifest_hash"),
    )
    return trust_engine.initialise(manifest["agent_id"], base_score, evidence)
```

---

## Integration point 2: Delegation chain → AGT scope-narrowing policy

AGT's policy engine enforces what an agent is allowed to do. Use the manifest's delegation chain as the input scope for AGT policy evaluation — the delegation chain proves what scope the issuer actually granted, which the policy engine can compare against what the agent is trying to do.

```python
from agt.policy import PolicyEngine, EvaluationContext   # AGT SDK

policy_engine = PolicyEngine.from_yaml("policies/agent-policies.yaml")

def evaluate_action(
    manifest: dict,
    requested_action: str,
    requested_data_class: str,
) -> bool:
    """Return True if the agent's delegation scope permits the action."""
    chain = manifest.get("delegation_chain") or []

    # The effective scope is the innermost hop's grant
    effective_scope = chain[-1]["scope_grant"] if chain else {
        "tools": [],           # no delegation = no scope
        "data_classifications": [],
    }

    ctx = EvaluationContext(
        agent_id=manifest["agent_id"],
        manifest_id=manifest["manifest_id"],
        granted_tools=effective_scope.get("tools", []),
        granted_data_classes=effective_scope.get("data_classifications", []),
        attestation_level=manifest.get("attestation", {}).get("level", 0),
    )

    return policy_engine.allows(ctx, action=requested_action, data_class=requested_data_class)
```

Example `policies/agent-policies.yaml`:
```yaml
rules:
  - id: require-level-2-for-pii
    description: Agents accessing PII must be Level 2+ attested
    condition:
      data_class: pii
    require:
      attestation_level: ">= 2"

  - id: payment-tool-requires-hitl
    description: Agents using execute_payment must have HITL approval
    condition:
      tool: execute_payment
    require:
      hitl_approved: true
```

---

## Integration point 3: Manifest audit chain root → AGT GovernanceEventSink

AGT's `GovernanceEventSink` is a pluggable event stream for governance events. Emit a `ManifestVerified` event whenever an agent presents its manifest so AGT can incorporate it into the observability pipeline.

```python
from agt.events import GovernanceEventSink, ManifestVerifiedEvent   # AGT SDK
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore

sink = GovernanceEventSink.connect("grpc://agt-sink.internal:4317")
revocation_store = RevocationStore()

def verify_and_emit(manifest: dict) -> bool:
    """Verify a manifest and emit a governance event. Returns True if valid."""
    result = verify_manifest(manifest, VerificationContext(), revocation_store)

    event = ManifestVerifiedEvent(
        manifest_id=manifest["manifest_id"],
        agent_id=manifest["agent_id"],
        issuer=manifest["issuer"],
        attestation_level=manifest.get("attestation", {}).get("level", 0),
        result=result.result.value,
        verification_id=result.verification_id,
        audit_chain_root=manifest.get("artifacts", {})
                                  .get("decision_trace", {})
                                  .get("audit_chain_root"),
    )
    sink.emit(event)

    return result.result.value == "VALID"
```

AGT can then apply trust score decay, trigger recovery rings, or fire alerts based on `ManifestVerifiedEvent` patterns (e.g., repeated `MISMATCH` results from the same agent).

---

## Integration point 4: Revocation → AGT kill-switch

When AGT's policy engine determines that an agent's trust score has fallen below a threshold, trigger the agent-manifest revocation flow automatically.

```python
from agent_manifest._revocation import sign_revocation, FileCRL
from agent_manifest import generate_ed25519
from pathlib import Path

REVOCATION_KP = generate_ed25519()   # load from secrets manager in production
CRL = FileCRL(Path("crl.jsonl"))

def agt_kill_switch_handler(agent_id: str, manifest_id: str, reason: str) -> None:
    """Called by AGT when trust score drops below threshold."""
    record = sign_revocation(
        manifest_id=manifest_id,
        reason=f"AGT kill-switch: {reason}",
        revoked_by="agt-policy-engine@trust.example",
        keypair=REVOCATION_KP,
    )
    CRL.revoke(record)
    # The CRL endpoint now returns 200 for this manifest_id
    # All verifiers checking the CRL will reject future requests from this agent
```

Wire this into AGT's kill-switch SPI:

```yaml
# agt-config.yaml
kill_switch:
  handler: mymodule.agt_kill_switch_handler
  trust_threshold: 0.20   # trigger revocation below 20% trust
```

---

## Recommended deployment architecture

```
Agent process
  │  manifest_id header
  ▼
Verification sidecar (agent-manifest)
  │  verify_manifest() → VerificationResult
  │  emit ManifestVerifiedEvent → GovernanceEventSink
  ▼
AGT policy engine
  │  evaluate_action() → allow/deny
  │  trust score update (time-decayed)
  ▼
Service handler
```

The verification sidecar and AGT policy engine run as a single fast path: the combined latency target is <10 ms at p99.

---

## What's next

- [Tutorial: Server-side verification](../tutorials/server-side-verification.md) — the verification sidecar in detail
- [Tutorial: Revocation and key rotation](../tutorials/revocation.md) — manual revocation flow complementing AGT kill-switch
- [AGT documentation](https://github.com/microsoft/agent-governance-toolkit) — full AGT reference
