# cMCP Session Binding

By the end of this tutorial you will understand how cMCP (PR #323) binds a signed Agent Manifest to a session at startup, what checks it performs, and what the Trust Record carries as a result.

## What you'll learn

- What `CMCP_AGENT_MANIFEST_PATH` does and when to set it
- Which fields cMCP verifies at startup against the running agent
- What the Trust Record carries from a successful manifest bind
- What session binding proves and what it does not prove

## Prerequisites

```bash
pip install agent-manifest
```

You also need a cMCP gateway with PR #323 applied (session binding support).

---

## What cMCP PR #323 does

cMCP PR #323 adds agent manifest session binding to the gateway startup sequence. When the env var `CMCP_AGENT_MANIFEST_PATH` points to a signed manifest, cMCP loads that manifest and verifies three things before the session opens:

1. The manifest's cryptographic signature is valid against a configured trusted key.
2. `manifest.agent_id` matches the authenticated agent subject from the session credentials.
3. Artifact hashes in the manifest match the hashes of the artifacts actually loaded by the gateway.

If any check fails, the session is rejected before any tool calls can be made. This is fail-closed: an absent or invalid manifest blocks the session rather than allowing it to proceed unverified.

---

## Point cMCP at your signed manifest

Set `CMCP_AGENT_MANIFEST_PATH` to the path of your signed `agent-manifest.json` before starting the gateway:

```bash
export CMCP_AGENT_MANIFEST_PATH=/etc/agent/signed-agent-manifest.json
cmcp-gateway start
```

Or in a docker-compose service definition:

```yaml
services:
  cmcp-gateway:
    image: cmcp-gateway:latest
    environment:
      CMCP_AGENT_MANIFEST_PATH: /etc/agent/signed-agent-manifest.json
    volumes:
      - ./signed-agent-manifest.json:/etc/agent/signed-agent-manifest.json:ro
```

The manifest file must be readable by the gateway process. It does not need to be writable - the gateway only reads it at startup.

---

## What cMCP verifies at startup

cMCP calls `verify_manifest()` from the agent-manifest SDK. The verification context is constructed from the gateway's own runtime state:

```python
# Illustrative - this runs inside the cMCP gateway, not in your code
from agent_manifest import verify_manifest, VerificationContext, RevocationStore

ctx = VerificationContext(
    trusted_keys={configured_key_id: configured_public_key_b64url},
    policy_bundle_hash=loaded_policy_bundle_hash,
    tool_catalog_hash=loaded_tool_catalog_hash,
)

result = verify_manifest(manifest_dict, ctx, RevocationStore())
```

The three checks that must all pass:

**Signature verification.** The `signature` block in the manifest must verify against the trusted key configured in the gateway. Without a valid signature, `result.result` is `UNVERIFIABLE` or `SIGNATURE_MISSING` and the session is rejected.

**Agent identity match.** cMCP reads `manifest.agent_id` from the verified manifest and compares it to the authenticated agent subject from the session's SPIFFE SVID or mTLS certificate. A mismatch means the manifest was signed for a different agent and the session is rejected.

**Artifact hash match.** If the manifest binds a `policy_bundle` hash, cMCP computes the SHA-256 of the loaded policy bundle and compares it to `manifest.artifacts.policy_bundle.hash`. Likewise for `tool_manifest.catalog_hash` and the loaded tool catalog. A mismatch means the running artifacts differ from those reviewed at manifest issue time.

---

## The Trust Record after successful binding

On a successful bind, cMCP writes a Trust Record for the session. The Trust Record includes:

```json
{
  "gateway.agent_identity": "spiffe://trust.example/agent/my-agent/prod",
  "gateway.manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
  "gateway.manifest_verified_at": "2026-06-21T09:00:00Z",
  "gateway.manifest_expires_at": "2026-06-22T09:00:00Z"
}
```

`gateway.agent_identity` is taken directly from `manifest.agent_id` in the verified manifest. Downstream systems that receive the Trust Record can use this field to identify the agent and look up its authorisations without re-verifying the manifest.

---

## What session binding proves

Session binding gives you a cryptographic guarantee that:

- The agent connecting to the session is the same agent named in the manifest (`agent_id` match).
- The policy bundle and tool catalog loaded by the gateway are the same artifacts that were reviewed when the manifest was issued (hash matches).
- The manifest itself has not been tampered with since it was signed (signature verification).

---

## What session binding does not prove

Session binding is a startup-time check. It does not provide:

- **Continuous runtime integrity.** If the policy bundle or tool catalog is replaced after the session opens, the manifest hashes are no longer valid - but the session is already open. Use a watchdog process or periodic re-verification to detect drift.
- **Behavioral correctness.** The manifest records what tools and policies were loaded. It does not record what the agent does with them during the session. Use decision traces and audit logs for behavioral accountability.
- **Forward secrecy.** If the signing key is compromised after session binding, the Trust Record is still valid for that session. Revoke the manifest to prevent new sessions from opening.

---

## Summary

Setting `CMCP_AGENT_MANIFEST_PATH` causes cMCP to call `verify_manifest()` at gateway startup and reject the session if the signature, agent identity, or artifact hashes do not match. The Trust Record carries `gateway.agent_identity` from the verified manifest, giving downstream systems a cryptographically-backed identity claim. Session binding proves the agent was authorised against the reviewed manifest; it does not prove agent behavior during the session. For signing the manifest, see [Your first manifest](your-first-manifest.md) and [CI/CD signing](ci-cd-signing.md). For revocation if a key is compromised, see [Revocation and key rotation](revocation-and-key-rotation.md).
