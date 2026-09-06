# cMCP session binding

Connect a signed manifest to the policy bundle and tool catalog loaded by a cMCP gateway. This guide explains the configuration and evidence boundaries; use the [cMCP quickstart](https://cmcp.agentrust-io.com/docs/quickstart/) to run the gateway first.

## Configure the binding

Add this fragment to your complete cMCP configuration, replacing the paths and subject with your approved values:

```yaml
agent_manifest:
  path: /etc/agent/signed-agent-manifest.json
  trust_anchor_path: /etc/agent/issuer-public-key.json
  authenticated_subject: spiffe://example.test/agent/summarizer
```

Start the gateway with its configuration:

```bash
cmcp start --config cmcp-config.yaml
```

The current configuration uses `agent_manifest.path` and `agent_manifest.trust_anchor_path` together. `CMCP_AGENT_MANIFEST_PATH` is not the configuration mechanism, and there is no `cmcp-gateway start` command in this package. Obtain issuer public keys independently from the signed manifest; follow the [cMCP binding implementation](https://github.com/agentrust-io/cmcp/blob/main/src/cmcp_runtime/agent_manifest.py) for accepted trust-anchor file formats.

The manifest must bind the gateway's policy bundle and tool catalog. The general first-manifest example binds different demo artifacts and cannot be used unchanged as a gateway manifest. Issue the manifest for the actual gateway inputs and configure the matching enforcement mode.

## Understand when binding is required

The default profile permits startup without a manifest binding. If both configured paths are present, loading or verification failure aborts startup. Supplying only one path is a configuration error. The `aarm` conformance profile requires the binding configuration; selecting that profile also carries other requirements and is not a shortcut to conformance.

An absent manifest therefore does not universally block a default gateway. Deployments that require identity binding must enforce that requirement in their configuration and deployment policy.

## What startup checks

| Check | Inputs and boundary |
|-------|---------------------|
| Signature and validity | Verify the signed JSON document or COSE envelope using the configured issuer keys; reject expired or unacceptable results. Preserve COSE envelope bytes for verification. |
| Policy and tool bindings | Compare the manifest's policy hash and catalog hash with the loaded gateway values. These bindings are required by the cMCP helper. |
| Enforcement mode | Compare the running mode with the manifest declaration, mapping cMCP `enforcing`, `advisory`, and `silent` to Manifest `enforce`, `advisory`, and `audit-only`. |
| Subject match | Compare `agent_id` with the supplied subject. The startup path supplies the configured subject; it does not automatically establish that the connecting peer presented that identity. |

In development mode, the helper can fall back to the manifest's own `agent_id` and mark the source `manifest-dev`. A configured subject is marked `config`. Neither source proves live caller authentication. The binding helper also supports `svid` as a source, but a supported label alone is not evidence that a particular startup path authenticated an SVID.

The current SDK call in the binding helper uses an empty `RevocationStore`. Do not assume publishing a Manifest CRL automatically prevents the gateway from opening a new session. Revocation distribution and enforcement require an explicit integration.

## Read the resulting evidence

The session claim contains a nested `gateway.agent_identity` object when a binding is present. Its core fields are:

| Field | Meaning |
|-------|---------|
| `manifest_id` | The bound manifest's identifier. |
| `agent_id` | The manifest's declared agent identity. |
| `authenticated_subject`, `subject_source` | The compared subject and where it came from; inspect both. |
| `issuer`, `issuer_key_id` | The issuer declaration and signing-key reference. |
| `policy_bundle_hash`, `tool_catalog_hash` | The bound configuration digests. |
| `enforcement_mode` | The checked gateway mode when supplied. |

The object can also carry an intent hash and agent-key thumbprint when supported and populated. The current session producer does not populate agent-key bytes into the binding, so do not infer a live agent-key binding from field availability. The model has no `gateway.manifest_verified_at` or `gateway.manifest_expires_at` fields.

Downstream systems must authenticate the claim, appraise its evidence, and apply their trust and authorization policy. Reading `agent_id` from an unauthenticated object is not a substitute. When verifying against the original manifest, supply that signed document and independently trusted issuer keys to the cMCP verifier.

## What to enforce after startup

Startup binding establishes a relationship among the checked document and supplied gateway inputs at that point. It does not establish that a human reviewed them, that policies are correct, or that later agent behavior is safe.

Treat later policy updates, tool-catalog changes, expiry, revocation, and caller identity as explicit runtime policy concerns. cMCP has separate catalog and session controls; consult its current behavior rather than assuming this startup helper continuously re-verifies the manifest. The helper provides no forward-secrecy guarantee.

For issuing documents, start with [your first manifest](../getting-started.md) and [CI signing](ci-cd-signing.md). For recipient-side checks and rejection handling, see [server-side verification](server-side-verification.md).
