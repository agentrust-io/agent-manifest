# ADR-0015: Agent Plugins manifest reference

**Status:** Accepted

**Date:** 2026-08-16

**Deciders:** Agent Manifest maintainers

## Context

Agent Plugins 1.0.0 has no provenance field, but permits client-specific objects under
reverse-domain keys in `plugin.json.extensions`. A bundle needs to locate a signed Agent Manifest
without implying that a URL or a key named by the plugin is itself trustworthy.

A whole-bundle digest placed inside `plugin.json` is recursive: adding the digest changes the file
being digested. Ignoring all extensions would avoid recursion but would also leave unrelated
client hooks and settings outside the package binding.

## Decision

Use `com.agentrust-io.manifest`, derived from the controlled `agentrust-io.com` domain. The object
contains only an HTTPS `manifest_uri` and the SHA-256 digest of the fetched manifest bytes.

The signed manifest carries `source_bundle` with format `agent-plugins-1.0.0` and a bundle digest.
That digest covers every regular file and every path, but canonicalizes `plugin.json` after
removing only `extensions.com.agentrust-io.manifest`. If no other extension remains, the empty
`extensions` member is also removed. This makes the digest stable before and after adding the
reference without excluding unrelated extension data.

Trust keys are configured independently by the verifier. A key identifier in the manifest helps
select a configured key; it never creates trust.

## Options considered

### Put the bundle digest in its own `plugin.json` extension

Rejected because the value would include itself. Fixed-point hashing is not a practical package
format and excluding the entire extension object would leave other client data unbound.

### Bind only `skills/*/SKILL.md`

Rejected because scripts, MCP declarations, and unrecognized extension files can change behavior.
The existing adapter deliberately hashes files it does not understand for this reason.

### Include a signing key in the extension

Rejected because a package cannot bootstrap trust in its own signer. It would turn signature
verification into integrity without provenance.

## Consequences

- A plugin can point to a signed manifest without changing the upstream 1.0.0 schema.
- Bundle mutation and fetched-manifest substitution are independently detectable.
- Callers must provide fetch policy and trusted keys out of band.
- A future upstream provenance field may supersede the namespace, but the signed source-bundle
  binding remains reusable.
