# 0012. Move the `@context` URI to a domain we control

- Status: Accepted
- Date: 2026-08-01
- Supersedes the provisional `@context` URL introduced with the v0.1 draft

## Context

Every Agent Manifest carries a JSON-LD `@context`. Through v0.1 that value was:

```
https://agentmanifest.agentrust.io/v0.1/context.json
```

The authority component of that URL, `agentrust.io`, is **not a domain this project
has ever controlled**. Verified 2026-08-01: it is registered to a third party through
GoDaddy behind Domains By Proxy, registered 2025-06-09 and paid through 2027-06-09. It
serves a parked lander and has no MX or TXT records. It is absent from both the Opaque
GoDaddy and Cloudflare accounts. The only acquisition route offered is a $99.99
non-refundable broker approach to an anonymous owner.

Two consequences follow, and only the first is cosmetic:

1. The context URL has never resolved, so no consumer has ever been able to dereference
   it. JSON-LD tolerates this, but a `@context` that cannot be fetched is a latent defect
   in an identity specification.
2. More seriously, every manifest we have issued is **named under a domain belonging to
   somebody else**. If that owner ever serves content at the path, they control the
   semantics of documents that claim to be Agent Manifests. For a specification whose
   entire purpose is establishing who an agent is and who vouched for it, an identifier
   we do not control is a contradiction.

This is the same defect that TRACE resolved in its v0.2 profile migration
(`agentrust-io/trace-spec#107`), where the tag URI `tag:agentrust.io,2026:trace-v0.1`
was found to be invalid under RFC 4151 for exactly this reason. That migration set the
precedent this ADR follows.

## Decision

The `@context` URI becomes:

```
https://manifest.agentrust-io.com/v0.2/context.json
```

`agentrust-io.com` is registered to Opaque at Cloudflare and `manifest.agentrust-io.com`
already serves the Agent Manifest documentation.

**The version is bumped to v0.2 and consumers cut over. They do not dual-accept.** The
v0.1 URL is withdrawn and MUST NOT be accepted. This mirrors TRACE, and the reasoning is
the same: an implementation that continued honouring the v0.1 URL would keep validating
manifests named under a domain we do not own, which is precisely the condition being
fixed. A permissive migration would leave the defect in place indefinitely.

**The manifest format itself does not change.** No field is added, removed or
re-typed. v0.2 differs from v0.1 in the `@context` value alone. The version bump exists
to force the cut-over, not to signal a schema change.

## Consequences

- Breaking for any consumer pinning the v0.1 context URL. This requires a coordinated
  SDK release, as TRACE did across `agentrust-trace` and `agentrust-trace-tests`.
- Manifests already issued under v0.1 remain checkable against the v0.1 specification,
  which stays published.
- The AAIF handover commitment is unchanged. The spec still states that the working group
  will assign the canonical URL before v1.0 ratification, and that
  `manifest.agentrust-io.com` transfers to AAIF-controlled infrastructure as a condition
  of v1.0 acceptance. This decision changes which provisional domain we hand over, not
  whether we hand it over.
- The new URL does not resolve yet either. Serving the context document at
  `manifest.agentrust-io.com/v0.2/context.json` is follow-up work and should be tracked
  separately. The difference that matters now is that we can serve it whenever we choose,
  because the domain is ours.

## Alternatives considered

**Swap the host, stay at v0.1.** Smallest change, but it lets old and new identifiers
coexist, so nothing forces consumers off an identifier naming a third party's domain.
Rejected for the same reason TRACE rejected dual-acceptance.

**Buy `agentrust.io`.** $99.99 non-refundable to open a negotiation with an anonymous
owner who registered the name deliberately and has paid through mid-2027, with no
guarantee of sale and no ceiling on price. Rejected as poor value against a rename that
costs nothing.

**Wait for the AAIF namespace.** Leaves a known-defective identifier live in a published,
widely-starred repository for an unbounded period, since ratification has no date.
Rejected.
