# Technical Charter — Agent Manifest

**Proposed donation target**: Agentic AI Foundation (AAIF) under the Linux Foundation  
**Status**: Pre-donation draft — effective upon AAIF acceptance  
**Version**: 0.1 (aligned with spec v0.1)

---

## 1. Mission

The Agent Manifest project develops and maintains an open cryptographic specification and reference implementation for establishing verifiable identity and provenance of autonomous AI agents. The mission is to make it structurally impossible — not merely difficult — for a verifying party to be deceived about which agent is running, what it is authorized to do, how it was built, and what human oversight has been applied.

## 2. Scope

The project includes:

- **The Agent Manifest Specification** — normative text defining the data model, cryptographic binding protocol, hardware attestation integration, verification API, and conformance requirements.
- **Reference implementations** — SDKs in Python (primary), with additional language SDKs added as the community grows.
- **Conformance test suite** — the canonical test suite validating compliance with the specification.
- **Supporting tools** — CLI tooling, verification server, and integration examples.

Out of scope: runtime policy enforcement (see Agent Governance Toolkit), MCP protocol extensions beyond manifest presentation (see cMCP), and hardware TEE platform SDKs.

## 3. Technical Steering Committee

Upon AAIF acceptance, governance transitions from the current single-maintainer model to a Technical Steering Committee (TSC).

**Composition**: 3–7 members. No single organization may hold more than 40% of TSC seats. The founding Project Lead (Imran Siddique, Opaque Systems) holds one permanent founding seat for the v1.0 ratification cycle, after which all seats are elected.

**Election**: TSC members are elected annually by active contributors (defined as: at least one merged PR or accepted spec change in the preceding 12 months). Each contributor has one vote.

**Quorum**: Two-thirds of TSC members must participate for a vote to be valid.

**Decisions**:
- Routine (spec errata, patch releases): simple TSC majority
- Minor spec versions (new optional fields, new conformance levels): two-thirds TSC majority + 14-day public comment period
- Major spec versions (breaking changes, new mandatory fields): two-thirds TSC majority + 30-day public comment period + explicit backward-compatibility statement

**Meetings**: Monthly public TSC meeting. Notes published within 5 business days.

## 4. Intellectual Property Policy

All contributions to the project must be made under the Apache License, Version 2.0. Contributors must sign off commits with the Developer Certificate of Origin (DCO). A Contributor License Agreement (CLA) may be required before AAIF acceptance if the foundation's IP policy requires it — contributors will be notified before any CLA requirement takes effect.

No contribution may incorporate material covered by a patent the contributor is unwilling to license royalty-free to all implementations of the specification.

The specification itself is licensed under CC-BY-4.0 to maximize adoption across implementations in any language or platform.

## 5. Trademark Policy

"Agent Manifest" as a specification name and the agentrust-io GitHub organization name are currently held by the founding maintainer. Upon AAIF acceptance, trademark ownership transfers to AAIF/Linux Foundation under their standard trademark policy. Until transfer, use of the name "Agent Manifest" to describe a conformant implementation is permitted without restriction. Use to describe a non-conformant implementation is not permitted.

## 6. Conformance

Implementations may claim conformance with the Agent Manifest Specification only if they pass the published conformance test suite for the version being claimed. Conformance claims must specify the test suite version and must include a link to a passing test run.

The TSC maintains the conformance test suite. Test suite changes that would invalidate previously passing implementations require a minor or major spec version increment.

## 7. Relationship to Other Standards

This project is designed to compose with, not replace:

- **SPIFFE/SPIRE** — agent identity uses SPIFFE SVIDs
- **SLSA** — supply chain provenance uses SLSA attestation format
- **CycloneDX / SPDX** — SBOM references use these formats
- **MCP** — the reference implementation uses MCP for agent-to-tool communication
- **AGT / Cedar** — policy bundle hashes reference AGT-formatted Cedar bundles
- **Sigstore / Rekor** — transparency log references use Rekor entry IDs

## 8. Amendments

Amendments to this charter require a two-thirds TSC majority and a 30-day public comment period. Before AAIF acceptance, amendments require Project Lead approval and 14-day notice to contributors.

## 9. Foundation Transition

This project is targeting donation to the Agentic AI Foundation (AAIF) alongside the Agent Governance Toolkit. The transition timeline:

| Milestone | Target |
|-----------|--------|
| v0.1 developer preview | June 2026 |
| AAIF working group formation | Q3 2026 |
| AAIF submission (spec + conformance suite) | September 2026 |
| v1.0 ratification under AAIF governance | 2027 |

Until AAIF acceptance, this charter describes the intended governance. The GOVERNANCE.md file describes the current operating governance.
