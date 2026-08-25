# Technical Charter — Agent Manifest

**Proposed contribution target**: Coalition for Secure AI (CoSAI), Working Stream 4, an OASIS Open Project  
**Status**: Pre-contribution draft, effective upon CoSAI WS4 acceptance. Phase 1 review is open in [WS4 issue #149](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149); no contribution has been proposed yet.  
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

Upon CoSAI WS4 acceptance, governance transitions from the current single-maintainer model to a Technical Steering Committee (TSC), aligned with the OASIS Open Projects governance model.

**Composition**: 3–7 members. No single organization may hold more than 40% of TSC seats. The founding Project Lead (Imran Siddique) holds one permanent founding seat for the v1.0 ratification cycle, after which all seats are elected.

**Election**: TSC members are elected annually by active contributors (defined as: at least one merged PR or accepted spec change in the preceding 12 months). Each contributor has one vote.

**Quorum**: Two-thirds of TSC members must participate for a vote to be valid.

**Decisions**:
- Routine (spec errata, patch releases): simple TSC majority
- Minor spec versions (new optional fields, new conformance levels): two-thirds TSC majority + 14-day public comment period
- Major spec versions (breaking changes, new mandatory fields): two-thirds TSC majority + 30-day public comment period + explicit backward-compatibility statement

**Meetings**: Monthly public TSC meeting. Notes published within 5 business days.

## 4. Intellectual Property Policy

All contributions to the project must be made under the Apache License, Version 2.0. Contributors must sign off commits with the Developer Certificate of Origin (DCO).

The specification itself is licensed under CC-BY-4.0 to maximize adoption across implementations in any language or platform.

No contribution may incorporate material covered by a patent the contributor is unwilling to license royalty-free to all implementations of the specification.

**Consequences of the CoSAI target, not yet in effect.** The OASIS Open Projects IPR Policy that governs CoSAI requires contributors to sign a Contributor License Agreement and, for non-trivial contributions, a patent non-assert, releasing source code under Apache-2.0 and documentation and data under CC-BY-4.0. That is a stricter regime than DCO alone. It takes effect for this project only if and when WS4 accepts a contribution, and contributors will be notified before any CLA requirement applies. The founding maintainer's own participation terms under that policy, including how the non-assert interacts with existing Opaque patent filings, require counsel sign-off before any contribution is filed.

## 5. Trademark Policy

"Agent Manifest" as a specification name and the agentrust-io GitHub organization name are currently held by the founding maintainer. Upon CoSAI WS4 acceptance, name and mark ownership transfer on the terms set by the OASIS Open Projects policy; the specific terms are to be determined with counsel before a contribution is filed and are not asserted here. Until transfer, use of the name "Agent Manifest" to describe a conformant implementation is permitted without restriction. Use to describe a non-conformant implementation is not permitted.

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

Amendments to this charter require a two-thirds TSC majority and a 30-day public comment period. Before CoSAI WS4 acceptance, amendments require Project Lead approval and 14-day notice to contributors.

## 9. Standards Body Transition

This project is targeting contribution to CoSAI Working Stream 4 (Secure Design Patterns for Agentic Systems), an OASIS Open Project. The timeline:

| Milestone | Target |
|-----------|--------|
| v0.1 developer preview | June 2026 |
| WS4 Phase 1 review (RFC open, feedback collection) | July to August 9, 2026 |
| Revised spec returned to WS4 with review dispositions | August 2026 |
| WS4 decision on formal contribution | Q4 2026 |
| v1.0 ratification under CoSAI governance | 2027 |

Phase 1 is a review pass, not a request to accept. Until WS4 accepts a contribution, this charter describes the intended governance and the GOVERNANCE.md file describes the current operating governance.

The Agent Governance Toolkit is governed separately and its own standards destination is not set by this charter.

## 10. Sponsors

Organizations providing financial, engineering, infrastructure, or other material support are recognized in [SPONSORS.md](SPONSORS.md). Sponsorship is separate from project governance and does not confer specification authority, additional voting rights, preferential conformance treatment, or endorsement of a sponsor's implementation.
