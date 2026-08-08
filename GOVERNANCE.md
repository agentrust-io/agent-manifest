# Governance

## Roles

### Contributor

Anyone who submits a PR, files an issue, or participates in discussion. No formal appointment required. Must follow the [Code of Conduct](CODE_OF_CONDUCT.md) and sign commits with DCO.

### Reviewer

Trusted contributors with triage and review rights. Can approve PRs but cannot merge without a Maintainer approval on security-sensitive paths. See [CODEOWNERS](.github/CODEOWNERS) for path-specific rules.

**Advancement**: 3+ merged substantive PRs. Nominated by any Maintainer, confirmed by Project Lead.

### Maintainer

Full commit and merge rights on designated package areas. PyPI publish rights on `agent-manifest`. Responsible for reviewing PRs within their area within 5 business days.

**Advancement**: Active Reviewer for 60+ days, 5+ merged PRs, demonstrated judgment on design questions. Nominated by any Maintainer, confirmed by Project Lead.

### Project Lead

Final decision authority on specification changes, standards contribution scope, conformance test disputes, and Maintainer appointments. Currently: Imran Siddique (OPAQUE Systems).

**Succession**: If the Project Lead is unavailable for 30+ days without notice, the active Maintainers vote to appoint an interim lead. Succession plan will be formalized before v1.0 contribution to CoSAI with a Technical Steering Committee structure.

## Decision-making

**Routine changes** (bug fixes, doc improvements, SDK additions that do not affect the spec): Maintainer review + merge.

**Spec changes** (normative text, field additions, conformance level changes): Requires an open issue with 5 business days of comment period, no unresolved objections from Maintainers, and Project Lead approval.

**Breaking spec changes** (backward-incompatible field removals, conformance level redefinition, cryptographic protocol changes): Requires a formal RFC issue, 14-day comment period, explicit sign-off from Project Lead, and update to the conformance test suite before merge.

**Voting**: If consensus cannot be reached, Maintainers vote. Simple majority decides routine changes; two-thirds majority required for breaking spec changes. The Project Lead has a tie-breaking vote.

## Who may author normative text

Normative text is any statement using an RFC 2119 keyword in uppercase: what a conformant implementation MUST, SHOULD or MAY do. A normative change binds every implementation of Agent Manifest, including implementations whose authors are not in the discussion.

**Normative spec changes require an organizational sponsor.** The sponsor is an organization that implements Agent Manifest, or produces the attestation platform the change concerns, and is willing to be named as accountable for the requirement in the PR. In practice that has meant silicon and cloud attestation vendors, platform and framework implementers, and standards bodies carrying the work forward. Reviewers confirm the sponsorship, not the individual's competence.

The reason is maintenance cost, not merit. A MUST is a promise the project keeps for every future version. Evaluating whether it can be implemented, at what cost, across which platforms, needs an organization that will actually implement it and answer for it later. Individual authorship gives the project no way to make that assessment and no one to return to when the requirement proves wrong.

**Anyone may propose a normative change.** Open a Spec change proposal issue. Proposals are evaluated on the technical argument alone. If one is accepted without a sponsor, a Maintainer carries the normative PR and the proposer is credited in the CHANGELOG entry. This is a question of who signs the requirement, not whose idea it was.

**No sponsor is required for** bug fixes, SDK work, examples, conformance tests, tooling, schema changes tracking an already-merged spec change, and informative additions such as crosswalks and mappings to external schemas. Informative text carries no RFC 2119 keywords and binds no implementation, so it is the right home for a mapping that is still settling: an OCSF or OpenTelemetry field correspondence is useful as guidance long before anyone should be required to follow it. Most contributions are in this set.

A normative PR opened without a sponsor is not rejected on that basis. Reviewers will say so on the PR and either identify a sponsor or convert it to an informative change.

## Conflict of interest

Maintainers must disclose any commercial interest in a proposal before participating in its review. Disclosed conflicts do not disqualify a Maintainer from voting but must be on the record.

## Foundation transition

This project is targeting contribution to CoSAI Working Stream 4, an OASIS Open Project. On acceptance, governance will transition to a TSC structure defined in [CHARTER.md](CHARTER.md). Until then, this document is the governance authority.

## Amendments

Amendments to this document require a PR, 14-day comment period, and Project Lead approval.
