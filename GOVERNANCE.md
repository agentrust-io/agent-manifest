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

Final decision authority on specification changes, AAIF submission scope, conformance test disputes, and Maintainer appointments. Currently: Imran Siddique (OPAQUE Systems).

**Succession**: If the Project Lead is unavailable for 30+ days without notice, the active Maintainers vote to appoint an interim lead. Succession plan will be formalized before AAIF v1.0 submission with a Technical Steering Committee structure.

## Decision-making

**Routine changes** (bug fixes, doc improvements, SDK additions that do not affect the spec): Maintainer review + merge.

**Spec changes** (normative text, field additions, conformance level changes): Requires an open issue with 5 business days of comment period, no unresolved objections from Maintainers, and Project Lead approval.

**Breaking spec changes** (backward-incompatible field removals, conformance level redefinition, cryptographic protocol changes): Requires a formal RFC issue, 14-day comment period, explicit sign-off from Project Lead, and update to the conformance test suite before merge.

**Voting**: If consensus cannot be reached, Maintainers vote. Simple majority decides routine changes; two-thirds majority required for breaking spec changes. The Project Lead has a tie-breaking vote.

## Conflict of interest

Maintainers must disclose any commercial interest in a proposal before participating in its review. Disclosed conflicts do not disqualify a Maintainer from voting but must be on the record.

## Foundation transition

This project is targeting donation to the Agentic AI Foundation (AAIF) under the Linux Foundation alongside the Agent Governance Toolkit. On acceptance, governance will transition to a TSC structure defined in [CHARTER.md](CHARTER.md) (to be added before AAIF submission). Until then, this document is the governance authority.

## Amendments

Amendments to this document require a PR, 14-day comment period, and Project Lead approval.
