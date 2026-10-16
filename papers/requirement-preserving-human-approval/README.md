# Requirement-Preserving Human Approvals for Signed Agent Manifests

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `cd requirement-preserving-human-approval && tectonic paper.tex` (prepared with Tectonic 0.16.9; set
SOURCE_DATE_EPOCH=1790812800 to reproduce the published PDF byte for byte). The fonts and their OFL
licenses are in `_paper-assets/fonts/`, the same relative path the manuscript uses.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/agent-manifest.

This package contains the manuscript source, the experiment runner and probes, and the records
of the September 27 and October 1, 2026 reruns. At the pinned Agent Manifest revision, 74
signing and delegation/HITL tests passed. The probes were also run against two later revisions,
the last being main on October 1, 2026. Rerun with:

    cd requirement-preserving-human-approval/experiments
    python reproduce.py --prepare-from CLONES --source-root EMPTY_DIR --output OUT
    python boundary_probes.py --source-root EMPTY_DIR --output OUT

`CLONES` holds clones of agentrust-telemetry, weight-custody-manifest and agent-manifest. The
runner extracts each pinned commit with `git archive` and refuses any other revision.

Software only. No hardware authenticator ceremony, external identity provider, enrolled human
approver or protected action execution was exercised.
Current implementation guidance: https://manifest.agentrust-io.com/
