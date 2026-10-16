# Agent Manifest: Portable, Hardware-Attestable Identity and Provenance for AI Agents

Technical report, version 2, October 1, 2026. Not peer reviewed. Patent Pending.
Version 2 corrects the signature pre-image description, the tamper-probe field list, the
delegation per-hop figure and the conformance test count, and records that the evaluated
verifier did not authenticate human approvals. The recorded numbers are unchanged.

Build: `tectonic paper.tex` (prepared with Tectonic 0.16.9; set SOURCE_DATE_EPOCH=1790812800
to reproduce the published PDF byte for byte).

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/agent-manifest.

This package contains the manuscript source, figures, the recorded benchmark results and the
October 1, 2026 rerun in `experiments/results/rerun-2026-10-01/`. The saved July 1 run did not
record its SDK commit; the inferred revision is agent-manifest 67c21db (SDK source identical to
tag python-v0.2.0). The rerun froze the SDK clock at the original run time because the example
manifests expired in September 2026. It reproduced every size and tamper outcome but not the
2.7 ms Level 1 verify bound. It is not an independently replicated reproduction package.
Current implementation guidance: https://manifest.agentrust-io.com/
