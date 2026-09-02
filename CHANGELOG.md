# Changelog

## Unreleased

### Deprecated

- **[SPEC] Issuing v0.1 manifests ends 2026-11-30** (issue #315, phase 5). From that
  date the reference implementation produces v0.2 COSE envelopes only. The date follows
  phase 4 completing: `cmcp` and `ca2a` both verify a v0.2 envelope through their real
  loader paths and both reject a payload declaring v0.1 under a v0.2 envelope
  (`AM-VEC-COSE-012`), so a consumer is exercising v0.2 rather than a test harness.

  **Verifying v0.1 manifests is not deprecated and has no end date.** These are audit
  records with regulated retention well beyond their 90-day validity, and a verifier that
  stops reading them destroys evidence rather than tidying a codebase. Same reasoning as
  keeping the `-8` Ed25519 code point acceptable indefinitely.

## [0.11.2] — 2026-08-27

### Fixed

- **[SECURITY][SDK]** `verify_manifest` now binds a declared
  `artifacts.policy_bundle.enforcement_mode` to the runtime's attested mode.
  A mismatch or an omitted runtime mode fails closed instead of accepting a
  matching policy hash while the runtime operates with weaker enforcement.

## [0.11.1] — 2026-08-23

### Fixed

- **[SECURITY][SDK]** The integrated verification path now authenticates every
  enforced HITL approval against a trusted approver key and binds that approval
  to the manifest being verified. Missing keys, malformed or invalid approval
  signatures, and approvals replayed from another manifest fail closed. See
  GHSA-ww2p-prj4-c6xf.

- **[SECURITY][CLI]** `manifest verify` gained `--approver-key
  APPROVER_ID=PATH` (repeatable) to supply trusted HITL approver keys. Without
  it the CLI had no input that could populate `approver_public_keys`, so every
  approval resolved to `UNVERIFIABLE` and `--enforce-hitl` could not succeed.
  A failing result now names the missing option.

- **[SECURITY][SDK]** Bound runtime artifacts now fail closed when their
  observed hashes are absent. Signature-only appraisal remains available only
  through an explicit API or CLI opt-out and must not be used as authorization
  evidence about a deployed agent.

- **[SECURITY][SDK]** Transparency receipts are no longer treated as a warning-
  only attachment at production conformance levels. Level 1+ (or explicit
  `require_transparency`) requires an entry ID or receipt digest produced by an
  independent appraisal against the relying party's trusted transparency-log
  policy. An attacker-controlled receipt in a COSE unprotected header is
  `UNVERIFIABLE`, not proof of inclusion.

### Added

- **[SPEC][SDK]** Added configuration assurance for artifact #1 (spec 3.2.1.1,
  issue #254). Every threat in section 7.1 is an adversary substituting
  something, and `system_prompt.hash` detects that. A prompt authored in good
  faith, reviewed, approved, signed, sealed to a TEE measurement and verified
  `VALID` may still specify behaviour the deploying organisation would reject if
  it were tested rather than read, with no adversary present and no digest
  changed. Artifact #1 is the specification of the agent's behaviour rather than
  data it consumes, so digest equality is necessary and not sufficient.

  `system_prompt.assurance_test` binds a named suite, suite version, harness
  version and result, the same shape and the same normative force section 3.2.5
  already gives `poisoning_scan`: `result: flagged` MUST NOT be issued as
  `VALID`. The verification result gains `configuration_assurance`, so absence
  is reported as `NOT_ASSESSED` rather than inferred as a pass. Which
  conformance level requires an assessment is deliberately left open.

  `safety_level` is now named in the spec as an operator assertion with no
  defined value space and no verification behaviour, which is what it always
  was; the field name resembled an assurance signal and nothing said otherwise.

- **[SPEC]** Stated the scope boundary of the memory checkpoint protocol
  (section 3.2.6.2, issue #298). A governed advance establishes integrity,
  ordering, freshness and budget, and establishes nothing about retrieval
  behaviour over the new state. A checkpoint can satisfy every rule while an
  appended correction stays less salient than the fact it corrects, while
  authorized additions displace a safety or identity anchor, while another
  tenant's memory becomes retrievable, or while states that should retrieve
  differently collapse to the same context. None of that needs a forged
  signature or a broken proof, so the protocol's own checks cannot see it.
  Assessment is a separate evidence artifact over a pinned retriever and probe
  suite, out of scope here and tracked in #298.

- **[SPEC][SDK]** Withdrew the artifact-only refresh path at Level 1 and above,
  and made a stale attestation fatal (issue #265). Section 2.2 let
  `memory_baseline.snapshot_hash` be renewed and the manifest re-signed without
  re-running the TEE attestation. That cannot hold: `manifest_hash_in_report` is
  computed over the full manifest including the `signature` block, so the
  refresh changes the attested pre-image twice and the retained report binds the
  previous document. A verifier had to either reject the refreshed manifest or
  stop enforcing the binding, and both cannot be conformant at once. Governed
  memory evolution belongs to the section 3.2.6.2 checkpoint protocol, which
  exists so a growing store does not mutate the attested document.

  The verifier previously reported a mismatched `manifest_hash_in_report` only
  when `enforce_attestation` was set, so the default path returned `VALID` for
  exactly the case above. A present attestation binding a different manifest is
  now `MISMATCH` regardless: `enforce_attestation` governs whether an
  attestation is required, not whether a wrong one counts. `AM-VEC-021` pins it,
  and `examples/level1-tpm-attested.json` carried a placeholder hash that bound
  no document, which the new rule surfaced.

- **[SPEC][SDK]** Added the audit-chain continuity protocol (spec Section
  3.2.7.1, issue #273). `audit_chain_root` is the chain state at signing time
  and decisions are produced after signing, so a verifier fetching the chain
  later could confirm it still contained the signed root but not that it was an
  append-only extension of it rather than a chain rebuilt around that prefix.
  `entry_count` detects deletion below the signed count and constrains nothing
  above it. The chain now gets the mechanism Section 3.2.6.2 already gives
  memory: `merkle-log` advances carry an RFC 9162 §2.1.2 consistency proof,
  `hash-chained` advances carry the ordered entry leaves folded forward from the
  signed root, and both walk the same fail-closed stages (proof, monotonic
  `seq`, TTL). `decision_trace` gains an `EXTENDED` result for a proven
  extension; a diverged root with absent, malformed, or failing evidence is
  still `MISMATCH`. There is no budget stage, because an audit chain is meant to
  grow without bound. A verified proof establishes that nothing below the head
  was rewritten; it does not establish that every action produced an entry, and
  the section says so.

- **[SPEC]** Added section 5.3.2, what `VALID` does not establish (issue #272).
  Section 5.3 defined behaviour on `MISMATCH` and none on `VALID`, so a gateway
  reading it literally had a rule for one outcome and a natural default for the
  other. `VALID` is a statement about provenance, not permission: it does not
  establish that the call about to be made is permitted, that it is within the
  consequence envelope an approver had in mind, or that the agent's current
  inputs are trustworthy. `catalog_hash` pins which tools were approved, and
  inside one authorized tool a read and an irreversible write are the same tool.
  Per-call authorization joins the section 7.2 out-of-scope list, and the
  overview sentence claiming the manifest proves "what it was allowed to do" is
  narrowed to what it actually binds. No schema, field, or conformance change;
  the conformance test from #280 already demonstrates the boundary.

- **[SPEC][SDK]** Resolved the `agent_id` lifetime overload and made the OCSF
  identity mapping normative (spec 3.1 / 6.4.2, issue #269). `agent_id` was
  serving both of OCSF's identity roles at once: the stable `ai_agent.uid` and
  the session-scoped `ai_agent.instance_uid`, which is why the crosswalk
  shipped informative. `agent_id` is now defined as the stable identity, and
  instance scope is declared in a new OPTIONAL signed `agent_instance_id`
  rather than parsed out of a SPIFFE path segment that carries no declared
  meaning. A producer emitting `ai_agent` for a manifest-governed session MUST
  populate `uid` from `agent_id`, MUST populate `instance_uid` from
  `agent_instance_id` when the manifest declares one, and MUST NOT fall back to
  `agent_id` for `instance_uid` when it does not. The verification result gains
  a `correlation` object carrying both identities and the `manifest_id` they
  came from. Adding the field leaves every existing signature verifying, since
  the pre-image omits absent fields; the conformance vectors are regenerated
  for the longer `signed_fields` list.

- **[SPEC][SDK]** Added the relying-party challenge and context binding for
  verification results (spec 5.1.2, issue #266). `verification_id` is chosen by
  the verification service and `verified_at` is a producer-selected timestamp,
  so neither shows a relying party that a result was produced for its live
  request: a signed `VALID` could be replayed to a different party, for a
  different `purpose`, or against a weaker context than the one now being asked
  for. A request may now carry `challenge_nonce` (at least 128 bits, single
  use), which the result echoes unchanged, alongside
  `verification_context_hash` over the RFC 8785 canonical form of the request
  context. The nonce is deliberately outside the hash so two requests asking the
  same question hash the same. A result with no nonce is unbound to any request
  and 5.3 now says it must not gate an action.

  `derive_runtime_nonce()` composes this challenge with the section 3.3.2
  runtime attestation report: `sha256("am-runtime-nonce" || nonce)`, domain
  separated so the derived value cannot be presented as a verification challenge
  itself. Without it the two freshness domains are replayable independently,
  which defeats both.


- **[SPEC][SDK]** Added the `com.agentrust-io.manifest` Agent Plugins 1.0.0
  extension profile. It resolves an HTTPS manifest by raw-byte digest, verifies
  it against independently trusted keys, and compares the local bundle with a
  signed `source_bundle` binding. Absent, unreachable, unverifiable, and
  mismatched references remain distinct outcomes.

- **[SPEC][SDK]** Added the signed `composition-only` profile for repository and
  pre-execution manifests. Every omitted artifact must be named in
  `unbound_artifacts`; overlap and undeclared omissions fail closed. These
  documents verify as `INCOMPLETE` and cannot claim Level 0 or above.

- **[SDK]** `parse_tpm_attest()` now exposes the common signed `TPMS_ATTEST`
  header and opaque union payload, while `parse_tpm_nv_certify()` enforces the
  signed type and parses the `TPMS_NV_CERTIFY_INFO` carried by
  `TPM2_NV_Certify`. This lets cMCP retire its remaining local NV-certify wire
  parser. Size-prefixed attestations now reject undeclared trailing bytes.

**[SDK] `AM-VEC-COSE-002` … `AM-VEC-COSE-015` publish the COSE negative conformance vectors.** Fourteen cases a conforming verifier must not accept, covering the protected/unprotected header split, CBOR tagging and framing, payload presence, the issuer authorization boundary, the two JSON parser divergences RFC 8259 leaves open (duplicate member names, non-finite numbers), version routing in both directions, and the payload depth bound. `011` and `015` are a pair: #243 records `NaN` and `Infinity` as one class of defect, but they are not one code path in every parser, so a verifier that special-cases `NaN` passes the first and fails the second. They complete the portable contract other-language SDKs are written against: until now the suite proved an implementation could accept a valid envelope, not that it rejected an invalid one.

`AM-VEC-COSE-014` is the reverse of `012` and the reason the version gate is described as bidirectional: a v0.2 manifest must not fall back to the v0.1 detached signature block, because a one-way gate is not a gate. It expects `MISMATCH` rather than `INCOMPATIBLE_VERSION`, since the verifier does support 0.2 and reporting otherwise would state something untrue about its capabilities.

The hybrid authorization case, a `COSE_Sign` carrying one authorized component key alongside one unauthorized one, is deliberately not a vector: it contains an ML-DSA-65 signature, ML-DSA-65 signing is hedged, and `cryptography` 49 exposes no deterministic mode, so the bytes differ on every regeneration. It remains covered by a per-run test in the Python suite, and the vector README states the rule as binding on other languages so it is not mistaken for out of scope.

Each negative carries `signature_valid`, recording whether the Ed25519 signature over the RFC 9052 `Sig_structure` verifies. Where it is true, a verifier cannot pass the vector by rejecting a broken signature and never reaching the rule the vector names. The vectors whose defect is in the payload are signed over the malformed bytes rather than having bytes swapped into an already-signed envelope, which is what keeps that guarantee. Two declare `false` by design: `AM-VEC-COSE-002` tampers with the protected header, which is the rule under test, and `AM-VEC-COSE-008` has a nil payload, so there is no `Sig_structure` to verify over.

`AM-VEC-COSE-009` is byte-identical to `AM-VEC-COSE-001` and differs only in `context.trusted_key_issuers`. Nothing about the object explains the rejection, so a verifier that stops at "the signature verifies under a trusted key" returns `VALID` and has no authorization boundary at all.

### Fixed

- The committed conformance vectors are now diffed against a fresh in-memory regeneration by the test suite, so a vector edited by hand, or a generator change made without regenerating, fails CI rather than shipping as a contract nobody can reproduce.

- The vectors had been stale each time `SIGNED_FIELDS` gained a member without being regenerated alongside it: `intent` in 0.11.0, `profile` and `unbound_artifacts` in #306, `source_bundle` in #307. In each case they they published a `signature.signed_fields` list omitting those fields, and `AM-VEC-018` carried the `manifest_hash_in_report` that followed from the shorter list. No signature or expected result changes, because none of these manifests declares any of those fields and `signing_pre_image` omits absent ones, so the signed bytes are identical either way. What was wrong is what the suite told other languages to build their pre-image from. The regeneration test above is what surfaced it, and is what stops it recurring.

### Security

- `verify_manifest()` now fails closed when a core identity, validity, or artifact-container claim is missing. A valid signature no longer turns such a structurally incomplete object into a `VALID` manifest; legacy v0.1 issuer omission remains compatible unless issuer authorization is configured.

All notable changes to Agent Manifest are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec changes are marked **[SPEC]**; SDK changes are marked **[SDK]**.

### Added

- Added an informative Agent Credentials integration guide describing how a relying party joins a credential decision to the exact signed manifest and runtime-evidence record at a defined execution boundary. The guide tracks CoSAI WS4 issue #99 and OCSF proposals #1704 and #1724 without treating either open proposal as released schema. Closes #267.

### Security

- The PyPI release workflow now installs and smoke-tests both the exact wheel and source distribution before upload, including version/tag agreement, import provenance, a public cryptographic verification roundtrip, and the packaged CLI entry point.

### Security

- Generic hardware-attestation certificate-chain verification now enforces every certificate's validity period and requires every issuing certificate to carry `BasicConstraints(ca=True)`. If an issuer declares `KeyUsage`, it must permit certificate signing.

### Fixed

- The Python test harness now pins imports to the checkout's `src` tree and asserts that location, preventing a stale installed `agent-manifest` wheel from producing misleading release-validation results.

### Security

- `FileCRL.revoke()` now verifies a record's signature and signer key ID before mutating its cache or append-only file whenever `trusted_signer_key` is configured. This closes an append-time bypass of the existing load-time trust check.

- `verify_manifest()` now rejects manifests whose `issued_at` is in the future and treats `expires_at` as an exclusive upper bound, enforcing the specification's full `issued_at <= now < expires_at` validity window.

## [0.11.0] — 2026-08-11

### Added

**[SPEC][SDK] Section 3.9 adds an OPTIONAL `intent` field, declared by the issuer.** Runtime governance frameworks (AARM R2/R3 among them) ask that an action be evaluated against the agent's stated intent, and this specification had no such input. The field is one string, `intent.statement`.

**The issuer declares it, and that is the whole design.** An intent the governed agent asserts about itself cannot support the check it exists for: an agent that intends to do X declares X, and the comparison becomes a formality. `intent` is therefore inside the signing pre-image, fixed before the agent runs, and the spec says an `intent` supplied outside the signed manifest — on a per-call request field, say — MUST NOT be accepted as satisfying the section.

Adding a field to `SIGNED_FIELDS` would normally be a compatibility break and is not one here: `signing_pre_image` omits fields absent from the manifest rather than serializing them as `null`, so a manifest without `intent` produces byte-identical pre-image to before and its signature still verifies. A test asserts that against the exact bytes, and it fails if absent fields are ever materialized.

No digest is stored beside the statement. `intent_hash()` derives `sha256:<hex>` over the canonical `intent` object on demand, so a runtime can bind the intent into a per-call receipt without a second representation that can be made to disagree with the first. It returns None when no intent is declared, which is a distinct answer from a digest over an empty statement.

Section 3.9.1 states what the field does **not** give: it is an input, not an analysis. Nothing here measures whether an action is semantically consistent with the declared intent, that would need a model whose own execution would have to be attested, and an implementation MUST NOT present the presence of `intent` as evidence such a measurement happened. A structural proxy is not a semantic measure and MUST NOT be labelled as one.

**[SPEC] Section 6.5 states the boundary with Agent Plugins** (#281). Agent Plugins 1.0.0 shipped as a packaging format for Agent Skills and MCP server configuration, backed by a multi-vendor steering committee, and the obvious reading from outside is that this project is a second format for the same job. It is not, and the specification had nowhere that said so.

The boundary in one sentence: Agent Plugins describes what a client should install, a manifest describes what actually ran. A plugin bundle is an input to a manifest.

The section argues that from the format's own documents rather than by assertion. `plugin.json` requires two fields, `$schema` and `name`, `version` is an unconstrained string, and there is no integrity, signature or provenance field in the 1.0.0 schema. `FUTURE_CONSIDERATIONS.md` states that v1.0.0 "does not define a trust model, permission system, or sandboxing requirements for plugins" and "does not specify how clients or users can verify the origin or integrity of a plugin", and lists attestation chains linking a published plugin to its source repository and build as possible future work.

Of the ten artifacts, Agent Plugins carries two, and carries both as declarations rather than as resolutions: `skills/*/SKILL.md` holds instruction material, and `mcp.json` declares which servers to start without enumerating the tools those servers exposed. That declared-versus-resolved gap is the boundary in miniature.

It stays informative for the same reason 6.4 does. Binding to `plugin.json` now would fix a field layout in a 1.0.0 format whose own roadmap anticipates adding provenance, so it would have to be revised rather than refined once that lands. The `extensions` object, keyed by reverse-domain namespace, is noted as sufficient to carry a manifest reference without any change to the format.

**[SDK] `manifest from-plugin` reads an Agent Plugins 1.0.0 bundle** (#282), along with `load_plugin_bundle`, `bundle_digest` and `system_prompt_binding_from_bundle`. This is the runnable half of the boundary in spec section 6.5: a plugin bundle is an input to a manifest, and now there is code that treats it as one.

**It does not build a tool manifest, and that is the point.** `ToolEntry` requires a `schema_hash` and a `description_hash` for every tool. `mcp.json` declares which servers to start and never enumerates the tools those servers expose, so a bundle carries neither hash and cannot be made to. Building a `ToolManifestBinding` from a bundle alone would mean inventing the two values the artifact exists to bind. Declared servers are therefore recorded as declarations, each with a hash of its declaration so a later resolution can be compared against what the bundle said, and the CLI says on stderr how many still need resolving. A test asserts that no tool-manifest builder appears in the module, so this stays true by accident-proofing rather than by memory.

The digest covers every file in the bundle, including ones the adapter does not parse, such as the reverse-domain client extension directories the format permits. A digest that skipped what it did not understand would report the same value for two bundles differing in an unread file, which is the case where unmeasured and empty become indistinguishable. Paths are bound alongside content, so a rename with identical bytes is a different digest.

`$schema` is checked against the 1.0.0 constant and an unrecognised value is refused rather than guessed at. Both `mcp.json` shapes seen in the wild are accepted, the `mcpServers` wrapper and a bare mapping, because rejecting the second would fail bundles every client accepts.

**[SPEC] Section 6.4 is an informative crosswalk to OCSF runtime evidence** (#269). There was no defined join key between a manifest and the OCSF events emitted under it, so a consumer holding both could not tell they described the same agent without an out-of-band convention, and implementers were left to invent a second identity mechanism for a job this specification already does. The new section records the intended correspondence and deliberately requires nothing.

Three things it gets right that a normative version could not yet: it is written against the **`ai_operation` profile**, which is what actually contributes `ai_agent`, rather than against an event class (the `Agent Inventory Info [5050]` class proposed for this does not exist in OCSF as of this writing; a Discovery-category class for agent trust-base inventory is now proposed upstream at `ocsf/ocsf-schema#1724`); it maps `ai_agent.uid` to the durable identity and `instance_uid` to the session-scoped one, which is what OCSF's own definitions ask for, instead of collapsing both onto `agent_id`; and it notes that `session_uid` is not an `ai_agent` attribute at all.

It stays informative because `agent_id` is one field serving both roles, and section 3.1 says the `/agent/<name>/<instance>` path is "a convention, not a requirement" — so a conformant `agent_id` may be stable and carry no instance scope. Requiring it to populate `instance_uid`, which OCSF defines as explicitly distinct from the stable `uid`, would force a stable identifier into the non-stable field and cost a consumer the ability to separate "every run of this agent" from "this run". Resolving that means deciding whether `agent_id` splits, which belongs in CoSAI WS4 alongside the canonical `@context` URL that section 3.1 already defers there.

The section also records a correspondence worth more than the identity one: OCSF's `delegation` object (`uid`, `parent_uid`, forming a re-delegation DAG) is structurally the delegation chain of section 3.4. It does not map today, because a section 3.4 hop has no per-hop durable identifier to populate `delegation.uid`, and OCSF wants that identifier issued by a trusted authority rather than self-asserted by the delegator. Closing that is a data-model change, not a crosswalk, and is not proposed here.

**[SPEC] Section 9.1.2 maps EU AI Act Article 50, and maps it as a gap.** Article 50 transparency duties have applied since 2 August 2026: chatbot disclosure, machine-readable marking of synthetic output, emotion-recognition notice. It is the only AI Act obligation in force against an agent deployment today, and no document in this repository mentioned it. The manifest satisfies none of the four paragraphs, so the new subsection says that in those words, notes that Article 50 applies regardless of Annex III classification, and states that a manifest MUST NOT be read as Article 50 evidence. `docs/compliance/eu-ai-act.md` carries the same mapping for auditors. Marking that binds to the attested agent that produced the output, rather than to a strippable metadata field, is the design being pursued; it is not built.

**[SDK] COSE_Sign1 signing and verification for manifest version 0.2** ([`_cose.py`](https://github.com/agentrust-io/agent-manifest/blob/main/python/src/agent_manifest/_cose.py), [ADR-0011](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0011-signature-envelope.md), [ADR-0013](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0013-cbor-library-for-cose.md)). Phase 2 of the envelope migration (issue #243). `verify_manifest()` now takes either a dict or bytes: **a dict is a v0.1 manifest and verifies exactly as it does today**, bytes are a v0.2 COSE envelope. The envelope follows the manifest `version`, never a flag, so no existing record is reinterpreted.

### Fixed

**[SPEC] The README pointed at a specification file that does not exist.** Three links and the spec badge referenced `spec/agent-manifest-spec-v0.1.md`, superseded by v0.2. All four now resolve.

### Changed

What the envelope buys is structural rather than incremental. `alg` is in the protected header and covered by the signature, so the downgrade fixed in 0.6.0 by an explicit cross-check cannot be expressed at all. The payload is verified as received, so RFC 8785 is no longer an input to verification — it stays the producer-side determinism rule and the basis of the hash bound into hardware. Receipts (label 394), the TEE attestation report, and HITL approvals attach in the unprotected header, which retires the `signed_fields` coverage table, the `hitl_record.approvals` normalization rule, and the `transparency_log_entry` ordering rule together. Hardware now binds `sha256` of the payload bytes, with no field subset to keep in sync.

Hybrid is one `COSE_Sign` with two signers rather than two `COSE_Sign1` objects, so both signatures covering identical payload bytes is a property of the structure. A verifier that cannot perform ML-DSA-65 returns `UNVERIFIABLE` and never falls back to the classical entry.

**[SDK] New runtime dependency: `cbor2`.** Serialization only. The COSE structures are built in this repository and every signature stays on `cryptography` (and optionally `pyoqs`), so the SDK's crypto surface is unchanged. [ADR-0013](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0013-cbor-library-for-cose.md) records why no COSE library was taken: neither `pycose` nor `cwt` ships the RFC 9964 code points that half this envelope needs, and both widen the dependency closure to do less.

### Fixed

**[SDK] The `pq` extra was uninstallable, and the module it imported is not the package it meant.** `pip install "agent-manifest[pq]"` required `pyoqs`, which is not published on PyPI, so the post-quantum profile could not be installed by following the documented instruction. Worse, the module name the SDK imports — `oqs` — belongs to an unrelated project on PyPI, and `_signing` treated a successful import as proof of liboqs. Installing that package turned every ML-DSA-65 call into an `AttributeError` (18 test failures) and made the SDK report a post-quantum capability it did not have.

**ML-DSA-65 now comes from `cryptography`**, which implements it through OpenSSL as of 47.0.0 and is already a required dependency. The `pq` extra is now `cryptography>=47` and installs cleanly. Deployments already carrying the liboqs bindings keep working: the backend is chosen by the key material, not by configuration, because the two differ in private key encoding — cryptography uses the 32-byte seed, liboqs the expanded secret key. **Public keys are the same 1952-byte encoding in both**, so `key_id`, the COSE `kid`, and every signature a third party verifies are unchanged and interoperable across backends. A build with neither backend still reports `UNVERIFIABLE` rather than accusing the manifest, unchanged from #245.

The capability check no longer trusts a module name: liboqs is now identified by its API. Thirteen post-quantum tests that skipped on every machine without liboqs — across signing, hybrid mode, evidence packs, and the COSE envelope — now execute against real FIPS 204 signatures.

### Changed

**[SPEC] EU AI Act mappings now carry the date each obligation applies from.** The mappings were written as if the high-risk obligations bind today. Under the current provisional timeline the Digital Omnibus amendments defer Annex III systems to around 2 December 2027 and Annex I to around August 2028, which `docs/compliance/eu-ai-act.md` already recorded and nothing else did. The mappings are correct and unchanged; only the applicability date is added, in section 9.1 (authoritative note), the section 8.1 conformance-level table, the section 8.1 log-retention requirement, `LIMITATIONS.md`, the HITL tutorial and example, `docs/index.md`, `docs/getting-started.md`, and the hardware-attestation tutorial. Where a deployment has an obligation in force today, the docs now lead with it: DORA for financial entities, HIPAA § 164.308(a)(5) for the HITL record.

**[SPEC][SDK] Ed25519 is identified by `-19`, not the deprecated `EdDSA` `-8`** ([ADR-0014](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0014-fully-specified-ed25519-code-point.md)). **RFC 9864 (Standards Track, October 2025) deprecated the polymorphic `EdDSA` identifier** and registered fully-specified ones; the IANA COSE Algorithms registry marks `-8` deprecated. Issue #243's "code points are settled: EdDSA -8" was therefore already out of date when phase 1 was written — the ML-DSA-65 half (`-49`) was confirmed correct against IANA. A producer now signs with `-19`; a verifier accepts both and **keeps accepting `-8` indefinitely**, because manifests are audit records with regulated retention and a signature cannot be re-issued under a new identifier without re-signing.

`-8` and `-19` name one algorithm, so anything reasoning about *which* algorithm signed compares algorithms rather than code points: a `post-quantum` profile is satisfied by neither, and a `COSE_Sign` carrying one entry of each is rejected as a single algorithm signed twice rather than accepted as a hybrid signature.

The cost is recorded in the ADR rather than glossed: **no COSE library implements RFC 9864 yet**, so a `-19` manifest cannot currently be verified by third-party tooling — the interop check runs against `-8` fixtures over the same structures for as long as that holds.

**[SDK] `AM-VEC-COSE-001` pins the COSE_Sign1 encoding byte-for-byte.** A vector now carries either `manifest` (v0.1) or `envelope_hex` (v0.2 COSE), and the same conformance loop runs both, since the engine selects the procedure from what it is handed. The vector fixes every element — tag, protected header, `unprotected_hex` of `a0`, payload, signature, and the payload hash hardware binds — so another language's SDK has something to agree with rather than only its own round-trip. Ed25519 only: ML-DSA-65 signing is hedged, so post-quantum envelopes differ per run and only their structure is stable.

**[SDK] A version 0.2 manifest may not use the v0.1 envelope.** The version gate now binds in both directions: a manifest declaring `version: "0.2"` while carrying a detached `signature` block is rejected rather than verified under v0.1 rules. `signature` is not a v0.2 field at all, since the COSE structure is the signature, so such a document claims the new version while using the envelope with the unauthenticated algorithm identifier and the canonicalize-before-verify step that ADR-0011 moved away from. Accepting it would have made the gate advisory and left the phase 5 deprecation with nothing to enforce. Version 0.1 manifests are unaffected.

**[SDK] `manifest sign` and `manifest verify` handle version 0.2.** `sign` selects the envelope from the manifest's `version` field, so a `0.2` manifest is written as a COSE envelope in binary CBOR and a `0.1` manifest is unchanged; there is no flag, consistent with ADR-0011. `verify` detects the envelope from the CBOR tag rather than the file extension, since guessing a format by filename is the ambiguity the media-type rules exist to remove. Signing a `0.2` manifest requires `--output`, because binary CBOR down stdout would be corrupted by the terminal. New reference page: [COSE envelope](https://github.com/agentrust-io/agent-manifest/blob/main/docs/api-reference/cose.md).

**[SDK] `POST /verify/cose` accepts a version 0.2 COSE manifest as raw CBOR.** The body is the `COSE_Sign1`/`COSE_Sign` object itself under `Content-Type: application/agent-manifest+cose` — the registered media type is the gate, rather than base64 inside a JSON wrapper, since the object is self-contained and the type exists to identify it. Three properties are deliberate: **only the exact media type is accepted** (a vendor-tree alias, `application/cbor`, and an absent type are all refused — the server never sniffs the body); **no key material crosses the wire**, so trust comes from a `cose_context` configured server-side when the router is built, and an unconfigured endpoint returns `UNVERIFIABLE` rather than `VALID`; and **the body is bounded before it is parsed**, with `Content-Length` checked when present and the stream capped regardless, because a declared length is attacker-controlled. A malformed or unverifiable envelope is a verdict (200 with a non-`VALID` result), not a transport error, and parser detail is never reflected back, so the endpoint cannot be used as an oracle for the decoder. Results carry `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Authentication, authorization and rate limiting remain deployment concerns (spec 5.1: mTLS with the agent's SPIFFE SVID).

**[SPEC] `version` MUST be `"0.2"`, resolving a contradiction inside the specification.** Section 2.4's compatibility matrix already planned for `0.2` manifests while the section 3 field table still required `"0.1"`, so a producer following the specification could never emit a manifest the COSE envelope governs. The field table now says `"0.2"`; `"0.1"` continues to identify a v0.1 manifest, which stays verifiable. The `@context` change had described v0.2 as differing from v0.1 "in the `@context` value alone" — accurate for that change in isolation, but v0.2 as a release also carries the COSE envelope, and [ADR-0012](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0012-context-uri-moved-to-controlled-domain.md) is amended with a note saying so.

**[SDK] `0.2` is now a supported manifest version.** `AM-VEC-007`, which used `0.2` as its stand-in for a version from the future, now uses `0.3`. Its expected result is unchanged.

**[SPEC][SDK] BREAKING: the `@context` URI moves to `https://manifest.agentrust-io.com/v0.2/context.json`**, and the specification is republished as v0.2 ([`spec/agent-manifest-spec-v0.2.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.2.md), [ADR-0012](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0012-context-uri-moved-to-controlled-domain.md)). The v0.1 URI `https://agentmanifest.agentrust.io/v0.1/context.json` named `agentrust.io`, a domain this project has never controlled: registered to a third party behind Domains By Proxy, paid through mid-2027, and it has never resolved. Every manifest issued to date was therefore identified under somebody else's name, which is untenable in an identity specification.

Consumers **cut over rather than dual-accepting**, matching the TRACE v0.2 profile migration (`agentrust-io/trace-spec#107`) that fixed the identical defect. An implementation that kept honouring the v0.1 URI would keep validating manifests named on a domain we do not own. Manifests already issued under v0.1 stay checkable against the v0.1 specification, which remains published.

**No field is added, removed or re-typed** by the `@context` change itself. Serving the context document at the new URL is follow-up work; what changes today is that the domain is ours to serve from. Note that v0.2 as a release is not only this: ADR-0011 assigns the COSE signature envelope to manifest version `0.2` as well, so a v0.2 manifest carries the new `@context` **and** is signed as a COSE object. The two changes share a version number.

## [0.10.0] — 2026-08-01

Exports the SEV-SNP ABI offset table so downstreams can delete the ctypes mirrors they kept solely to read offsets from. Completes what 0.9.0 started: cmcp used its struct as an offset oracle across seven test files, so sharing the parse without sharing the table would only have moved the duplication into test scaffolding, where it would drift silently.

### Added

**[SDK]** **`SNP_OFFSETS` and `SNP_REPORT_LEN` are public.** The offsets are the contract consumers build and appraise reports against, and they are now checked against the genuine Azure capture rather than against themselves.

## [0.9.0] — 2026-08-01

Shares the SEV-SNP report union so cmcp and ca2a can delete four copies of the layout between them, and restores a check that existed only in the copies being deleted: the report's declared `sig_algo` is now verified before the signature is checked under it. Phase A2 of consolidating TEE verification into this package.

### Added

**[SDK]** **`SnpReport` now carries `guest_svn`, `vmpl` and `signature_algo`**, and `load_snp_cert_chain()` is public. Phase A2 of the TEE consolidation: cmcp and ca2a carried four copies of the SEV-SNP report layout between them (two inside cmcp alone), and all four agreed on every offset, so this is a union rather than a reconciliation. The three fields were parsed by the downstream copies and not by this one, which meant a consumer of agent-manifest could not enforce checks those copies enforced.

`load_snp_cert_chain()` splits a concatenated PEM into `(vcek, ask, ark)` by shape rather than order: the VCEK is the only EC leaf, and of the two RSA certificates the self-signed one is the ARK. It came from cmcp, which had it and this package did not.

### Fixed

**[SDK]** **`verify_snp_signature()` now checks the report's declared `sig_algo` before verifying.** It assumed ECDSA-P384/SHA-384 because that is the only scheme AMD has defined, and verified under it without confirming the report said so. Both downstream copies checked this field; the shared implementation did not, so consolidating onto it would have silently dropped a check. A report declaring anything other than `SIG_ALGO_ECDSA_P384_SHA384` now raises rather than being appraised under the wrong scheme.

This surfaced two synthetic fixtures in this repo that left `sig_algo` at zero, which no AMD processor emits — the genuine capture in `tests/vectors/snp/azure_snp_report_redacted.bin` carries 1. Both fixtures described a report that cannot exist and are corrected. Same shape of defect as the cmcp TPM fixture found in 0.8.0.

## [0.8.0] — 2026-08-01

Shares the `TPMT_SIGNATURE` parse and teaches the quote parser both attest framings, so cmcp and ca2a can delete their copies rather than keep three implementations of the same wire formats in step by hand. Phase A1 of consolidating TEE verification into this package. No change to manifest signing or verification behaviour.

### Added

**[SDK]** **`parse_tpmt_signature()` and `ParsedSignature` are now public**, so cmcp and ca2a can stop carrying a copy each. Both had byte-identical implementations of the `TPMT_SIGNATURE` unwrap that `tpm2_quote -s` and `tpm2-pytss`'s `signature.marshal()` produce, differing only in which exception they raised; cmcp's comment already named this as "the piece agent-manifest does not model". It raises `TpmVerificationError` rather than `ValueError`, so a downstream migrating off its own copy needs to widen its `except` clause. `struct.error` on a truncated buffer is now caught and re-raised as `TpmVerificationError`, which ca2a handled and cmcp did not.

**[SDK]** **`parse_tpm_quote()` accepts a size-prefixed `TPM2B_ATTEST` as well as a bare `TPMS_ATTEST`.** `tpm2_quote -m` writes the bare form and other producers write the wrapped one, so a verifier that accepts only one rejects genuine quotes from standard tooling. `TpmQuote.raw` is now always the inner `TPMS_ATTEST`, and `verify_tpm_quote()` checks the AK signature over that rather than over its argument — verifying over the outer bytes would have failed a real wrapped quote. For bare input, which is everything the suite previously exercised, both are the same bytes and behaviour is unchanged.

Framing is decided by requiring the magic to appear under one reading or the other, not by the leading bytes alone. The obvious implementation, "magic at offset 0 means bare, otherwise treat the first two bytes as a length", silently reinterprets a blob with a corrupt magic as a framing fault and reports `TPM2B_ATTEST size field invalid`, which sends whoever is debugging a one-bit corruption to the wrong problem. Two tests caught this and both are kept as regression guards.

### Changed

**[SPEC]** **Target standards body retargeted from AAIF to CoSAI Working Stream 4**, an OASIS Open Project, following the Phase 1 RFC in [cosai-oasis/ws4-secure-design-agentic-systems#149](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149). Affects the spec header, section 3.1 (who assigns the canonical `@context` URL), section 3.2.5 (scanner registry), section 10.1 through 10.3, and the governance set: `CHARTER.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `ANTITRUST.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `README.md`. No normative data-model, cryptographic, or conformance change; nothing about how a manifest is signed or verified moves.

Three things did not change mechanically with the rest. The conformance test suite in section 8.2 was described as shipping "alongside the AGT donation to AAIF" and is now decoupled, because AGT's standards destination is governed separately and is not set by this charter. Two AAIF references are retained deliberately: the `AAIF Spec Enhancement Proposal (SEP)` route in section 6.3 and the `MCP (Anthropic / AAIF)` row in section 10.4 both describe MCP's own governance home, not this specification's target. And the IP terms are stated as consequences rather than commitments: the OASIS Open Projects IPR Policy requires a CLA plus a patent non-assert on non-trivial contributions, which is stricter than the DCO-only regime in force today, so `CHARTER.md` section 4 records that it takes effect only on WS4 acceptance and that the founding maintainer's terms under it need counsel sign-off first. Trademark transfer terms are marked to be determined rather than asserted.
### Fixed

**[SDK]** `parse_tdx_quote_signature()` now rejects a quote whose declared lengths overrun the buffer instead of silently parsing a shorter value. Four lengths come from the quote, which is untrusted input: the signature-data size, `cert_size`, `qe_auth_size`, and `pck_size`. Python slicing clamps rather than overreading, so an inflated length previously yielded a short slice and parsing continued against whatever fit. No read was ever out of bounds and the downstream signature check would fail, so this is fail-closed hardening rather than a memory-safety fix, but a verifier should reject a quote that declares 400 bytes and supplies 300 rather than appraise the 300. Found while reviewing the same parse in cmcp#420, which shares the derivation.

## [0.7.0] — 2026-07-27

Shares the hardware-validated TDX quote-signature parse so the sibling repos can stop carrying their own copies of the offsets, and specifies the v0.2 COSE envelope. No change to manifest signing or verification behaviour.

### Added

**[SPEC]** **COSE envelope specified for manifest version 0.2**: [`spec/agent-manifest-cose-envelope-v0.2.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-cose-envelope-v0.2.md), phase 1 of the ADR-0011 migration ([#243](https://github.com/agentrust-io/agent-manifest/issues/243)). `COSE_Sign1` (tag 18), or `COSE_Sign` (tag 98) with two signers for a hybrid Ed25519 + ML-DSA-65 signature so that both entries covering one payload is structural rather than an application rule. Protected header carries `alg` (`-8` / `-49`, RFC 9053 and RFC 9964), `kid`, `content type` (3), and `typ` (16, RFC 9596); the payload is the RFC 8785 canonical JSON of the manifest, carried inline; the SCITT receipt attaches as `receipts` (unprotected label 394, RFC 9942 receipts). Media types `application/agent-manifest+json` (payload) and `application/agent-manifest+cose` (object), standards-tree, registration pending.

Three v0.1 mechanisms are deleted rather than ported, because each existed only to work around JSON having no defined place for post-signing data: the fixed `signed_fields` list and its coverage table, the `hitl_record.approvals` normalization rule, and the `transparency_log_entry` ordering rule. In v0.2 the payload is what is signed, and approvals, the attestation report, and the receipt all attach in the unprotected header. Hardware attestation binds `sha256` of the payload bytes, so there is no longer a set of fields to exclude and keep in sync. No code changes; manifest version 0.1 is untouched and continues to verify under v0.1 section 3.6.

**[SDK]** `parse_tdx_quote_signature()` and `TdxQuoteSignature` expose the validated DCAP v4 signature-section parse (de-nested QE report, QE signature, auth data, PCK chain PEM) so sibling repos can delegate to it instead of reimplementing the offsets. Real quotes nest the QE material under a type-6 `QE_REPORT_CERTIFICATION_DATA` header; a flat parse reads the QE report six bytes early and rejects every genuine quote, which is what happened in cmcp and ca2a. `verify_tdx_quote()` now calls the shared parse, so there is one copy of the layout, and two regression tests pin the nested structure.

## [0.6.1] — 2026-07-27

Closes a crash in `verify_manifest()` reachable from untrusted input on a default install, and settles the signature-envelope question for v0.2. No change to how manifests are signed or to any existing verification result.

### Fixed

**[SDK]** **`verify_manifest()` no longer raises on a post-quantum manifest when the `pq` extra is absent.** `pyoqs` is optional, so on a default install any manifest declaring `ML-DSA-65` or `hybrid-Ed25519-ML-DSA-65` reached `_require_oqs()` and crashed the engine with an uncaught `RuntimeError`. Since a manifest is untrusted input, a verification endpoint would answer 500 to an attacker-supplied manifest rather than returning a verdict. `_require_oqs()` now raises `AlgorithmUnavailableError` (a `RuntimeError` subclass, so existing callers are unaffected), the engine catches it, records the reason as a warning, and returns **`UNVERIFIABLE`**. Not `MISMATCH`: the verifier has established nothing about a manifest that may be entirely valid, so accusing it of a defect would be wrong. An algorithm identifier outside the registry remains a `MISMATCH`, rejected by the schema enum before verification runs.

**[SDK]** A `signature` block with no `algorithm` field no longer falls back to Ed25519. The field is REQUIRED by spec 3.6 but sits outside the signing pre-image, and the verifier defaulted a missing identifier to the classical algorithm; it is now a `signature.algorithm` mismatch. Completes the 0.6.0 downgrade check, which only covered a present-but-weaker identifier.

### Documentation

**[SPEC]** **ADR-0005 amended** after a spec-versus-implementation audit. Three of its statements did not match what shipped: it defined three `crypto_profile` values (`standard`, `post_quantum`, `hybrid`) where the spec and SDK define two (`standard`, `post-quantum`) with hybrid as a *signature algorithm* rather than a profile; it required the post-quantum profile at "Level 2 and above" where section 8.1 places it at Level 3; and it required an unsupported-algorithm verifier to "raise `INCOMPATIBLE_VERSION`", which is reserved for unsupported specification versions and is not something a verifier should raise at all. The original text is preserved per the ADR immutability rule, with an amendment section recording each correction. Section 4.2 now states the `UNVERIFIABLE` requirement normatively.

**[SPEC]** New **section 10.5, SCITT profile mapping**. Maps every structural piece of this specification to its RFC 9943 term (Artifact, Subject, Statement, Issuer, Signed Statement, Transparency Service, Receipt, Transparent Statement, Registration Policy, Auditor), which turns "agent-layer profile of SCITT" into a checkable claim and tells an implementer which parts are agent-specific (sections 3.2 to 3.5) and which are inherited. The section also states what the spec deliberately does not restate: OpenSSF Model Signing for the model artifact, SLSA and in-toto for build provenance, SCITT and Sigstore for transparency. Section 10.4 gains an OMS row, and v0.2 gains a line item for an explicit OMS bundle reference in `model_identity` so a verifier can follow the chain from agent to model publisher instead of trusting an operator-asserted hash.

**[SPEC]** New **[ADR-0011](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0011-signature-envelope.md): the manifest is a signed document, not a JWT/JOSE profile**, accepted. Answers the recurring "why not just a JWT extension?" question on precedent rather than on capability, steelmanning EAT ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)) rather than dismissing it, and setting against it the choice every comparable multi-artifact provenance standard made: SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)) mandates COSE_Sign1, DSSE rejected a JWS profile in writing, C2PA signs with `COSE_Sign1_Tagged`. The ADR also records a decision this project had never actually made: the envelope is neither JOSE nor COSE but a bespoke canonical-JSON detached signature, which carries both properties DSSE cites as reasons to avoid JWS while lacking a specification anyone else implements.

The accepted decision is that **the envelope moves to COSE_Sign1 in spec v0.2**. The post-quantum profile is not a blocker, which was the main technical risk: [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) (Standards Track, May 2026) gives ML-DSA final IANA code points in COSE (ML-DSA-65 = `alg` -49, AKP key type 7). Migration is sequenced in five phases and gated on the manifest `version` field, so v0.1 records keep verifying unchanged; tracked in [#243](https://github.com/agentrust-io/agent-manifest/issues/243). Hybrid is the one construction COSE has no single answer for and is deferred to the v0.2 spec work. Nothing in this release changes how a manifest is signed.

**[SPEC]** Corrected three factual errors in the spec. Section 2.2 and Section 5 described the manifest signature as "JWS", which it has never been (there is no JOSE dependency in the SDK; the signature is a detached Ed25519 or ML-DSA-65 signature over an RFC 8785 pre-image). Section 10.4 cited EAT as RFC 9528, which is EDHOC; EAT is RFC 9711.

**[SPEC]** Section 3.6 gained a normative algorithm-binding rule making the 0.6.0 verifier behaviour part of the specification: because the `signature` block sits outside the pre-image, a verifier MUST cross-check the declared algorithm against the signed `crypto_profile`, MUST reject a downgrade, and MUST reject an unrecognized algorithm identifier rather than defaulting to Ed25519. Section 10.4 adds rows for RFC 9711 and RFC 9943 positioning Agent Manifest as the agent-layer profile of the SCITT model.

**[SDK]** `docs/index.md` FAQ answers "why not specify it as a JWT or JOSE profile?" with the short form of the ADR-0011 argument.

## [0.6.0] — 2026-07-26

Fixes the CLI that every document described but that nobody could run, and closes a signature-downgrade gap in the verifier.

### Fixed

**[SDK]** **The documented CLI invocation now works.** Every command was nested under a redundant second `manifest` group, so the real invocation was `manifest manifest verify signed.json` while the README, the docs site, the PyPI description, and the CLI's own module docstring all printed `manifest verify signed.json`. Running the published quickstart failed at the first step with `Error: No such command 'keygen'`. `tests/test_cli.py` used the nested form, so CI never caught it. Commands are now attached to the top-level group as documented; the nested spelling still works, is hidden from `--help`, and prints a deprecation warning (removal in 1.0). `test_documented_commands_are_top_level` guards the surface.

**[SDK]** `verify_manifest()` now cross-checks the signed `crypto_profile` against `signature.algorithm` and fails closed on a downgrade (spec 4.2). `crypto_profile` is inside the signing pre-image, but the whole `signature` block is excluded from it (spec 3.6), so the algorithm identifier could previously be rewritten without disturbing the signed bytes: a manifest declaring the post-quantum profile verified `VALID` on a classical-only Ed25519 signature. The check runs independently of `trusted_keys` (the downgrade is a property of the manifest, not of the verifier's key material) and is one-directional: it rejects a signature weaker than the declared profile requires and permits a stronger one, so an issuer dual-signing ahead of the profile flip is not flagged. New conformance vector `AM-VEC-020`.

### Documentation

**[SDK]** `docs/getting-started.md`: new "Watch it catch a change" step. Shows the two ways verification fails and how they differ — an edit to the signed record (signature fails, `signature_verified: false`) versus runtime drift against an intact signature (declared-vs-actual binding fails, `system_prompt: MISMATCH`) — and names the boot-time boundary, pointing at `attest_runtime_state()` for freshness. All printed values are copied from real runs.

**[SDK]** `docs/api-reference/cli.md` is now generated from the CLI by `scripts/gen_cli_reference.py` instead of hand-written. The hand-written page had drifted into fiction: it documented `manifest keygen --out/--print-pub`, `manifest verify --revocation-url/--min-slsa-level`, `manifest create --agent-id/--issuer/--model/--ttl-hours`, and `manifest revoke --crl-file/--key-file`, none of which exist, while omitting the options that do. `test_cli_reference.py` fails if the committed page drifts from the CLI again.

**[SDK]** CLI help output is readable: `\b` markers keep the example blocks from being rewrapped into one line, and `-o/--output`, `--enforce-hitl`, and `--enforce-attestation` have help text instead of appearing bare.

**[SDK]** Corrected CLI examples that could not have worked: `docs/operations/key-rotation.md` used the non-existent `manifest keygen --out ... --print-pub`, and `docs/index.md` plus `python/README.md` printed `manifest verify` without `--public-key`, which fails closed as `UNVERIFIABLE` and exits 1 rather than the `VALID` shown.

**[SDK]** `LIMITATIONS.md`: document that **Azure TDX is not supported for offline attestation** (hardware-confirmed). Azure runs TDX behind the Hyper-V paravisor, so the guest gets no signed DCAP quote — only a MAC'd `TDREPORT` via the vTPM — and rooting that as genuine silicon needs a networked service (Azure MAA). Offline TDX attestation is supported on non-paravisor guests (e.g. GCP C3); on Azure use SEV-SNP (`AzureCVMProvider`). Azure-MAA TDX support is tracked as a follow-up.

## [0.5.0] — 2026-07-21

Generalizes the verification API so cmcp and ca2a can delegate their full SNP/TDX/TPM crypto to this package (via PyPI) without changing behavior or rewriting their test fixtures. Backward compatible — all existing functions and signatures are unchanged.

### Added

**[SDK]** Generic, algorithm-agnostic certificate-chain verifier `verify_cert_chain(chain, trusted_roots, *, root_fingerprint_hash=SHA256)` (exported, with `CertChainError`). Verifies a leaf-first chain by honoring **each certificate's own** signature algorithm — ECDSA, RSASSA-PSS, or RSA PKCS#1 v1.5 — via `x509.Certificate.verify_directly_issued_by`, then pins the chain root by fingerprint. This is the shared primitive behind AMD VCEK, Intel PCK, and TPM AK chains; it lets both consumers replace their own chain verifiers (cmcp's synthetic RSA-PKCS1v15 ARK/ASK and ca2a's EC chains both verify through it). The AMD-specialized `verify_vcek_chain` is unchanged (kept as its hardware-validated specialization).

### Changed

**[SDK]** `parse_tdx_quote(quote, *, strict=True)` gained a `strict` flag. `strict=True` (default) keeps enforcing the production layout (`version==4`, `tee_type==0x81`); `strict=False` parses the header/body of an otherwise well-formed quote whose version/tee_type differ (e.g. consumers' synthetic vectors) without asserting production TDX identity. `verify_tdx_quote` is unaffected and always strict.

## [0.4.0] — 2026-07-21

Makes agent-manifest the canonical hardware-verification library for the org: SEV-SNP, TDX, and now TPM quote verification live here and are consumed by cmcp and ca2a via this PyPI package rather than duplicated per repo.

### Added

**[SDK]** Shared TPM 2.0 quote verifier (`agent_manifest._tpm_verify`, exported: `parse_tpm_quote`, `verify_tpm_quote`, `TpmQuote`, `TpmVerificationError`). Fail-closed appraisal of a `TPMS_ATTEST` quote: magic/type structural check, AK certificate chain to a caller-pinned trusted root, AK signature (ECDSA-P256 or RSA PKCS#1 v1.5 / SHA-256) over the attest blob, and constant-time qualifying-data (nonce) + PCR-digest binding checks. Wired into `verify_attestation_chain` (dispatch on `platform in {"tpm","aws-nitro"}`). Ported from ca2a's reference implementation so the three repos share one verifier. Caveat: exercised against synthetic self-consistent vectors; unlike the SEV-SNP/TDX paths it is not yet validated against a real TPM quote (follow-up).

**[SDK]** Intel TDX DCAP quote verification (`agent_manifest._tdx_verify`, exported), **hardware-validated on a non-paravisor TDX guest (GCP C3)**. `TDXProvider` now uses the configfs-TSM `tdx_guest` provider, which returns a full remotely-verifiable DCAP quote (v4, ECDSA-P256) instead of a bare local `TDREPORT`. Verification checks the quote's attestation-key signature over the TD report, the QE report binding, the PCK signature over the QE report, and the PCK certificate chain up to the **pinned Intel SGX Root CA** (embedded; offline). Wired into `verify_attestation_chain`, which now returns `passed=True` for a TDX report only when the quote + PCK chain verify. Closes the TDX half of the "shipped the binding without verification" gap (#204/#228); the previous `/dev/tdx-guest` ioctl path (raw TDREPORT, no signature check, RTMR-extend that never happened) has been removed. Azure TDX (paravisor/vTPM-rooted) remains a follow-up.
**[SDK]** `AzureCVMProvider` — hardware-attested manifest binding on Azure confidential VMs, validated on live SEV-SNP silicon (Azure DCasv5). Azure runs SNP behind a Hyper-V paravisor, so there is no `/dev/sev-guest`; the SNP report is read from the vTPM NV index `0x01400001` and the manifest hash is bound through the vTPM (PCR + AK-signed quote), with the AK rooted in silicon by the SNP report + VCEK chain. Auto-selected by `provider='auto'` on Azure.
**[SDK]** AMD SEV-SNP signature backend (`agent_manifest._snp_verify`, exported): SNP report parsing, HCL-report splitting, the Azure `REPORT_DATA == sha256(runtime_data)` binding check, ECDSA-P384 report-signature verification against the VCEK, and VCEK ← ASK ← ARK chain verification (with optional pinned AMD root). Validated against a real SEV-SNP report.
**[SDK]** `verify_attestation_chain` now performs real hardware-signature verification when VCEK/certificate material is supplied (previously always `NOT_IMPLEMENTED`); it returns `passed=True` only once the SNP signature and VCEK chain verify. Without VCEK material it still fails closed.

### Changed

**[SDK]** `SEVSNPProvider` now uses the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`, kernel 6.7+) for bare-metal / non-paravisor SNP guests; the previous `/dev/sev-guest` ioctl path (never hardware-validated, incorrect ABI) has been removed. **Hardware-validated on a non-paravisor SEV-SNP guest (GCP N2D, AMD Milan):** the manifest digest lands in the guest-controlled `REPORT_DATA` and the report verifies against the AMD VCEK chain. On Azure use `AzureCVMProvider`.
**[SDK]** Attestation providers (`AzureCVMProvider`, `SEVSNPProvider`, `TDXProvider`, `OPAQUEProvider`, `TPMProvider`) and the chain verifier are now exported from `agent_manifest`; CLI `manifest attest` accepts `--provider azure-cvm`.
**[SDK]** `OPAQUEProvider` is now explicitly **not implemented** and fails closed at construction. The OPAQUE managed attestation service is not generally available and the SDK never verified the TRACE claim it would return (no claim-signature or `service_measurement` check — issue #201 §5); shipping a path that looked verified but was not is worse than none. Use a locally-verifiable provider (SEV-SNP / TDX / Azure CVM) for Level 1+. The prior unverified HTTP flow has been removed.

## [0.3.0] — 2026-07-15

### Security

**[SDK]** Verification can now bind trusted signing keys to authorized issuers. `VerificationContext.trusted_key_issuers` maps each trusted `key_id` to the issuer SPIFFE URIs allowed to sign with it; when supplied, a manifest whose signing key is not authorized for its declared `issuer` is rejected (fail-closed). Opt-in and backward compatible: an empty map preserves prior behavior.

### Added

**[SDK]** Delegation verification is now part of the public API: `verify_delegation_chain`, `verify_hitl_approval`, `delegation_depth_exceeded`, `DelegationHopSigner`, and `HitlApprovalSigner` are exported from `agent_manifest`. Downstream projects (for example agentrust-io/cA2A) call `verify_delegation_chain` to verify an inbound peer's delegation chain, so the two implementations stay aligned rather than duplicated. No behavior change; these were previously reachable only through the private `_delegation` module.

## [0.2.0] — 2026-06-30

### Security

**[SDK]** Delegation chain root is now bound to the manifest issuer/agent identity — forged-authority chains are rejected.
**[SDK]** Scope-narrowing enforces constraint-superset, non-increasing `ttl_seconds`, and non-increasing `max_delegation_depth`.
**[SDK]** Verification schema-validates the manifest (fail-closed); CLI `verify` no longer prints bare `VALID` when artifact bindings were not checked.

### Changed

**[SPEC]** SNP/TDX attestation field corrections and provider experimental markers (`REPORT_DATA` at `0x50`); threat-model/levels documentation scoped to what TEE attestation provides.

### Fixed

**[SDK]** `PrincipalType` set reconciled (no `service`).

### Added

**[SPEC]** Memory Checkpoint & Delta Protocol (Section 3.2.6.2) — v0.2 incremental memory binding.
- Append-only operation-log (merkle-log) model lets persistent memory evolve across a session and prove the evolution was governed, without re-approving the whole store.
- Per-representation leaf canonicalization: key-value, semantic/vector (binds embedding + model id), and graph-RAG (nodes + edges).
- A governed checkpoint advance is accepted only with a valid RFC 9162 §2.1.2 consistency proof; an unproven change still triggers v0.1 drift detection (`MEMORY_DRIFT_DETECTED`) — fail-closed preserved.

**[SDK]** `MerkleTree.consistency_proof` + `verify_consistency` (RFC 9162 §2.1.2) in `agent_manifest._merkle`.
**[SDK]** `agent_manifest._memory_delta`: `build_memory_tree`, `MemoryCheckpoint`, `verify_delta`, `fold_kv`.
**[SDK]** `MemoryCheckpointBinding` model (`memory_root` anchor; additive — `MemoryBaselineBinding` and `snapshot_hash` semantics unchanged).

**[SDK]** Export the verification API from the package root, so relying parties
and gateways call `agent_manifest.verify_manifest()` and `VerificationContext`
directly instead of importing the private `_verify` module (#176).

**[SPEC]** Document runtime-session binding guidance for gateways, including
the signed fields that bind `agent_id`, artifact hashes, validity windows,
delegation handling, and attestation separation (#177).

## [0.1.0] — 2026-06-23

Stable launch release at Confidential Computing Summit, June 23 2026.

### Fixed

**[SDK]** Enforce `poisoning_scan.result` rules in verifier — bad scan results now correctly fail closed (#167).
**[SDK]** Align Pydantic models, examples, and signing logic to the v0.1 spec (#165).
**[SDK]** Transparency log and signing error paths fully covered; fail-closed verifier restored (#168).

## [0.1.0-alpha1] — 2026-06-04

Initial developer preview. Launching at Confidential Computing Summit, June 23 2026.

### Added

**[SPEC]** v0.1 specification published.
- All 10 artifact bindings defined (Sections 3.2.1–3.2.8, 3.4, 3.5)
- Hardware attestation binding for TPM, SEV-SNP, TDX, OPAQUE (Section 3.3)
- A2A delegation chain with Cedar scope constraint evaluation (Section 3.4)
- HITL approval records with hardware-signed approver identity (Section 3.5)
- Manifest signature protocol: Ed25519 / ML-DSA-65 / hybrid (Section 3.6)
- Revocation and key rotation protocols (Sections 3.7, 3.8)
- Standard and post-quantum cryptographic profiles (Section 4)
- Verification endpoint specification with error schema (Section 5)
- Integration architecture for AGT, cMCP, MCP (Section 6)
- Threat model covering 10 threat classes (Section 7)
- Conformance levels 0–3 with 197 conformance tests across 5 modules (Section 8)
- Regulatory mapping: EU AI Act, DORA, GDPR, HIPAA, PCI-DSS, FedRAMP (Section 9)

**[SDK]** Python SDK v0.1.0-alpha1 (`pip install agent-manifest`).
- `Manifest`, `ArtifactBindings`, and all 10 artifact binding Pydantic models
- `generate_ed25519`, `Ed25519Signer` for standard-profile signing
- `verify_manifest`, `VerificationContext`, `RevocationStore` for verification
- Merkle tree computation for RAG corpus and tool manifest catalog hash
- RFC 8785 canonical JSON serialization
- Hardware provider auto-selection: OPAQUE > SEV-SNP > TDX > TPM > software
- CLI: `manifest keygen`, `create`, `sign`, `attest`, `verify`, `revoke`
- Post-quantum support via `pyoqs`: `pip install "agent-manifest[pq]"`
- Verification server: `pip install "agent-manifest[server]"`
- Python 3.11, 3.12, 3.13 support

- Python 3.11, 3.12, 3.13 support

- Python 3.11, 3.12, 3.13 support

- Python 3.11, 3.12, 3.13 support
