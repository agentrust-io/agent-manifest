"""PLATFORM_INFO appraisal composed with verify_manifest() (LIMITATIONS.md
"Platform state: appraised only if you ask").

``verify_manifest()`` never calls ``appraise_platform_info()`` itself, and
that is by design (see the docstring on
``VerificationContext.verified_attestation_manifest_hashes``): PLATFORM_INFO
appraisal, like hardware signature/chain appraisal via
``verify_attestation_chain()``, reaches ``verify_manifest()`` only as a result
the caller already computed and placed in
``VerificationContext.verified_attestation_manifest_hashes`` neither
appraisal function is called by ``verify_manifest()`` itself. This is an
integration-style test of that documented caller-side composition, run
through the actual ``verify_manifest()`` path against a cryptographically
self-consistent synthetic SEV-SNP report and certificate chain (same
technique as ``test_attestation_chain.py``, extended with PLATFORM_INFO bits
freshly generated keys shaped like the real VCEK/ASK/ARK hierarchy, not
AMD-rooted hardware evidence; see ``_snp_synthetic.py``).

What this demonstrates: when a caller performs both appraisals and withholds
the trusted hash exactly when platform appraisal fails, ``verify_manifest()``
gives the correct result it respects ``verified_attestation_manifest_hashes``
exactly as documented. The policy decision itself (add the hash only if both
appraisals pass) is implemented in this test's own helper, not by any new
production code this patch adds. It does *not* demonstrate that some
production integration automatically performs this composition, and it does
*not* mean the SDK enforces a platform policy automatically nothing here
adds a call inside ``verify_manifest()`` or a field on ``VerificationContext``;
the caller is still the one deciding whether to call
``appraise_platform_info()`` and whether to act on it.

    1. Baseline: ``appraise_platform_info()`` is never called at all ->
       behavior is identical to every caller before PLATFORM_INFO existed.
    2. Calling ``appraise_platform_info()`` with no ``require``/``forbid``
       is a no-op through this same path, same as not calling it (the
       bit-level version of this claim is already pinned in
       ``test_snp_verify.py::test_empty_policy_asserts_nothing_and_says_so``;
       this repeats it through the full verify_manifest() path).
    3. A policy is applied and satisfied -> still VALID.
    4. Only the ``require`` clause is violated (``forbid`` is satisfied) ->
       ATTESTATION_UNAVAILABLE.
    5. Only the ``forbid`` clause is violated (``require`` is satisfied) ->
       ATTESTATION_UNAVAILABLE. (4) and (5) are kept separate so a bug that
       breaks one direction while leaving the other looking correct - the
       exact shape of the go-sev-guest#195 bug ``appraise_platform_info()``
       itself guards against, see ``test_snp_verify.py`` - cannot hide
       behind a report that happens to violate both at once.
    6. Both clauses are violated at once -> still ATTESTATION_UNAVAILABLE,
       covering the case a real misconfigured host is most likely to hit.
    7. Hardware appraisal itself fails (a byte inside the signed body is
       flipped after signing) while PLATFORM_INFO alone would satisfy the
       policy -> platform appraisal must never even be reached, and the
       result must still be ATTESTATION_UNAVAILABLE. The result alone can't
       distinguish a correct short-circuit from a broken one that happens to
       land on the same verdict (the final gate is `hw_result.passed AND
       platform_ok` either way), so appraise_platform_info() is monkeypatched
       to fail the test if it is called at all.
    8. A genuinely malformed report (truncated to 100 bytes) makes
       verify_attestation_chain() fail closed without raising - it already
       wraps its own report parsing in a try/except. The concrete crash
       scenario the ordering fix prevents is a caller's *second*,
       unprotected parse_snp_report() call (made to read PLATFORM_INFO) on
       those same truncated bytes; under the corrected ordering that call is
       never reached, and the whole composition completes without raising.
       This is the ordering the hardware-attestation tutorial's composition
       sketch follows: check hardware appraisal first, only attempt platform
       appraisal once it has passed.
    9. PLATFORM_INFO is inside the signed report body (offset 0x40, within
       the 0x2A0-byte signed region): flipping just that field *after*
       signing, without re-signing, must fail hardware signature
       verification rather than silently change what gets appraised. This
       is the executable backing for the corrected claim in the
       hardware-attestation tutorial: the field is authenticated, only its
       policy meaning is unevaluated by ``verify_attestation_chain()``.

Scope: this exercises the v0.1 detached-signature manifest path
(``verify_manifest()`` called directly on a dict), not the v0.2 COSE
envelope path - this file does not build or verify a COSE envelope. Per
``_verify.py::_verify_cose_envelope``'s own docstring, the v0.2 path uses
the identical shared attestation-appraisal pipeline (the same
``verified_attestation_manifest_hashes`` gate exercised here), so this is an
architectural note about where that gate lives, not a claim that this file
covers the v0.2 wire format.
"""
from __future__ import annotations

import copy
import sys
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from agent_manifest import (
    ArtifactBindings,
    CryptoProfile,
    DeploymentType,
    Ed25519Signer,
    EnforcementMode,
    Manifest,
    ModelAttestationType,
    ModelIdentityBinding,
    OverallResult,
    PolicyBundleBinding,
    PolicyLanguage,
    SNP_OFFSETS,
    SNP_REPORT_LEN,
    SnpVerificationError,
    SystemPromptBinding,
    appraise_platform_info,
    canonical_hash,
    generate_ed25519,
    parse_platform_info,
    parse_snp_report,
)
from agent_manifest._attestation import SignatureStatus, verify_attestation_chain
from agent_manifest._providers import AttestationReport
from agent_manifest._types import HashValue, ManifestId
from agent_manifest._verify import RevocationStore, VerificationContext, verify_manifest

from ._snp_synthetic import build_synthetic_snp_report_with_chain

MEASUREMENT = "ab" * 48
SYSTEM_PROMPT_HASH = "sha256:" + "a" * 64
POLICY_BUNDLE_HASH = "sha256:" + "b" * 64

# PLATFORM_INFO_BITS (agent_manifest.PLATFORM_INFO_BITS, see _snp_verify.py):
# "alias_check_complete" is bit 5, "smt_enabled" is bit 0.
_ALIAS_CHECK_BIT = 1 << 5
_SMT_BIT = 1 << 0

POLICY = {"require": {"alias_check_complete"}, "forbid": {"smt_enabled"}}

# The four reachable combinations of the two bits this policy inspects.
PLATFORM_INFO_BOTH_SATISFIED = _ALIAS_CHECK_BIT  # alias check done, SMT off
PLATFORM_INFO_REQUIRE_VIOLATED_ONLY = 0  # alias check NOT done, SMT off
PLATFORM_INFO_FORBID_VIOLATED_ONLY = _ALIAS_CHECK_BIT | _SMT_BIT  # alias check done, SMT on
PLATFORM_INFO_BOTH_VIOLATED = _SMT_BIT  # alias check NOT done, SMT on


def _build_signed_manifest():
    now = datetime.now(timezone.utc)
    manifest = Manifest(
        manifest_id=ManifestId("019236ab-cdef-7000-8000-0000000000aa"),
        agent_id="spiffe://trust.acme.co/agent/platform-info-demo/prod",
        issued_at=now,
        expires_at=now + timedelta(days=90),
        issuer="spiffe://trust.acme.co/signing-authority",
        crypto_profile=CryptoProfile.standard,
        artifacts=ArtifactBindings(
            system_prompt=SystemPromptBinding(
                hash=HashValue(SYSTEM_PROMPT_HASH),
                hash_algorithm="SHA-256",
                version="1.0.0",
                classification="internal",
                bound_at=now,
            ),
            policy_bundle=PolicyBundleBinding(
                hash=HashValue(POLICY_BUNDLE_HASH),
                policy_language=PolicyLanguage.cedar,
                version="1.0.0",
                enforcement_mode=EnforcementMode.enforce,
                bound_at=now,
            ),
            model_identity=ModelIdentityBinding(
                provider="example",
                model_id="demo-model",
                version="demo-v1",
                deployment_type=DeploymentType.api,
                model_attestation_type=ModelAttestationType.provider_asserted,
                bound_at=now,
            ),
        ),
    )
    keypair = generate_ed25519()
    record = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
    record["signature"] = Ed25519Signer(keypair).sign(record)
    return record, keypair


def _base_context(keypair) -> VerificationContext:
    return VerificationContext(
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        enforcement_mode="enforce",
        model_version="demo-v1",
        trusted_keys={keypair.key_id: keypair.public_b64url()},
        enforce_attestation=True,
    )


def _attest(
    record: dict, *, platform_info_bits: int,
) -> tuple[dict, AttestationReport, bytes, bytes]:
    """Bind a synthetic SNP report (carrying ``platform_info_bits``) to
    *record*, and append the attestation block the way
    ``manifest attest --provider sev-snp`` does (see cli.py)."""
    # Spec 3.3: the pre-image the report binds excludes "attestation" and
    # "transparency_log_entry" - neither is present yet at this point, so the
    # manifest as it stands right now IS that pre-image.
    expected_hash = canonical_hash(record)
    digest_hex = expected_hash.split(":", 1)[1]

    snp_bytes, vcek_der, chain_pem = build_synthetic_snp_report_with_chain(
        digest_hex, MEASUREMENT, platform_info=platform_info_bits,
    )
    report = AttestationReport(
        platform="amd-sev-snp",
        manifest_hash=expected_hash,
        quote=snp_bytes,
        raw={"report_data": digest_hex + "00" * 32, "measurement": MEASUREMENT},
    )

    attested = copy.deepcopy(record)
    attested["attestation"] = {
        "platform": "amd-sev-snp",
        "manifest_hash_in_report": expected_hash,
        "audit_key_sealed": True,
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return attested, report, vcek_der, chain_pem


def _verify_chain(
    report: AttestationReport, *, expected_hash: str, vcek_der: bytes, chain_pem: bytes,
):
    """The signature/chain/measurement appraisal every caller already needs
    to do today, unrelated to PLATFORM_INFO."""
    return verify_attestation_chain(
        report,
        expected_manifest_hash=expected_hash,
        expected_measurements={MEASUREMENT},
        snp_report_bytes=report.quote,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain_pem,
    )


def _appraise_platform(platform_info_bits: int, *, require=None, forbid=None) -> bool:
    """Decode PLATFORM_INFO from the given bits via the real report-parsing
    path (not the bits constant directly) and appraise it. Returns whether
    the policy was satisfied; ``require``/``forbid`` default to this file's
    ``POLICY`` when omitted.

    ``parse_snp_report()`` is pure struct-unpacking with no cryptographic
    check, so this uses a bare zero-filled buffer with only the
    PLATFORM_INFO field set, instead of a signed report + VCEK/ASK/ARK
    chain: it exercises the same parse path without the unrelated cost of
    generating and signing a certificate chain nobody here verifies.
    """
    buf = bytearray(SNP_REPORT_LEN)
    buf[SNP_OFFSETS["platform_info"]:SNP_OFFSETS["platform_info"] + 8] = (
        platform_info_bits.to_bytes(8, "little")
    )
    platform_info = parse_platform_info(parse_snp_report(bytes(buf)).platform_info)
    try:
        appraise_platform_info(
            platform_info,
            require=POLICY["require"] if require is None else require,
            forbid=POLICY["forbid"] if forbid is None else forbid,
        )
        return True
    except SnpVerificationError:
        return False


def _run_composed_verify(
    *, platform_info_bits: int, apply_policy: bool, tamper_signed_body: bool = False,
):
    """Run the exact composition the hardware-attestation tutorial shows:
    hardware appraisal first, and platform appraisal only attempted once
    hardware appraisal has already passed - a tampered or malformed report
    can fail hardware appraisal on its own, and there is no reason to also
    risk parsing PLATFORM_INFO from the same bad bytes, or to trust
    PLATFORM_INFO from a report whose signature never verified. Then
    ``verify_manifest()``. Returns the ``VerificationResult``.

    ``tamper_signed_body=True`` flips a byte inside the signed report body
    (without re-signing) to force ``hw_result.passed`` to False, for testing
    that short-circuit.
    """
    record, keypair = _build_signed_manifest()
    attested, report, vcek_der, chain_pem = _attest(record, platform_info_bits=platform_info_bits)
    expected_hash = report.manifest_hash

    if tamper_signed_body:
        quote = bytearray(report.quote)
        quote[0x90] ^= 0xFF  # flip a measurement byte inside the signed body, do not re-sign
        report = AttestationReport(
            platform=report.platform, manifest_hash=report.manifest_hash,
            quote=bytes(quote), raw=report.raw,
        )

    hw_result = _verify_chain(
        report, expected_hash=expected_hash, vcek_der=vcek_der, chain_pem=chain_pem,
    )
    if not tamper_signed_body:
        assert hw_result.passed, (
            "test setup produced a report that does not even pass hardware appraisal"
        )

    platform_ok = False
    if hw_result.passed:
        if apply_policy:
            platform_info = parse_platform_info(parse_snp_report(report.quote).platform_info)
            try:
                appraise_platform_info(platform_info, **POLICY)
                platform_ok = True
            except SnpVerificationError:
                platform_ok = False
        else:
            platform_ok = True  # no policy requested; hardware appraisal alone decides

    context = _base_context(keypair)
    if hw_result.passed and platform_ok:
        context.verified_attestation_manifest_hashes.add(expected_hash)
        context.attestation_evidence_manifest_id = attested["manifest_id"]

    return verify_manifest(attested, context, RevocationStore())


def test_baseline_appraise_platform_info_never_called_is_unaffected():
    """A caller that never calls appraise_platform_info() at all - exactly
    every caller before PLATFORM_INFO existed - sees no change: hardware
    appraisal alone still gates VALID, regardless of what PLATFORM_INFO
    would have said if anyone had looked."""
    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_BOTH_VIOLATED, apply_policy=False,
    )
    assert result.attestation_verified is True
    assert result.result == OverallResult.VALID


def test_appraise_platform_info_with_empty_policy_is_a_noop_end_to_end():
    """Calling appraise_platform_info() with no require/forbid is documented
    to assert nothing (test_snp_verify.py pins this at the bit level); this
    confirms the same through the full verify_manifest() path, with a report
    that would fail POLICY if it were applied."""
    record, keypair = _build_signed_manifest()
    attested, report, vcek_der, chain_pem = _attest(
        record, platform_info_bits=PLATFORM_INFO_BOTH_VIOLATED,
    )
    expected_hash = report.manifest_hash

    hw_result = _verify_chain(
        report, expected_hash=expected_hash, vcek_der=vcek_der, chain_pem=chain_pem,
    )
    assert hw_result.passed

    platform_info = parse_platform_info(parse_snp_report(report.quote).platform_info)
    appraise_platform_info(platform_info)  # empty policy - must not raise

    context = _base_context(keypair)
    context.verified_attestation_manifest_hashes.add(expected_hash)
    context.attestation_evidence_manifest_id = attested["manifest_id"]

    result = verify_manifest(attested, context, RevocationStore())
    assert result.attestation_verified is True
    assert result.result == OverallResult.VALID


def test_platform_policy_satisfied_reaches_valid():
    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_BOTH_SATISFIED, apply_policy=True,
    )
    assert result.attestation_verified is True
    assert result.result == OverallResult.VALID


def test_require_violation_alone_blocks_valid():
    """alias_check_complete unset, smt_enabled unset: forbid is satisfied,
    require is not. Isolated from the forbid case so a bug in one direction
    cannot hide behind a report that also happens to fail the other."""
    assert _appraise_platform(PLATFORM_INFO_REQUIRE_VIOLATED_ONLY) is False
    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_REQUIRE_VIOLATED_ONLY, apply_policy=True,
    )
    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_forbid_violation_alone_blocks_valid():
    """alias_check_complete set, smt_enabled set: require is satisfied,
    forbid is not."""
    assert _appraise_platform(PLATFORM_INFO_FORBID_VIOLATED_ONLY) is False
    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_FORBID_VIOLATED_ONLY, apply_policy=True,
    )
    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_both_clauses_violated_blocks_valid_despite_hardware_signature_passing():
    """The report's signature, chain, and measurement all pass appraisal -
    this is not a forged or tampered report. PLATFORM_INFO reports SMT on
    and alias_check_complete unset, violating both clauses of the caller's
    policy at once (the case a real misconfigured host is most likely to
    hit). The manifest hash must not reach
    verified_attestation_manifest_hashes, so enforce_attestation=True must
    yield ATTESTATION_UNAVAILABLE, never VALID, even though hardware
    appraisal alone would have passed."""
    assert _appraise_platform(PLATFORM_INFO_BOTH_VIOLATED) is False
    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_BOTH_VIOLATED, apply_policy=True,
    )
    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_hardware_appraisal_failure_short_circuits_before_platform_info_is_reached(monkeypatch):
    """The composition must check hardware appraisal first and only attempt
    platform appraisal once it has passed - not the reverse. Here a
    measurement byte is flipped after signing (hw_result.passed is False)
    while PLATFORM_INFO itself still satisfies the policy, so a regression
    that dropped the ordering guard would still coincidentally land on
    ATTESTATION_UNAVAILABLE too (the final gate is `hw_result.passed AND
    platform_ok`) - the result alone cannot tell a correct short-circuit
    apart from a broken one that happens to be masked. appraise_platform_info
    is monkeypatched to fail the test if called at all, so this proves
    platform appraisal is genuinely never reached, not just that its outcome
    didn't end up mattering.

    This also backs the corrected ordering in the hardware-attestation
    tutorial: running appraise_platform_info() unconditionally, before
    checking hw_result.passed, risked parse_snp_report() raising on the very
    bytes hardware appraisal had already rejected, before the caller ever
    reached its decision (see the next test for that crash scenario
    specifically)."""

    def _fail_if_called(*args, **kwargs):
        pytest.fail(
            "appraise_platform_info() must not be called once hardware appraisal has failed"
        )

    monkeypatch.setattr(sys.modules[__name__], "appraise_platform_info", _fail_if_called)

    result = _run_composed_verify(
        platform_info_bits=PLATFORM_INFO_BOTH_SATISFIED,
        apply_policy=True,
        tamper_signed_body=True,
    )
    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_malformed_report_bytes_do_not_crash_the_composition():
    """The concrete crash scenario the ordering fix above prevents:
    verify_attestation_chain() already fails closed on a too-short report
    (parse_snp_report() raises SnpVerificationError internally, caught by
    _verify_snp_signature_step and turned into SignatureStatus.FAILED - see
    _attestation.py). But a caller's *own* second parse_snp_report() call,
    made to read PLATFORM_INFO, is not inside that try/except. Under the
    corrected ordering (only parse once hw_result.passed), that second call
    is never reached against these same truncated bytes, so the composition
    completes without raising."""
    record, keypair = _build_signed_manifest()
    attested, report, vcek_der, chain_pem = _attest(
        record, platform_info_bits=PLATFORM_INFO_BOTH_SATISFIED,
    )
    expected_hash = report.manifest_hash

    truncated_report = AttestationReport(
        platform=report.platform,
        manifest_hash=report.manifest_hash,
        quote=report.quote[:100],  # well under SNP_REPORT_LEN (1184 bytes)
        raw=report.raw,
    )

    hw_result = _verify_chain(
        truncated_report, expected_hash=expected_hash, vcek_der=vcek_der, chain_pem=chain_pem,
    )
    assert hw_result.passed is False  # fails closed, does not raise

    # The tutorial's corrected composition, inline: platform appraisal is
    # only attempted once hardware appraisal has passed. With hw_result
    # already False, parse_snp_report(truncated_report.quote) - which would
    # raise SnpVerificationError on these 100 bytes - must never run.
    platform_ok = False
    if hw_result.passed:
        platform_info = parse_platform_info(parse_snp_report(truncated_report.quote).platform_info)
        try:
            appraise_platform_info(platform_info, **POLICY)
            platform_ok = True
        except SnpVerificationError:
            platform_ok = False

    context = _base_context(keypair)
    if hw_result.passed and platform_ok:
        context.verified_attestation_manifest_hashes.add(expected_hash)
        context.attestation_evidence_manifest_id = attested["manifest_id"]

    result = verify_manifest(attested, context, RevocationStore())  # must not raise
    assert result.attestation_verified is False
    assert result.result == OverallResult.ATTESTATION_UNAVAILABLE


def test_platform_info_is_covered_by_the_signature_not_just_parsed_from_it():
    """PLATFORM_INFO lives at offset 0x40, inside the 0x2A0-byte region the
    SNP signature covers (see _snp_verify.py: signed_body=report[:_OFF_SIGNATURE]).
    Flipping a bit there *after* signing, without re-signing, must fail
    hardware signature verification - not silently produce a different
    PLATFORM_INFO appraisal from an otherwise-valid report. This is the
    executable backing for the hardware-attestation tutorial's corrected
    claim: the field is authenticated; only its policy meaning goes
    unevaluated by verify_attestation_chain()."""
    record, keypair = _build_signed_manifest()
    attested, report, vcek_der, chain_pem = _attest(
        record, platform_info_bits=PLATFORM_INFO_BOTH_SATISFIED,
    )
    expected_hash = report.manifest_hash

    good = _verify_chain(
        report, expected_hash=expected_hash, vcek_der=vcek_der, chain_pem=chain_pem,
    )
    assert good.signature == SignatureStatus.VERIFIED

    tampered_quote = bytearray(report.quote)
    tampered_quote[0x40] ^= 0xFF  # flip the PLATFORM_INFO byte, do not re-sign
    tampered_report = AttestationReport(
        platform=report.platform,
        manifest_hash=report.manifest_hash,
        quote=bytes(tampered_quote),
        raw=report.raw,
    )
    tampered = _verify_chain(
        tampered_report, expected_hash=expected_hash, vcek_der=vcek_der, chain_pem=chain_pem,
    )
    assert tampered.signature == SignatureStatus.FAILED
    assert tampered.passed is False
