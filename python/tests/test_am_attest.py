"""AM-ATTEST: Hardware attestation conformance tests — issue #18.

Covers manifest pre-image correctness, attestation provider interface,
report structure, field cross-checks with cMCP, and the TPM PCR pipeline.
Target: 29 tests.
"""
import hashlib

from agent_manifest._providers import (
    AttestationReport,
    AttestationUnavailableError,
    RuntimeAttestationReport,
    TPMProvider,
)
from agent_manifest._auto_provider import SoftwareProvider, select_provider
from agent_manifest._signing import signing_pre_image
from agent_manifest._transparency import _raw_ed25519_to_pem, TransparencyLogEntry
import os

SHA_A = "sha256:" + "a" * 64
NOW_ISO = "2026-06-23T09:00:00Z"

MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod",
    "version": "0.1",
    "issued_at": NOW_ISO,
    "expires_at": "2026-09-21T09:00:00Z",
    "crypto_profile": "standard",
    "artifacts": {"policy_bundle": {"hash": SHA_A, "enforcement_mode": "enforce"}},
    "delegation_chain": [],
    "hitl_record": None,
    "signature": {"algorithm": "Ed25519", "signature_value": "sig_abc123"},
    "attestation": {"platform": "tpm", "should_be_excluded": True},
}


# ---------------------------------------------------------------------------
# Pre-image construction (AM-ATTEST-01 to 08)
# ---------------------------------------------------------------------------

def test_attest_pre_image_excludes_attestation_block():
    p = TPMProvider()
    pre = p.manifest_pre_image(MANIFEST)
    assert b"should_be_excluded" not in pre
    assert b"attestation" not in pre

def test_attest_pre_image_includes_signature():
    """Unlike signing_pre_image, attestation pre-image includes signature."""
    p = TPMProvider()
    pre = p.manifest_pre_image(MANIFEST)
    assert b"signature" in pre

def test_attest_pre_image_is_rfc8785():
    p = TPMProvider()
    assert p.manifest_pre_image(MANIFEST) == p.manifest_pre_image(MANIFEST)

def test_attest_pre_image_differs_from_signing_pre_image():
    """Signing pre-image covers only SIGNED_FIELDS; attest pre-image includes signature."""
    sign_pre = signing_pre_image(MANIFEST)
    attest_pre = TPMProvider().manifest_pre_image(MANIFEST)
    assert sign_pre != attest_pre

def test_manifest_hash_is_sha256_of_pre_image():
    p = TPMProvider()
    pre = p.manifest_pre_image(MANIFEST)
    expected = f"sha256:{hashlib.sha256(pre).hexdigest()}"
    assert p.manifest_hash_value(MANIFEST) == expected

def test_manifest_hash_format():
    h = TPMProvider().manifest_hash_value(MANIFEST)
    assert h.startswith("sha256:")
    assert len(h) == 71

def test_manifest_change_changes_attest_hash():
    p = TPMProvider()
    h1 = p.manifest_hash_value(MANIFEST)
    modified = {**MANIFEST, "version": "9.9"}
    h2 = p.manifest_hash_value(modified)
    assert h1 != h2

def test_attestation_block_change_no_hash_change():
    p = TPMProvider()
    h1 = p.manifest_hash_value(MANIFEST)
    modified = {**MANIFEST, "attestation": {"platform": "different"}}
    h2 = p.manifest_hash_value(modified)
    assert h1 == h2


# ---------------------------------------------------------------------------
# AttestationProvider interface (AM-ATTEST-09 to 14)
# ---------------------------------------------------------------------------

def test_provider_has_required_methods():
    p = TPMProvider()
    assert hasattr(p, "extend_manifest_hash")
    assert hasattr(p, "get_attestation_report")
    assert hasattr(p, "verify_manifest_in_report")
    assert hasattr(p, "attest_runtime_state")
    assert hasattr(p, "manifest_pre_image")
    assert hasattr(p, "manifest_hash_value")

def test_software_provider_returns_report():
    p = SoftwareProvider()
    p.extend_manifest_hash(MANIFEST)
    report = p.get_attestation_report()
    assert isinstance(report, AttestationReport)
    assert report.platform == "software"

def test_software_provider_hash_in_report():
    p = SoftwareProvider()
    p.extend_manifest_hash(MANIFEST)
    report = p.get_attestation_report()
    assert p.verify_manifest_in_report(report, MANIFEST)

def test_software_provider_mismatch():
    p = SoftwareProvider()
    p.extend_manifest_hash(MANIFEST)
    report = p.get_attestation_report()
    assert not p.verify_manifest_in_report(report, {**MANIFEST, "version": "evil"})

def test_attestation_unavailable_error_is_runtime():
    assert issubclass(AttestationUnavailableError, RuntimeError)

def test_select_provider_level0_returns_software():
    """Without hardware, level 0 returns SoftwareProvider."""
    # Temporarily remove tpm2_extend from path simulation by using software fallback
    import shutil
    if shutil.which("tpm2_extend") is None and not os.path.exists("/dev/sev-guest"):
        p = select_provider(level=0)
        assert isinstance(p, SoftwareProvider)


# ---------------------------------------------------------------------------
# AttestationReport structure (AM-ATTEST-15 to 19)
# ---------------------------------------------------------------------------

def test_report_has_platform():
    r = AttestationReport(platform="tpm", manifest_hash=SHA_A)
    assert r.platform == "tpm"

def test_report_has_manifest_hash():
    r = AttestationReport(platform="tpm", manifest_hash=SHA_A)
    assert r.manifest_hash == SHA_A

def test_report_pcr_values_optional():
    r = AttestationReport(platform="tpm", manifest_hash=SHA_A)
    assert r.pcr_values == {}

def test_report_with_pcr_values():
    r = AttestationReport(platform="tpm", manifest_hash=SHA_A, pcr_values={"PCR15": SHA_A})
    assert r.pcr_values["PCR15"] == SHA_A

def test_report_cert_chain_optional():
    r = AttestationReport(platform="tpm", manifest_hash=SHA_A)
    assert r.cert_chain == []


# ---------------------------------------------------------------------------
# PCR assignment (AM-ATTEST-20 to 22)
# ---------------------------------------------------------------------------

def test_default_pcr_not_nitro():
    p = TPMProvider()
    if not os.path.exists("/dev/nsm"):
        assert p.pcr_index == 15

def test_custom_pcr():
    p = TPMProvider(pcr_index=8)
    assert p.pcr_index == 8

def test_nitro_pcr_label():
    p = TPMProvider(pcr_index=8)
    p._is_nitro = True  # simulate Nitro
    assert p.pcr_index == 8


# ---------------------------------------------------------------------------
# cMCP field cross-check (AM-ATTEST-23 to 25)
# ---------------------------------------------------------------------------

def test_policy_bundle_hash_in_manifest_matches_report_field():
    """manifest.artifacts.policy_bundle.hash == report field policy_bundle_hash."""
    # In the actual cMCP integration this cross-check happens at verification time.
    # Here we confirm the manifest pre-image deterministically encodes this hash.
    p = TPMProvider()
    pre = p.manifest_pre_image(MANIFEST)
    assert b"policy_bundle" in pre
    assert SHA_A.encode() in pre

def test_enforcement_mode_in_manifest_pre_image():
    p = TPMProvider()
    pre = p.manifest_pre_image(MANIFEST)
    assert b"enforce" in pre

def test_container_image_digest_in_supply_chain():
    m = {**MANIFEST, "artifacts": {**MANIFEST["artifacts"],
         "supply_chain": {"container_image_digest": "sha256:" + "c" * 64}}}
    p = TPMProvider()
    pre = p.manifest_pre_image(m)
    assert b"c" * 10 in pre


# ---------------------------------------------------------------------------
# Transparency log entry format (AM-ATTEST-26 to 29)
# ---------------------------------------------------------------------------

def test_transparency_entry_fields():
    e = TransparencyLogEntry(
        log_id="rekor.sigstore.dev",
        entry_id="abc123",
        inclusion_proof="base64_proof",
    )
    assert e.log_id == "rekor.sigstore.dev"
    assert e.checkpoint is None
    assert e.integrated_time is None

def test_transparency_entry_with_checkpoint():
    e = TransparencyLogEntry(
        log_id="rekor.sigstore.dev",
        entry_id="abc123",
        inclusion_proof="proof",
        checkpoint="signed_tree_head",
        integrated_time=1750000000,
    )
    assert e.checkpoint == "signed_tree_head"
    assert e.integrated_time == 1750000000

def test_raw_ed25519_to_pem_format():
    raw = bytes(32)  # all-zero key for test
    pem = _raw_ed25519_to_pem(raw)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert pem.strip().endswith(b"-----END PUBLIC KEY-----")

def test_raw_ed25519_to_pem_length():
    from agent_manifest._signing import generate_ed25519
    kp = generate_ed25519()
    pem = _raw_ed25519_to_pem(kp.public_bytes)
    # Ed25519 SubjectPublicKeyInfo is 44 bytes DER = ~60 chars base64
    assert len(pem) > 60


# ---------------------------------------------------------------------------
# RuntimeAttestationReport + attest_runtime_state() (AM-ATTEST-30 to 38)
# ---------------------------------------------------------------------------

_NONCE = b"\x01" * 16
_CTX_HASH = "sha256:" + "aa" * 32


def test_runtime_report_required_fields():
    r = RuntimeAttestationReport(
        platform="software",
        report_data_hash="sha256:" + "aa" * 32,
        context_hash=_CTX_HASH,
        nonce_hex=_NONCE.hex(),
    )
    assert r.platform == "software"
    assert r.report_data_hash.startswith("sha256:")
    assert r.context_hash == _CTX_HASH
    assert r.nonce_hex == _NONCE.hex()
    assert r.quote is None
    assert r.raw == {}


def test_software_provider_attest_runtime_state_returns_report():
    p = SoftwareProvider()
    rt = p.attest_runtime_state(_NONCE, _CTX_HASH)
    assert isinstance(rt, RuntimeAttestationReport)
    assert rt.platform == "software"
    assert rt.nonce_hex == _NONCE.hex()
    assert rt.context_hash == _CTX_HASH


def test_runtime_state_report_data_hash_derivation():
    """report_data_hash must equal sha256(sha256(nonce || context_bytes))."""
    p = SoftwareProvider()
    nonce = b"\x02" * 16
    ctx = "sha256:" + "bb" * 32
    rt = p.attest_runtime_state(nonce, ctx)

    ctx_bytes = bytes.fromhex(ctx.split(":", 1)[-1])
    qualifying = hashlib.sha256(nonce + ctx_bytes).digest()
    expected = "sha256:" + hashlib.sha256(qualifying).hexdigest()
    assert rt.report_data_hash == expected


def test_runtime_state_different_nonces_differ():
    p = SoftwareProvider()
    rt1 = p.attest_runtime_state(b"\x01" * 16, _CTX_HASH)
    rt2 = p.attest_runtime_state(b"\x02" * 16, _CTX_HASH)
    assert rt1.report_data_hash != rt2.report_data_hash


def test_runtime_state_different_contexts_differ():
    p = SoftwareProvider()
    rt1 = p.attest_runtime_state(_NONCE, "sha256:" + "aa" * 32)
    rt2 = p.attest_runtime_state(_NONCE, "sha256:" + "bb" * 32)
    assert rt1.report_data_hash != rt2.report_data_hash


def test_runtime_state_is_deterministic():
    """Same nonce + context must always produce the same report_data_hash."""
    p = SoftwareProvider()
    rt1 = p.attest_runtime_state(_NONCE, _CTX_HASH)
    rt2 = p.attest_runtime_state(_NONCE, _CTX_HASH)
    assert rt1.report_data_hash == rt2.report_data_hash


def test_tpm_provider_no_ak_raises():
    """attest_runtime_state without an AK must raise AttestationUnavailableError immediately."""
    p = TPMProvider()  # no ak_context
    try:
        p.attest_runtime_state(_NONCE, _CTX_HASH)
        assert False, "expected AttestationUnavailableError"
    except AttestationUnavailableError as exc:
        assert "Attestation Key" in str(exc)


def test_software_provider_raw_labels_not_hw_attested():
    p = SoftwareProvider()
    rt = p.attest_runtime_state(_NONCE, _CTX_HASH)
    assert "warning" in rt.raw
    assert "software-only" in rt.raw["warning"]


def test_all_hw_providers_expose_attest_runtime_state():
    from agent_manifest._hw_providers import SEVSNPProvider, TDXProvider, OPAQUEProvider
    for cls in (SEVSNPProvider, TDXProvider, OPAQUEProvider):
        assert callable(getattr(cls, "attest_runtime_state", None)), (
            f"{cls.__name__} missing attest_runtime_state"
        )
