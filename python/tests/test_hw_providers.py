"""Tests for hardware attestation providers: SEVSNPProvider, TDXProvider, OPAQUEProvider.

Strategy:
  Initialization failures (no device / no env var): tested on all platforms by
    mocking os.path.exists — no hardware required.
  get_attestation_report() before extend_manifest_hash(): always raises, no mock.
  verify_manifest_in_report(): pure Python hash comparison, no mock.
  extend_manifest_hash for SEVSNPProvider/TDXProvider: mock fcntl.ioctl + open
    so struct packing and report-parsing code paths run without hardware.
    Gated by sys.platform == "linux" because fcntl is Linux-only.
  extend_manifest_hash for OPAQUEProvider: mock httpx.post, runs on all platforms.
    Tests auth header, pre-image encoding, HTTP error handling.
  Integration markers: NEEDS_SEV_SNP, NEEDS_TDX, NEEDS_OPAQUE for real hardware.
"""
import os
import struct
import sys

import pytest

from agent_manifest._hw_providers import (
    OPAQUEProvider,
    SEVSNPProvider,
    TDXProvider,
)
from agent_manifest._providers import AttestationReport, AttestationUnavailableError

LINUX = sys.platform == "linux"

NEEDS_SEV_SNP = pytest.mark.skipif(
    not (os.path.exists("/sys/module/sev_guest") and os.path.isdir("/sys/kernel/config/tsm/report")),
    reason="requires a bare-metal SNP guest with the sev-guest driver + configfs-TSM",
)
NEEDS_TDX = pytest.mark.skipif(
    not (
        (os.path.exists("/sys/module/tdx_guest") or os.path.exists("/dev/tdx_guest"))
        and os.path.isdir("/sys/kernel/config/tsm/report")
    ),
    reason="requires an Intel TDX guest with the tdx-guest driver + configfs-TSM",
)
NEEDS_OPAQUE = pytest.mark.skipif(
    not os.environ.get("OPAQUE_ATTESTATION_URL"),
    reason="set OPAQUE_ATTESTATION_URL to run OPAQUE integration tests",
)

SAMPLE_MANIFEST = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "agent_id": "spiffe://trust.example/agent/kyc/prod",
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "expires_at": "2026-09-21T09:00:00Z",
    "issuer": "spiffe://trust.example/signing-authority",
    "crypto_profile": "standard",
    "artifacts": {},
    "delegation_chain": [],
    "hitl_record": None,
    "signature": {"algorithm": "Ed25519", "signature_value": "abc"},
}


# ---------------------------------------------------------------------------
# SEVSNPProvider — initialization and pure-Python paths
# ---------------------------------------------------------------------------


TSM_DIR = "/sys/kernel/config/tsm/report"


def _snp_report_with(report_data: bytes, measurement: bytes = bytes(range(48))) -> bytes:
    """Build a minimal 1184-byte SNP report carrying the given fields."""
    buf = bytearray(0x4A0)
    buf[0x00:0x04] = (3).to_bytes(4, "little")  # version
    buf[0x50:0x50 + len(report_data)] = report_data
    buf[0x90:0x90 + 48] = measurement
    return bytes(buf)


def test_sevsnp_raises_without_device(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: False)
    with pytest.raises(AttestationUnavailableError, match="SEV-SNP"):
        SEVSNPProvider()


def test_sevsnp_report_before_extend_raises(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()
    with pytest.raises(AttestationUnavailableError, match="extend_manifest_hash"):
        provider.get_attestation_report()


def test_sevsnp_verify_manifest_match(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()
    expected = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="amd-sev-snp", manifest_hash=expected)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_sevsnp_verify_manifest_mismatch(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()
    report = AttestationReport(platform="amd-sev-snp", manifest_hash="sha256:" + "00" * 32)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_sevsnp_extend_with_mocked_tsm(monkeypatch):
    """extend + get_attestation_report over a mocked configfs-TSM report."""
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()

    import agent_manifest._hw_providers as hw

    def fake_tsm(report_data):
        # Real hardware echoes the request's report data into REPORT_DATA (0x50).
        return _snp_report_with(report_data), "sev_guest", None

    monkeypatch.setattr(hw, "_tsm_get_report", fake_tsm)
    provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.platform == "amd-sev-snp"
    assert report.manifest_hash.startswith("sha256:")
    assert report.raw["measurement"] == bytes(range(48)).hex()
    # REPORT_DATA carries the manifest digest in its first 32 bytes.
    digest = provider.manifest_hash_value(SAMPLE_MANIFEST).split(":", 1)[1]
    assert report.raw["report_data"][:64] == digest


def test_sevsnp_wrong_tsm_provider_raises(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()

    import agent_manifest._hw_providers as hw

    monkeypatch.setattr(
        hw, "_tsm_get_report", lambda rd: (_snp_report_with(rd), "tdx_guest", None)
    )
    with pytest.raises(AttestationUnavailableError, match="not 'sev_guest'"):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)


def test_sevsnp_extend_manifest_hash_value_matches(monkeypatch):
    """verify_manifest_in_report compares REPORT_DATA from the captured bytes."""
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = SEVSNPProvider()

    import agent_manifest._hw_providers as hw

    monkeypatch.setattr(
        hw, "_tsm_get_report", lambda rd: (_snp_report_with(rd), "sev_guest", None)
    )
    provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.manifest_hash == provider.manifest_hash_value(SAMPLE_MANIFEST)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


# ---------------------------------------------------------------------------
# AzureCVMProvider — detection and PCR-replay verification (mocked tpm2)
# ---------------------------------------------------------------------------


def test_azure_unavailable_without_hcl_index(monkeypatch):
    import agent_manifest._hw_providers as hw

    def raise_tpm(args):
        raise AttestationUnavailableError("tpm2_nvreadpublic ... handle not found")

    monkeypatch.setattr(hw, "_run_tpm", raise_tpm)
    from agent_manifest._hw_providers import AzureCVMProvider

    with pytest.raises(AttestationUnavailableError, match="Azure confidential VM"):
        AzureCVMProvider()


import base64  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402

from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding as _padding  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding as _Encoding,
    PublicFormat as _PublicFormat,
)

from agent_manifest._tpm_verify import (  # noqa: E402
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
)


def _azure_build_attest(
    qualifying_data: bytes, pcr_digest: bytes, *, hash_alg: int = 0x000B, bitmap: bytes = b"\x00\x00\x01"
) -> bytes:
    """Minimal structurally-valid TPMS_ATTEST (single PCR-bank selection)."""
    out = TPM_GENERATED_VALUE.to_bytes(4, "big")
    out += TPM_ST_ATTEST_QUOTE.to_bytes(2, "big")
    out += (0).to_bytes(2, "big")  # qualifiedSigner: empty TPM2B_NAME
    out += len(qualifying_data).to_bytes(2, "big") + qualifying_data
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8  # firmwareVersion
    out += (1).to_bytes(4, "big")  # TPML_PCR_SELECTION count
    out += hash_alg.to_bytes(2, "big")
    out += len(bitmap).to_bytes(1, "big")  # sizeofSelect
    out += bitmap
    out += len(pcr_digest).to_bytes(2, "big") + pcr_digest
    return out


def _azure_tpmt_sign(ak_key, attest: bytes) -> bytes:
    """RSASSA/SHA-256 TPMT_SIGNATURE over ``attest``."""
    sig = ak_key.sign(attest, _padding.PKCS1v15(), _hashes.SHA256())
    return (0x0014).to_bytes(2, "big") + (0x000B).to_bytes(2, "big") + len(sig).to_bytes(2, "big") + sig


def _azure_good_fixture(provider, manifest=SAMPLE_MANIFEST):
    """Build a fully self-consistent, cryptographically-valid Azure evidence set.

    Returns a dict of the raw-report fields plus the SNP report bytes, all
    genuinely tied together: the AK signs a quote over the manifest PCR, the
    AK is embedded in runtime_data, and runtime_data is bound (via
    REPORT_DATA) into the SNP report -- exactly the composite chain
    ``verify_manifest_in_report`` must authenticate.
    """
    digest = provider.manifest_hash_value(manifest).split(":", 1)[1]
    expected_pcr_value = hashlib.sha256(bytes(32) + bytes.fromhex(digest)).digest()
    pcr_digest = hashlib.sha256(expected_pcr_value).digest()

    ak_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_pub_pem = ak_key.public_key().public_bytes(
        _Encoding.PEM, _PublicFormat.SubjectPublicKeyInfo
    ).decode()

    quote_msg = _azure_build_attest(bytes(16), pcr_digest)
    quote_sig = _azure_tpmt_sign(ak_key, quote_msg)

    numbers = ak_key.public_key().public_numbers()
    modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    n_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=").decode()
    runtime_data = json.dumps({"keys": [{"kid": "HCLAkPub", "n": n_b64, "e": "AQAB"}]}).encode()

    report_data = hashlib.sha256(runtime_data).digest() + bytes(32)
    snp_report_bytes = _snp_report_with(report_data)

    return {
        "digest": digest,
        "manifest_hash": f"sha256:{digest}",
        "snp_report_bytes": snp_report_bytes,
        "raw": {
            "ak_pub_pem": ak_pub_pem,
            "runtime_data_hex": runtime_data.hex(),
            "quote_msg": base64.b64encode(quote_msg).decode(),
            "quote_sig": base64.b64encode(quote_sig).decode(),
        },
        "ak_key": ak_key,
        "pcr_digest": pcr_digest,
    }


def _azure_report_from_fixture(fx, *, raw_overrides=None, quote_override=None):
    raw = dict(fx["raw"])
    if raw_overrides:
        raw.update(raw_overrides)
    return AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=fx["manifest_hash"],
        quote=fx["snp_report_bytes"] if quote_override is None else quote_override,
        raw=raw,
    )


def test_azure_verify_manifest_full_chain_passes(monkeypatch):
    """Positive path: every link of the composite chain genuinely verifies."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider


    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    report = _azure_report_from_fixture(fx)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is True


def test_azure_verify_manifest_uses_provider_pcr_index_not_self_reported_raw(monkeypatch):
    """A provider configured for PCR 17 must check PCR 17 -- and a self-reported
    ``raw["pcr_index"]`` claiming a different value must not override that.
    Exercises the fix for the gap: the expected index must come from verifier 
    configuration, not from the report itself.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=17)
    # _azure_good_fixture always signs over the PCR16 bitmap regardless of
    # provider._pcr, so build the PCR17-selection quote by hand here.
    fx = _azure_good_fixture(provider)
    quote_msg_17 = _azure_build_attest(bytes(16), fx["pcr_digest"], bitmap=b"\x00\x00\x02")
    sig_17 = _azure_tpmt_sign(fx["ak_key"], quote_msg_17)
    # Claim (falsely, and irrelevantly) that this report is about PCR 16.
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(quote_msg_17).decode(),
            "quote_sig": base64.b64encode(sig_17).decode(),
            "pcr_index": 16,
        },
    )
    # Still passes: the provider's own configured pcr_index (17) is what's
    # actually checked, and it genuinely matches the signed selection.
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is True

    other_provider = AzureCVMProvider(pcr_index=16)
    # The same evidence checked against a *differently configured* provider
    # (expecting PCR 16, but the quote was signed over PCR 17) must fail --
    # confirming the check is real and not vacuously true.
    assert other_provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject(monkeypatch):
    """fabricated pcr_read, no AK evidence.

    A report whose ``raw`` carries a matching ``pcr_read`` string but omits
    ``ak_pub_pem``, ``quote_msg``, ``quote_sig``, and any runtime-data binding
    evidence must never verify -- ``pcr_read`` is not signed by anything.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)

    digest = provider.manifest_hash_value(SAMPLE_MANIFEST).split(":", 1)[1]
    expected_pcr = hashlib.sha256(bytes(32) + bytes.fromhex(digest)).hexdigest()
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=f"sha256:{digest}",
        quote=_snp_report_with(bytes(64)),
        raw={"pcr_read": f"  16: 0x{expected_pcr.upper()}", "pcr_index": 16},
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_missing_evidence_entirely(monkeypatch):
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    report = AttestationReport(platform="azure-cvm-sev-snp", manifest_hash="sha256:" + "00" * 32, raw={})
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_wrong_pcr_in_quote(monkeypatch):
    """A correctly-signed quote over the WRONG PCR value must not pass."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    wrong_digest = hashlib.sha256(bytes(32) + b"\x00" * 32).digest()
    tampered_quote_msg = _azure_build_attest(bytes(16), wrong_digest)
    tampered_sig = _azure_tpmt_sign(fx["ak_key"], tampered_quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(tampered_quote_msg).decode(),
            "quote_sig": base64.b64encode(tampered_sig).decode(),
        },
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_wrong_pcr_selection_with_correct_digest_bytes(monkeypatch):
    """signed selection bitmap changed from PCR16 to PCR17,
    same pcr_digest bytes, re-signed with the runtime-data-bound AK. Checking
    only the digest (and not which bank/PCR it was computed over) let this
    pass before; it must not pass now.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    # PCR17 bitmap: bit 1 of byte 2 (byte*8+bit = 2*8+1 = 17).
    retargeted_quote_msg = _azure_build_attest(bytes(16), fx["pcr_digest"], bitmap=b"\x00\x00\x02")
    retargeted_sig = _azure_tpmt_sign(fx["ak_key"], retargeted_quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(retargeted_quote_msg).decode(),
            "quote_sig": base64.b64encode(retargeted_sig).decode(),
        },
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_pcr_selection_wrong_bank(monkeypatch):
    """Same PCR index (16) but a different bank (SHA-384 alg id) must not pass:
    the verifier is configured to require the SHA-256 bank specifically.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    wrong_bank_quote_msg = _azure_build_attest(bytes(16), fx["pcr_digest"], hash_alg=0x000C)
    wrong_bank_sig = _azure_tpmt_sign(fx["ak_key"], wrong_bank_quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(wrong_bank_quote_msg).decode(),
            "quote_sig": base64.b64encode(wrong_bank_sig).decode(),
        },
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_ak_exponent_mismatch(monkeypatch):
    """runtime-data JWK exponent changed to e=3 while the
    PEM AK key keeps e=65537, rebound into a freshly-signed SNP report.
    Comparing only the modulus let this pass before; both (n, e) must match.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)

    numbers = fx["ak_key"].public_key().public_numbers()
    modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    n_b64 = base64.urlsafe_b64encode(modulus_bytes).rstrip(b"=").decode()
    # e=3 -> base64url("\x03") without padding, i.e. "Aw".
    wrong_e_b64 = base64.urlsafe_b64encode((3).to_bytes(1, "big")).rstrip(b"=").decode()
    runtime_data_wrong_e = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": n_b64, "e": wrong_e_b64}]}
    ).encode()

    # Rebind REPORT_DATA to the new runtime data so binding step 4 alone
    # would pass -- isolating that step 3 (exact key: n AND e) rejects.
    snp_report_bytes = _snp_report_with(hashlib.sha256(runtime_data_wrong_e).digest() + bytes(32))
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={"runtime_data_hex": runtime_data_wrong_e.hex()},
        quote_override=snp_report_bytes,
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_malformed_runtime_data_keys_shape(monkeypatch):
    """valid JSON `{"keys": 1}`, correctly hash-bound into
    the signed SNP report, must fail closed (return False) rather than raise.
    """
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)

    malformed_runtime_data = json.dumps({"keys": 1}).encode()
    snp_report_bytes = _snp_report_with(hashlib.sha256(malformed_runtime_data).digest() + bytes(32))
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={"runtime_data_hex": malformed_runtime_data.hex()},
        quote_override=snp_report_bytes,
    )
    # Must not raise TypeError -- must simply return False.
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_tampered_signature(monkeypatch):
    """A valid quote_msg with a corrupted quote_sig must not pass."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    sig_bytes = bytearray(base64.b64decode(fx["raw"]["quote_sig"]))
    sig_bytes[-1] ^= 0xFF
    report = _azure_report_from_fixture(
        fx, raw_overrides={"quote_sig": base64.b64encode(bytes(sig_bytes)).decode()}
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_missing_ak_evidence(monkeypatch):
    """Signature/quote present but ak_pub_pem omitted -- cannot pass."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    report = _azure_report_from_fixture(fx, raw_overrides={"ak_pub_pem": None})
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_ak_not_bound_in_runtime_data(monkeypatch):
    """ak_pub_pem is a genuine key, but a DIFFERENT key is embedded in runtime_data."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)

    other_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_numbers = other_key.public_key().public_numbers()
    other_modulus = other_numbers.n.to_bytes((other_numbers.n.bit_length() + 7) // 8, "big")
    other_n_b64 = base64.urlsafe_b64encode(other_modulus).rstrip(b"=").decode()
    swapped_runtime_data = json.dumps(
        {"keys": [{"kid": "HCLAkPub", "n": other_n_b64, "e": "AQAB"}]}
    ).encode()

    # Keep REPORT_DATA consistent with the swapped runtime_data so binding
    # step 4 alone would pass -- isolating that step 3 (AK identity) rejects.
    snp_report_bytes = _snp_report_with(hashlib.sha256(swapped_runtime_data).digest() + bytes(32))
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={"runtime_data_hex": swapped_runtime_data.hex()},
        quote_override=snp_report_bytes,
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_runtime_data_not_bound_in_snp_report(monkeypatch):
    """runtime_data/AK are internally consistent, but REPORT_DATA doesn't hash-bind to it."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    wrong_snp_report = _snp_report_with(bytes(64))  # REPORT_DATA all zero
    report = _azure_report_from_fixture(fx, quote_override=wrong_snp_report)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_reject_freshness_nonce_replayed_as_boot_quote(monkeypatch):
    """A quote with a non-zero qualifying value (a runtime-attestation quote) is not boot proof."""
    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")
    provider = AzureCVMProvider(pcr_index=16)
    fx = _azure_good_fixture(provider)
    quote_msg = _azure_build_attest(b"\x01" * 16, fx["pcr_digest"])
    quote_sig = _azure_tpmt_sign(fx["ak_key"], quote_msg)
    report = _azure_report_from_fixture(
        fx,
        raw_overrides={
            "quote_msg": base64.b64encode(quote_msg).decode(),
            "quote_sig": base64.b64encode(quote_sig).decode(),
        },
    )
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


def test_azure_get_attestation_report_has_no_stale_verification_flags(monkeypatch):
    """get_attestation_report() must never hand out a boolean that claims a
    check ran when it didn't (#373 nitpick). Regression guard: an earlier
    revision hardcoded raw["runtime_data_binding_verified"] = True
    unconditionally, on every single report, whether or not anything about
    that binding had actually been checked at that point (it hadn't --
    that's verify_attestation_chain's job, done later, from the quote/sig/AK
    material also on this report). Nothing in the verification code path
    ever reads that key (confirmed by grep across src/), so it was pure
    dead-but-misleading metadata. It must not come back.
    """
    import agent_manifest._hw_providers as hw

    provider = hw.AzureCVMProvider.__new__(hw.AzureCVMProvider)
    provider._pcr = 16
    provider._manifest_hash = "sha256:" + "cd" * 32

    fake_blobs = {
        "quote_msg": "bXNn",
        "quote_sig": "c2ln",
        "quote_pcrs": "cGNycw==",
        "ak_pub_pem": "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
        "snp_report": (b"\x00" * 0x1A0).hex(),
        "runtime_data_hex": b"{}".hex(),
        "measurement": "ab" * 48,
        "report_data": "cd" * 64,
    }
    monkeypatch.setattr(provider, "_quote", lambda nonce_hex: fake_blobs)
    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"16: 0x" + b"cd" * 32)

    report = provider.get_attestation_report()

    assert "runtime_data_binding_verified" not in report.raw
    assert "vcek_cert_chain_verified" not in report.raw
    # The fields verify_attestation_chain / verify_azure_manifest_binding
    # actually consume must still be there.
    for key in ("quote_msg", "quote_sig", "ak_pub_pem", "runtime_data_hex", "report_data", "measurement"):
        assert key in report.raw


def test_azure_reject_caller_supplied_boolean_alone_is_not_evidence():
    """Freely constructing an AttestationReport and asserting truthy fields proves nothing.

    There is no boolean shortcut anywhere in the raw schema: constructing a
    report with only descriptive/legacy fields set to favorable-looking
    values (no actual quote/signature/AK material) must fail closed.
    """

    provider_pcr = 16
    report = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash="sha256:" + "ab" * 32,
        raw={
            "runtime_data_binding_verified": True,  # self-reported, must not be trusted
            "vcek_cert_chain_verified": True,
            "pcr_index": provider_pcr,
        },
     )
    import agent_manifest._hw_providers as hw

    az = hw.AzureCVMProvider.__new__(hw.AzureCVMProvider)
    az._pcr = provider_pcr
    az._manifest_hash = None
    assert az.verify_manifest_in_report(report, SAMPLE_MANIFEST) is False


# ---------------------------------------------------------------------------
# TDXProvider — initialization and pure-Python paths
# ---------------------------------------------------------------------------


def _fake_tdx_quote(report_data: bytes) -> bytes:
    """Minimal TDX v4 quote (header + TD report body) carrying report_data.

    Enough for parse + verify_manifest_in_report; no signature (the provider only
    verifies the signature when require_quote_verification=True).
    """
    header = struct.pack("<HHI", 4, 2, 0x81) + bytes(40)
    body = bytearray(584)
    body[520:520 + len(report_data)] = report_data[:64]
    return header + bytes(body)


def test_tdx_raises_without_device(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: False)
    with pytest.raises(AttestationUnavailableError, match="TDX"):
        TDXProvider()


def test_tdx_report_before_extend_raises(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = TDXProvider()
    with pytest.raises(AttestationUnavailableError, match="extend_manifest_hash"):
        provider.get_attestation_report()


def test_tdx_verify_manifest_match(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = TDXProvider()
    expected = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="intel-tdx", manifest_hash=expected)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_tdx_verify_manifest_mismatch(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = TDXProvider()
    report = AttestationReport(platform="intel-tdx", manifest_hash="sha256:" + "ff" * 32)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_tdx_extend_with_mocked_tsm(monkeypatch):
    """extend + get_attestation_report over a mocked configfs-TSM tdx_guest quote."""
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = TDXProvider()

    import agent_manifest._hw_providers as hw

    def fake_tsm(report_data):
        return _fake_tdx_quote(report_data), "tdx_guest", None

    monkeypatch.setattr(hw, "_tsm_get_report", fake_tsm)
    provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.platform == "intel-tdx"
    assert report.manifest_hash.startswith("sha256:")
    digest = provider.manifest_hash_value(SAMPLE_MANIFEST).split(":", 1)[1]
    assert report.raw["report_data"][:64] == digest  # REPORTDATA[:32]
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_tdx_wrong_tsm_provider_raises(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda p: p == TSM_DIR)
    provider = TDXProvider()

    import agent_manifest._hw_providers as hw

    monkeypatch.setattr(
        hw, "_tsm_get_report", lambda rd: (_fake_tdx_quote(rd), "sev_guest", None)
    )
    with pytest.raises(AttestationUnavailableError, match="not 'tdx_guest'"):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)


# ---------------------------------------------------------------------------
# OPAQUEProvider — not implemented (managed service not GA; see issue #201 §5)
# ---------------------------------------------------------------------------


def test_opaque_provider_is_not_implemented():
    """OPAQUE managed attestation is disabled: the managed service is not
    generally available and the SDK does not verify its TRACE claim, so the
    provider fails closed at construction rather than looking verified."""
    with pytest.raises(AttestationUnavailableError, match="not implemented"):
        OPAQUEProvider()


# ---------------------------------------------------------------------------
# Hardware integration tests — only run on actual hardware
# ---------------------------------------------------------------------------


@NEEDS_SEV_SNP
def test_sevsnp_hardware_roundtrip():
    provider = SEVSNPProvider()
    provider.extend_manifest_hash(SAMPLE_MANIFEST)
    report = provider.get_attestation_report()
    assert report.platform == "amd-sev-snp"
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)
    assert len(report.raw.get("measurement", "")) > 0


@NEEDS_TDX
def test_tdx_hardware_roundtrip():
    provider = TDXProvider()
    provider.extend_manifest_hash(SAMPLE_MANIFEST)
    report = provider.get_attestation_report()
    assert report.platform == "intel-tdx"
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)

