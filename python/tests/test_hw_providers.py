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
from unittest.mock import MagicMock, patch

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


def test_azure_verify_manifest_pcr_replay(monkeypatch):
    import hashlib

    import agent_manifest._hw_providers as hw
    from agent_manifest._hw_providers import AzureCVMProvider

    monkeypatch.setattr(hw, "_run_tpm", lambda args: b"ok")  # NV index "present"
    provider = AzureCVMProvider(pcr_index=16)

    digest = provider.manifest_hash_value(SAMPLE_MANIFEST).split(":", 1)[1]
    # A resettable PCR starts at 0; after one extend it is sha256(0x00*32 || digest).
    expected_pcr = hashlib.sha256(bytes(32) + bytes.fromhex(digest)).hexdigest()
    good = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=f"sha256:{digest}",
        raw={"pcr_read": f"  16: 0x{expected_pcr.upper()}", "pcr_index": 16},
    )
    assert provider.verify_manifest_in_report(good, SAMPLE_MANIFEST) is True

    bad = AttestationReport(
        platform="azure-cvm-sev-snp",
        manifest_hash=f"sha256:{digest}",
        raw={"pcr_read": "  16: 0x" + "00" * 32, "pcr_index": 16},
    )
    assert provider.verify_manifest_in_report(bad, SAMPLE_MANIFEST) is False


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
# OPAQUEProvider — all platforms (mock httpx)
# ---------------------------------------------------------------------------


def test_opaque_raises_without_env_var(monkeypatch):
    monkeypatch.delenv("OPAQUE_ATTESTATION_URL", raising=False)
    with pytest.raises(AttestationUnavailableError, match="OPAQUE_ATTESTATION_URL"):
        OPAQUEProvider()


def test_opaque_raises_on_empty_env_var(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "")
    with pytest.raises(AttestationUnavailableError, match="OPAQUE_ATTESTATION_URL"):
        OPAQUEProvider()


def test_opaque_report_before_extend_raises(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()
    with pytest.raises(AttestationUnavailableError, match="extend_manifest_hash"):
        provider.get_attestation_report()


def test_opaque_extend_success(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    fake_trace = {"eat_profile": "tag:agentrust.io,2026:trace-v0.1", "iat": 1234567890}
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = fake_trace

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    called_url = mock_post.call_args[0][0]
    assert called_url == "https://attest.example.com/v1/attest"

    report = provider.get_attestation_report()
    assert report.platform == "opaque"
    assert report.manifest_hash.startswith("sha256:")
    assert report.raw == fake_trace


def test_opaque_extend_posts_pre_image(monkeypatch):
    import base64
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    body = mock_post.call_args.kwargs["json"]
    assert "manifest_pre_image" in body
    decoded = base64.b64decode(body["manifest_pre_image"])
    assert len(decoded) > 0


def test_opaque_extend_pre_image_is_correct(monkeypatch):
    """The posted pre-image must match manifest_pre_image()."""
    import base64
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    body = mock_post.call_args.kwargs["json"]
    posted = base64.b64decode(body["manifest_pre_image"])
    expected = provider.manifest_pre_image(SAMPLE_MANIFEST)
    assert posted == expected


def test_opaque_extend_with_api_key(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    monkeypatch.setenv("OPAQUE_API_KEY", "secret-key-123")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    headers = mock_post.call_args.kwargs["headers"]
    assert headers.get("Authorization") == "Bearer secret-key-123"


def test_opaque_extend_without_api_key_sends_empty_headers(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    monkeypatch.delenv("OPAQUE_API_KEY", raising=False)
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    headers = mock_post.call_args.kwargs["headers"]
    assert "Authorization" not in headers


def test_opaque_extend_http_error_raises(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_response.text = "Service Unavailable"

    with patch("httpx.post", return_value=mock_response):
        with pytest.raises(AttestationUnavailableError, match="503"):
            provider.extend_manifest_hash(SAMPLE_MANIFEST)


def test_opaque_extend_401_raises(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"

    with patch("httpx.post", return_value=mock_response):
        with pytest.raises(AttestationUnavailableError, match="401"):
            provider.extend_manifest_hash(SAMPLE_MANIFEST)


def test_opaque_manifest_hash_format(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.manifest_hash.startswith("sha256:")
    assert len(report.manifest_hash) == 7 + 64


def test_opaque_verify_manifest_match(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()
    expected = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="opaque", manifest_hash=expected)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_opaque_verify_manifest_mismatch(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com")
    provider = OPAQUEProvider()
    report = AttestationReport(platform="opaque", manifest_hash="sha256:" + "aa" * 32)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_opaque_url_trailing_slash_stripped(monkeypatch):
    monkeypatch.setenv("OPAQUE_ATTESTATION_URL", "https://attest.example.com/")
    provider = OPAQUEProvider()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}

    with patch("httpx.post", return_value=mock_response) as mock_post:
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    called_url = mock_post.call_args[0][0]
    assert not called_url.startswith("https://attest.example.com//")
    assert called_url == "https://attest.example.com/v1/attest"


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


@NEEDS_OPAQUE
def test_opaque_hardware_roundtrip():
    provider = OPAQUEProvider()
    provider.extend_manifest_hash(SAMPLE_MANIFEST)
    report = provider.get_attestation_report()
    assert report.platform == "opaque"
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)
