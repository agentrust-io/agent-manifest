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
    not os.path.exists("/dev/sev-guest"),
    reason="requires AMD SEV-SNP hardware (/dev/sev-guest)",
)
NEEDS_TDX = pytest.mark.skipif(
    not os.path.exists("/dev/tdx-guest"),
    reason="requires Intel TDX hardware (/dev/tdx-guest)",
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


def test_sevsnp_raises_without_device(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    with pytest.raises(AttestationUnavailableError, match="SEV-SNP"):
        SEVSNPProvider()


def test_sevsnp_report_before_extend_raises(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()
    with pytest.raises(AttestationUnavailableError, match="extend_manifest_hash"):
        provider.get_attestation_report()


def test_sevsnp_verify_manifest_match(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()
    expected = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="amd-sev-snp", manifest_hash=expected)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_sevsnp_verify_manifest_mismatch(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()
    report = AttestationReport(platform="amd-sev-snp", manifest_hash="sha256:" + "00" * 32)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_sevsnp_extend_with_mocked_ioctl(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()

    mock_buf = bytearray(4096)
    mock_buf[0x90:0x90 + 48] = bytes(range(48))   # fake measurement
    mock_buf[0x140:0x180] = bytes(range(64))        # fake HOST_DATA

    import fcntl

    def mock_ioctl(fd, op, buf):
        buf[:] = mock_buf

    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)

    monkeypatch.setattr(fcntl, "ioctl", mock_ioctl)
    with patch("builtins.open", return_value=mock_dev):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.platform == "amd-sev-snp"
    assert report.manifest_hash.startswith("sha256:")
    assert report.raw["measurement"] == bytes(range(48)).hex()
    assert report.raw["host_data"] == bytes(range(64)).hex()
    assert report.raw["vmpl"] == 0


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_sevsnp_extend_ioctl_oserror_raises(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()

    import fcntl

    monkeypatch.setattr(fcntl, "ioctl", MagicMock(side_effect=OSError("perm denied")))
    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)
    with patch("builtins.open", return_value=mock_dev):
        with pytest.raises(AttestationUnavailableError, match="ioctl"):
            provider.extend_manifest_hash(SAMPLE_MANIFEST)


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_sevsnp_extend_manifest_hash_value_matches(monkeypatch):
    """verify_manifest_in_report must compare HOST_DATA from hardware bytes (HW-002)."""
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/sev-guest")
    provider = SEVSNPProvider()

    import fcntl

    def mock_ioctl_with_host_data(fd, op, buf):
        # Simulate hardware echoing user_data into HOST_DATA (offset 0x140)
        # extend_manifest_hash puts user_data = digest||zeros at buf[0:64]
        buf[0x140:0x140 + 64] = buf[0:64]

    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(fcntl, "ioctl", mock_ioctl_with_host_data)
    with patch("builtins.open", return_value=mock_dev):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.manifest_hash == provider.manifest_hash_value(SAMPLE_MANIFEST)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


# ---------------------------------------------------------------------------
# TDXProvider — initialization and pure-Python paths
# ---------------------------------------------------------------------------


def test_tdx_raises_without_device(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    with pytest.raises(AttestationUnavailableError, match="TDX"):
        TDXProvider()


def test_tdx_report_before_extend_raises(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()
    with pytest.raises(AttestationUnavailableError, match="extend_manifest_hash"):
        provider.get_attestation_report()


def test_tdx_default_rtmr_index(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()
    assert provider._rtmr == 1


def test_tdx_custom_rtmr_index(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider(rtmr_index=2)
    assert provider._rtmr == 2


def test_tdx_verify_manifest_match(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()
    expected = provider.manifest_hash_value(SAMPLE_MANIFEST)
    report = AttestationReport(platform="intel-tdx", manifest_hash=expected)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


def test_tdx_verify_manifest_mismatch(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()
    report = AttestationReport(platform="intel-tdx", manifest_hash="sha256:" + "ff" * 32)
    assert not provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_tdx_extend_with_mocked_ioctl(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider(rtmr_index=1)

    # buf is 1088 bytes (tdx_report_req: reportdata[64] + tdreport[1024])
    # reportdata in tdreport is at buf offset 104 (64 + 40)
    mock_response = bytearray(1088)
    for i in range(64):
        mock_response[104 + i] = i  # recognizable pattern at reportdata offset

    import fcntl

    def mock_ioctl(fd, op, buf):
        buf[:1088] = mock_response

    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)

    monkeypatch.setattr(fcntl, "ioctl", mock_ioctl)
    with patch("builtins.open", return_value=mock_dev):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.platform == "intel-tdx"
    assert report.manifest_hash.startswith("sha256:")
    assert report.raw["rtmr_index"] == 1
    assert report.raw["report_data"] == bytes(range(64)).hex()


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_tdx_extend_ioctl_oserror_raises(monkeypatch):
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()

    import fcntl

    monkeypatch.setattr(fcntl, "ioctl", MagicMock(side_effect=OSError("no perm")))
    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)
    with patch("builtins.open", return_value=mock_dev):
        with pytest.raises(AttestationUnavailableError, match="TDX"):
            provider.extend_manifest_hash(SAMPLE_MANIFEST)


@pytest.mark.skipif(not LINUX, reason="fcntl only available on Linux")
def test_tdx_extend_manifest_hash_value_matches(monkeypatch):
    """verify_manifest_in_report must compare reportdata from hardware bytes (HW-002)."""
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/dev/tdx-guest")
    provider = TDXProvider()

    import fcntl

    def mock_ioctl_with_reportdata(fd, op, buf):
        # Simulate hardware echoing reportdata (buf[0:64]) into REPORTMACSTRUCT.reportdata
        # tdreport starts at offset 64; reportdata is at offset 40 within REPORTMACSTRUCT
        buf[104:168] = buf[0:64]  # 64 + 40 = 104

    mock_dev = MagicMock()
    mock_dev.__enter__ = lambda s: mock_dev
    mock_dev.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(fcntl, "ioctl", mock_ioctl_with_reportdata)
    with patch("builtins.open", return_value=mock_dev):
        provider.extend_manifest_hash(SAMPLE_MANIFEST)

    report = provider.get_attestation_report()
    assert report.manifest_hash == provider.manifest_hash_value(SAMPLE_MANIFEST)
    assert provider.verify_manifest_in_report(report, SAMPLE_MANIFEST)


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
