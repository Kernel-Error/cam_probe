"""Tests for cam_probe.py — all HTTP interactions are mocked."""

from __future__ import annotations

import csv
import http.client
import struct
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest
import requests

import cam_probe


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Minimal valid JPEG: SOI + APP0 marker + EOI
MINIMAL_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 20 + b"\xff\xd9"

# Minimal valid PNG header (8-byte signature)
PNG_HEADER = b"\x89PNG\r\n\x1a\n"


@pytest.fixture()
def tmp_output(tmp_path: Path) -> Path:
    """Return a temporary directory for image output."""
    d = tmp_path / "output"
    d.mkdir()
    return d


def _fake_response(
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    content: bytes = b"",
    is_redirect: bool = False,
    encoding: Optional[str] = "utf-8",
) -> MagicMock:
    """Build a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = content
    resp.is_redirect = is_redirect
    resp.encoding = encoding

    def iter_content(chunk_size: int = 8192):
        for i in range(0, len(content), chunk_size):
            yield content[i : i + chunk_size]

    resp.iter_content = iter_content
    resp.close = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestEnsureLeadingSlash:
    def test_adds_slash(self):
        assert cam_probe.ensure_leading_slash("foo") == "/foo"

    def test_keeps_existing_slash(self):
        assert cam_probe.ensure_leading_slash("/bar") == "/bar"

    def test_empty_string(self):
        assert cam_probe.ensure_leading_slash("") == "/"


class TestSanitizePathForFilename:
    def test_normal_path(self):
        result = cam_probe.sanitize_path_for_filename("/cgi-bin/snapshot.cgi")
        assert result == "cgi_bin_snapshot_cgi"

    def test_empty_string(self):
        assert cam_probe.sanitize_path_for_filename("") == "root"

    def test_only_slashes(self):
        assert cam_probe.sanitize_path_for_filename("///") == "root"

    def test_long_path_truncated(self):
        long_path = "/a" * 200
        result = cam_probe.sanitize_path_for_filename(long_path)
        assert len(result) <= 100


class TestTimestampUtc:
    def test_format(self):
        ts = cam_probe.timestamp_utc()
        assert ts.endswith("Z")
        assert "T" in ts
        # No microseconds
        assert "." not in ts


class TestDedupePaths:
    def test_removes_duplicates_preserves_order(self):
        result = cam_probe._dedupe_paths(["/a", "/b", "/a", "/c", "/b"])
        assert result == ["/a", "/b", "/c"]

    def test_empty(self):
        assert cam_probe._dedupe_paths([]) == []


# ---------------------------------------------------------------------------
# Image extraction
# ---------------------------------------------------------------------------


class TestExtractFirstJpeg:
    def test_valid_jpeg(self):
        result = cam_probe.extract_first_jpeg(MINIMAL_JPEG)
        assert result is not None
        assert result.startswith(b"\xff\xd8\xff")
        assert result.endswith(b"\xff\xd9")

    def test_jpeg_with_prefix_garbage(self):
        buf = b"\x00\x00garbage" + MINIMAL_JPEG + b"trailing"
        result = cam_probe.extract_first_jpeg(buf)
        assert result is not None
        assert result.startswith(b"\xff\xd8\xff")

    def test_no_jpeg(self):
        assert cam_probe.extract_first_jpeg(b"not an image at all") is None

    def test_soi_without_eoi(self):
        assert cam_probe.extract_first_jpeg(b"\xff\xd8\xff\xe0no end") is None

    def test_empty_buffer(self):
        assert cam_probe.extract_first_jpeg(b"") is None


class TestExtractMjpegFrame:
    def _build_mjpeg(self, boundary: str, jpeg: bytes) -> bytes:
        return (
            f"--{boundary}\r\n"
            f"Content-Type: image/jpeg\r\n"
            f"Content-Length: {len(jpeg)}\r\n"
            f"\r\n"
        ).encode("latin1") + jpeg + f"\r\n--{boundary}--".encode("latin1")

    def test_extracts_frame(self):
        buf = self._build_mjpeg("myboundary", MINIMAL_JPEG)
        result = cam_probe.extract_mjpeg_frame(buf, "myboundary")
        assert result is not None
        assert result.startswith(b"\xff\xd8\xff")

    def test_empty_boundary(self):
        assert cam_probe.extract_mjpeg_frame(b"data", "") is None

    def test_quoted_boundary(self):
        buf = self._build_mjpeg("frame", MINIMAL_JPEG)
        result = cam_probe.extract_mjpeg_frame(buf, '"frame"')
        assert result is not None

    def test_no_matching_boundary(self):
        buf = self._build_mjpeg("actual", MINIMAL_JPEG)
        assert cam_probe.extract_mjpeg_frame(buf, "wrong") is None


class TestExtractJpegFromException:
    def test_bad_status_line_with_jpeg(self):
        exc = http.client.BadStatusLine(MINIMAL_JPEG)
        result = cam_probe.extract_jpeg_from_exception(exc)
        assert result is not None

    def test_request_exception_no_jpeg(self):
        exc = requests.RequestException("connection refused")
        assert cam_probe.extract_jpeg_from_exception(exc) is None

    def test_chained_exception(self):
        inner = http.client.BadStatusLine(MINIMAL_JPEG)
        outer = requests.RequestException("wrapper")
        outer.__cause__ = inner
        result = cam_probe.extract_jpeg_from_exception(outer)
        assert result is not None


# ---------------------------------------------------------------------------
# Buffer processing
# ---------------------------------------------------------------------------


class TestProcessBuffer:
    def test_image_jpeg_content_type(self, tmp_output):
        result = cam_probe.process_buffer(
            MINIMAL_JPEG, "image/jpeg", "10.0.0.1", 80, "/snap.jpg", tmp_output
        )
        assert result["is_image"] is True
        assert result["bytes_saved"] > 0
        assert Path(result["saved_file"]).exists()

    def test_image_png_content_type(self, tmp_output):
        png_data = PNG_HEADER + b"\x00" * 50
        result = cam_probe.process_buffer(
            png_data, "image/png", "10.0.0.1", 80, "/snap.png", tmp_output
        )
        assert result["is_image"] is True
        assert result["saved_file"].endswith(".png")

    def test_jpeg_signature_in_non_image_content_type(self, tmp_output):
        result = cam_probe.process_buffer(
            MINIMAL_JPEG,
            "application/octet-stream",
            "10.0.0.1",
            80,
            "/unknown",
            tmp_output,
        )
        assert result["is_image"] is True
        assert "jpeg_signature_found" in result["marker"]

    def test_no_image_in_html(self, tmp_output):
        result = cam_probe.process_buffer(
            b"<html><body>Hello</body></html>",
            "text/html",
            "10.0.0.1",
            80,
            "/index.html",
            tmp_output,
        )
        assert result["is_image"] is False

    def test_mjpeg_content_type(self, tmp_output):
        boundary = "frameboundary"
        jpeg_frame = MINIMAL_JPEG
        mjpeg_body = (
            f"--{boundary}\r\n"
            f"Content-Type: image/jpeg\r\n\r\n"
        ).encode("latin1") + jpeg_frame + f"\r\n--{boundary}--".encode("latin1")
        ct = f'multipart/x-mixed-replace; boundary="{boundary}"'
        result = cam_probe.process_buffer(
            mjpeg_body, ct, "10.0.0.1", 80, "/mjpeg", tmp_output
        )
        assert result["is_image"] is True
        assert "mjpeg_frame_saved" in result["marker"]

    def test_mjpeg_no_boundary(self, tmp_output):
        result = cam_probe.process_buffer(
            b"some data",
            "multipart/x-mixed-replace",
            "10.0.0.1",
            80,
            "/stream",
            tmp_output,
        )
        assert result["is_image"] is False
        assert "mjpeg_no_boundary" in result["marker"]


# ---------------------------------------------------------------------------
# save_image_bytes
# ---------------------------------------------------------------------------


class TestSaveImageBytes:
    def test_saves_file(self, tmp_output):
        path, size = cam_probe.save_image_bytes(
            MINIMAL_JPEG, tmp_output, "10.0.0.1", 80, "/snap.jpg", ".jpg"
        )
        assert Path(path).exists()
        assert size == len(MINIMAL_JPEG)

    def test_avoids_collision(self, tmp_output):
        path1, _ = cam_probe.save_image_bytes(
            MINIMAL_JPEG, tmp_output, "10.0.0.1", 80, "/snap.jpg", ".jpg"
        )
        path2, _ = cam_probe.save_image_bytes(
            MINIMAL_JPEG, tmp_output, "10.0.0.1", 80, "/snap.jpg", ".jpg"
        )
        assert path1 != path2
        assert Path(path1).exists()
        assert Path(path2).exists()

    def test_derived_flag(self, tmp_output):
        path, _ = cam_probe.save_image_bytes(
            MINIMAL_JPEG, tmp_output, "10.0.0.1", 80, "/snap.jpg", ".jpg", derived=True
        )
        assert "derived" in Path(path).name


# ---------------------------------------------------------------------------
# read_stream_with_cap
# ---------------------------------------------------------------------------


class TestReadStreamWithCap:
    def test_reads_full_content(self):
        resp = _fake_response(content=b"abcdef")
        result = cam_probe.read_stream_with_cap(resp, 1024)
        assert result == b"abcdef"

    def test_caps_at_max_bytes(self):
        resp = _fake_response(content=b"a" * 1000)
        result = cam_probe.read_stream_with_cap(resp, 100)
        assert len(result) <= 100

    def test_zero_cap_reads_all(self):
        data = b"x" * 500
        resp = _fake_response(content=data)
        result = cam_probe.read_stream_with_cap(resp, 0)
        assert result == data


# ---------------------------------------------------------------------------
# HTTP redirect helpers
# ---------------------------------------------------------------------------


class TestHeadWithRedirects:
    def test_no_redirect(self):
        session = MagicMock(spec=requests.Session)
        resp = _fake_response(status_code=200, is_redirect=False)
        session.head.return_value = resp

        result = cam_probe.head_with_redirects(session, "http://10.0.0.1/snap.jpg", 5.0)
        assert result.status_code == 200

    def test_follows_redirect(self):
        session = MagicMock(spec=requests.Session)
        redirect_resp = _fake_response(
            status_code=302,
            headers={"Location": "/real.jpg"},
            is_redirect=True,
        )
        redirect_resp.close = MagicMock()
        final_resp = _fake_response(status_code=200, is_redirect=False)

        session.head.side_effect = [redirect_resp, final_resp]
        result = cam_probe.head_with_redirects(session, "http://10.0.0.1/old.jpg", 5.0)
        assert result.status_code == 200
        assert session.head.call_count == 2

    def test_stops_at_max_redirects(self):
        session = MagicMock(spec=requests.Session)
        redirect_resp = _fake_response(
            status_code=302,
            headers={"Location": "/loop"},
            is_redirect=True,
        )
        redirect_resp.close = MagicMock()

        # Third call: still a redirect but max_redirects=2 reached
        final_redirect = _fake_response(
            status_code=302,
            headers={"Location": "/loop"},
            is_redirect=True,
        )
        session.head.side_effect = [redirect_resp, redirect_resp, final_redirect]
        result = cam_probe.head_with_redirects(session, "http://10.0.0.1/loop", 5.0)
        assert result.status_code == 302


class TestGetWithRedirects:
    def test_no_redirect(self):
        session = MagicMock(spec=requests.Session)
        resp = _fake_response(status_code=200, is_redirect=False)
        session.get.return_value = resp

        result, final_url = cam_probe.get_with_redirects(
            session, "http://10.0.0.1/snap.jpg", 5.0
        )
        assert result.status_code == 200
        assert final_url == "http://10.0.0.1/snap.jpg"

    def test_follows_redirect(self):
        session = MagicMock(spec=requests.Session)
        redir = _fake_response(
            status_code=301,
            headers={"Location": "http://10.0.0.1/new.jpg"},
            is_redirect=True,
        )
        redir.close = MagicMock()
        final = _fake_response(status_code=200, is_redirect=False)
        session.get.side_effect = [redir, final]

        result, final_url = cam_probe.get_with_redirects(
            session, "http://10.0.0.1/old.jpg", 5.0
        )
        assert result.status_code == 200
        assert final_url == "http://10.0.0.1/new.jpg"


# ---------------------------------------------------------------------------
# HTML following
# ---------------------------------------------------------------------------


class TestMaybeFollowHtmlOnce:
    def _run(self, html: str, session: MagicMock, tmp_output: Path) -> Optional[Dict[str, Any]]:
        return cam_probe.maybe_follow_html_once(
            session,
            "http://10.0.0.1:80/page",
            html,
            timeout=5.0,
            max_bytes=524288,
            host="10.0.0.1",
            port=80,
            original_path="/page",
            output_dir=tmp_output,
        )

    def test_meta_refresh_with_image(self, tmp_output):
        html = '<html><head><meta http-equiv="refresh" content="0;url=/snap.jpg"></head></html>'
        session = MagicMock(spec=requests.Session)
        resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            content=MINIMAL_JPEG,
            is_redirect=False,
        )
        session.get.return_value = resp

        result = self._run(html, session, tmp_output)
        assert result is not None
        assert result["is_image"] is True
        assert "html_meta_refresh" in result["marker"]

    def test_img_src(self, tmp_output):
        html = '<html><body><img src="/camera.jpg"></body></html>'
        session = MagicMock(spec=requests.Session)
        resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            content=MINIMAL_JPEG,
            is_redirect=False,
        )
        session.get.return_value = resp

        result = self._run(html, session, tmp_output)
        assert result is not None
        assert "html_img_src" in result["marker"]

    def test_js_assign(self, tmp_output):
        html = "<html><script>var snapshotUrl = '/live.jpg';</script></html>"
        session = MagicMock(spec=requests.Session)
        resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            content=MINIMAL_JPEG,
            is_redirect=False,
        )
        session.get.return_value = resp

        result = self._run(html, session, tmp_output)
        assert result is not None
        assert "html_js_path" in result["marker"]

    def test_no_candidate(self, tmp_output):
        html = "<html><body>No links here</body></html>"
        session = MagicMock(spec=requests.Session)
        result = self._run(html, session, tmp_output)
        assert result is None

    def test_follow_request_error(self, tmp_output):
        html = '<html><head><meta http-equiv="refresh" content="0;url=/fail.jpg"></head></html>'
        session = MagicMock(spec=requests.Session)
        session.get.side_effect = requests.RequestException("timeout")

        result = self._run(html, session, tmp_output)
        assert result is not None
        assert result["is_image"] is False
        assert "error" in result["marker"]


# ---------------------------------------------------------------------------
# probe_one (integration-level, mocked HTTP)
# ---------------------------------------------------------------------------


class TestProbeOne:
    def _make_session(self):
        return MagicMock(spec=requests.Session)

    def test_image_found_via_get(self, tmp_output):
        session = self._make_session()
        head_resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            is_redirect=False,
        )
        session.head.return_value = head_resp

        get_resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            content=MINIMAL_JPEG,
            is_redirect=False,
        )
        session.get.return_value = get_resp

        with patch("cam_probe.Path") as MockPath:
            mock_dir = tmp_output
            MockPath.return_value = mock_dir
            MockPath.side_effect = None

            # Use the real Path for output
            with patch("cam_probe.Path", wraps=Path) as _:
                result = cam_probe.probe_one(
                    session, "http", "10.0.0.1", 80, "/snap.jpg", 5.0, 524288
                )

        assert result["is_image"] is True
        assert result["url"] == "http://10.0.0.1:80/snap.jpg"

    def test_404_returns_not_image(self):
        session = self._make_session()
        head_resp = _fake_response(
            status_code=404,
            headers={"Content-Type": "text/html"},
            is_redirect=False,
        )
        session.head.return_value = head_resp

        result = cam_probe.probe_one(
            session, "http", "10.0.0.1", 80, "/nonexistent.jpg", 5.0, 524288
        )
        assert result["is_image"] is False
        assert result["status"] == "404"

    def test_head_exception_no_jpeg(self):
        session = self._make_session()
        session.head.side_effect = requests.ConnectionError("refused")

        result = cam_probe.probe_one(
            session, "http", "10.0.0.1", 80, "/snap.jpg", 5.0, 524288
        )
        assert result["is_image"] is False
        assert "head_error" in result["marker"]

    def test_auth_required_triggers_get(self):
        session = self._make_session()
        head_resp = _fake_response(
            status_code=401,
            headers={"Content-Type": "text/html"},
            is_redirect=False,
        )
        session.head.return_value = head_resp

        get_resp = _fake_response(
            status_code=401,
            headers={"Content-Type": "text/html"},
            content=b"<html>Login required</html>",
            is_redirect=False,
        )
        session.get.return_value = get_resp

        result = cam_probe.probe_one(
            session, "http", "10.0.0.1", 80, "/protected.jpg", 5.0, 524288
        )
        assert session.get.called
        assert result["status"] == "401"

    def test_401_html_with_logo_is_not_false_positive(self):
        """Issue #3: A 401 HTML page containing an <img src> for a vendor logo
        must NOT be reported as a found camera snapshot. Currently the HTML
        follow-through runs regardless of status code, causing false positives."""
        session = self._make_session()
        head_resp = _fake_response(
            status_code=401,
            headers={"Content-Type": "text/html"},
            is_redirect=False,
        )
        session.head.return_value = head_resp

        login_html = (
            b'<html><body><h1>Login Required</h1>'
            b'<img src="/images/logo.png"></body></html>'
        )
        get_resp_html = _fake_response(
            status_code=401,
            headers={"Content-Type": "text/html; charset=utf-8"},
            content=login_html,
            is_redirect=False,
            encoding="utf-8",
        )
        # If the code follows the img src, this is what it would get:
        get_resp_logo = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/png"},
            content=PNG_HEADER + b"\x00" * 50,
            is_redirect=False,
        )
        session.get.side_effect = [get_resp_html, get_resp_logo]

        result = cam_probe.probe_one(
            session, "http", "10.0.0.1", 80, "/admin", 5.0, 524288
        )
        # This assertion documents the *desired* behavior.
        # It will FAIL until issue #3 is fixed — the HTML follow-through
        # should be gated on status_code == 200.
        assert result["is_image"] is False, (
            "401 login page logo was incorrectly detected as a camera snapshot"
        )

    def test_mid_stream_read_failure_still_produces_result(self):
        """Issue #5: If iter_content() raises mid-stream after a successful GET,
        the path should still appear in results with an error marker, not vanish."""
        session = self._make_session()
        head_resp = _fake_response(
            status_code=200,
            headers={"Content-Type": "image/jpeg"},
            is_redirect=False,
        )
        session.head.return_value = head_resp

        # Build a GET response whose iter_content raises mid-stream
        get_resp = MagicMock(spec=requests.Response)
        get_resp.status_code = 200
        get_resp.headers = {"Content-Type": "image/jpeg"}
        get_resp.is_redirect = False
        get_resp.encoding = "utf-8"
        get_resp.close = MagicMock()

        def exploding_iter(chunk_size=8192):
            yield b"\xff\xd8"  # partial JPEG start
            raise requests.ConnectionError("connection reset mid-stream")

        get_resp.iter_content = exploding_iter
        session.get.return_value = get_resp

        result = cam_probe.probe_one(
            session, "http", "10.0.0.1", 80, "/stream.jpg", 5.0, 524288
        )
        # The result dict should exist (not swallowed as worker_error).
        # Currently this may raise and produce no CSV row — the test
        # documents the desired behavior for issue #5.
        assert result is not None
        assert result["url"] == "http://10.0.0.1:80/stream.jpg"


# ---------------------------------------------------------------------------
# CLI / argument parsing
# ---------------------------------------------------------------------------


class TestBuildCli:
    def test_required_host(self):
        parser = cam_probe.build_cli()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_defaults(self):
        parser = cam_probe.build_cli()
        args = parser.parse_args(["-H", "10.0.0.1", "-p", "80"])
        assert args.host == "10.0.0.1"
        assert args.port == 80
        assert args.scheme == "http"
        assert args.workers == 24
        assert args.timeout == 8.0
        assert args.max_bytes == 524288

    def test_all_options(self):
        parser = cam_probe.build_cli()
        args = parser.parse_args([
            "-H", "192.168.1.1",
            "--ports", "80,443",
            "--scheme", "https",
            "-w", "8",
            "-t", "3.5",
            "--max-bytes", "1024",
            "--paths-file", "/tmp/paths.txt",
            "--user-agent", "test/1.0",
        ])
        assert args.ports == "80,443"
        assert args.scheme == "https"
        assert args.workers == 8
        assert args.timeout == 3.5
        assert args.max_bytes == 1024
        assert args.user_agent == "test/1.0"


class TestParsePorts:
    def test_single_port(self):
        assert cam_probe.parse_ports(80, None) == [80]

    def test_port_list(self):
        assert cam_probe.parse_ports(None, "80,443,8080") == [80, 443, 8080]

    def test_both_raises(self):
        with pytest.raises(ValueError, match="only one"):
            cam_probe.parse_ports(80, "443")

    def test_neither_raises(self):
        with pytest.raises(ValueError):
            cam_probe.parse_ports(None, None)

    def test_invalid_port_value(self):
        with pytest.raises(ValueError):
            cam_probe.parse_ports(None, "80,abc")

    def test_port_out_of_range(self):
        with pytest.raises(ValueError):
            cam_probe.parse_ports(None, "99999")

    def test_zero_port(self):
        with pytest.raises(ValueError):
            cam_probe.parse_ports(0, None)


class TestLoadExtraPaths:
    def test_loads_paths(self, tmp_path):
        f = tmp_path / "paths.txt"
        f.write_text("/custom/snap.jpg\ncustom/other.jpg\n# comment\n\n")
        result = cam_probe.load_extra_paths(str(f))
        assert result == ["/custom/snap.jpg", "/custom/other.jpg"]

    def test_none_returns_empty(self):
        assert cam_probe.load_extra_paths(None) == []

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            cam_probe.load_extra_paths("/nonexistent/paths.txt")


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------


class TestWriteCsv:
    def test_writes_csv(self, tmp_path):
        rows = [
            {
                "timestamp": "2025-01-01T00:00:00Z",
                "url": "http://10.0.0.1:80/snap.jpg",
                "path": "/snap.jpg",
                "status": "200",
                "content_type": "image/jpeg",
                "is_image": True,
                "marker": "image_content_type:image/jpeg",
                "bytes_saved": 1024,
                "saved_file": "output/file.jpg",
            }
        ]
        out_dir = tmp_path / "results"
        cam_probe.write_csv(rows, out_dir)
        csv_path = out_dir / "results.csv"
        assert csv_path.exists()

        with csv_path.open() as f:
            reader = csv.DictReader(f)
            written = list(reader)
        assert len(written) == 1
        assert written[0]["url"] == "http://10.0.0.1:80/snap.jpg"
        assert written[0]["status"] == "200"

    def test_creates_directory(self, tmp_path):
        out_dir = tmp_path / "nested" / "dir"
        cam_probe.write_csv([], out_dir)
        assert (out_dir / "results.csv").exists()


# ---------------------------------------------------------------------------
# Color / formatting helpers
# ---------------------------------------------------------------------------


class TestFormatMarker:
    def test_empty_marker(self):
        assert cam_probe.format_marker("") == ""

    def test_single_marker(self):
        result = cam_probe.format_marker("jpeg_signature_found")
        assert "jpeg_signature_found" in result

    def test_multiple_markers(self):
        result = cam_probe.format_marker("a;b;c")
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_highlight_no_image(self):
        result = cam_probe.format_marker("no_image_detected", highlight_no_image=True)
        # Should contain ANSI escape codes for bright red
        assert cam_probe.BRIGHT_RED in result


class TestColorHelpers:
    def test_green(self):
        assert cam_probe.GREEN in cam_probe.green("test")
        assert cam_probe.RESET in cam_probe.green("test")

    def test_bright_green(self):
        assert cam_probe.BRIGHT_GREEN in cam_probe.bright_green("test")

    def test_red(self):
        assert cam_probe.RED in cam_probe.red("test")

    def test_yellow(self):
        assert cam_probe.YELLOW in cam_probe.yellow("test")

    def test_magenta(self):
        assert cam_probe.MAGENTA in cam_probe.magenta("test")

    def test_dim(self):
        assert cam_probe.DIM in cam_probe.dim("test")


# ---------------------------------------------------------------------------
# print_outcome (smoke tests — just ensure no exceptions)
# ---------------------------------------------------------------------------


class TestPrintOutcome:
    def test_image_found(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/snap.jpg", 200, "image/jpeg",
            "image_content_type:image/jpeg", "/tmp/file.jpg", True,
        )
        captured = capsys.readouterr()
        assert "IMAGE" in captured.out

    def test_error(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/snap.jpg", None, "",
            "head_error:timeout", "", False,
        )
        captured = capsys.readouterr()
        assert "ERR" in captured.out

    def test_status_200_no_image(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/page", 200, "text/html",
            "no_image_detected", "", False,
        )
        captured = capsys.readouterr()
        assert "200" in captured.out

    def test_status_401(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/protected", 401, "text/html",
            "", "", False,
        )
        captured = capsys.readouterr()
        assert "401" in captured.out

    def test_status_404(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/missing", 404, "text/html",
            "", "", False,
        )
        captured = capsys.readouterr()
        assert "404" in captured.out

    def test_redirect(self, capsys):
        cam_probe.print_outcome(
            "http://10.0.0.1/old", 302, "text/html",
            "", "", False,
        )
        captured = capsys.readouterr()
        assert "302" in captured.out


# ---------------------------------------------------------------------------
# DEFAULT_PATHS sanity
# ---------------------------------------------------------------------------


class TestDefaultPaths:
    def test_no_duplicates(self):
        assert len(cam_probe.DEFAULT_PATHS) == len(set(cam_probe.DEFAULT_PATHS))

    def test_all_start_with_slash_or_query(self):
        for p in cam_probe.DEFAULT_PATHS:
            assert p.startswith("/") or p.startswith("?"), f"Bad path: {p}"

    def test_not_empty(self):
        assert len(cam_probe.DEFAULT_PATHS) > 100
