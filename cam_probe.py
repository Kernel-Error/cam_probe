#!/usr/bin/env python3
# cam_probe.py - Defensive Camera Exposure Testing Tool
# Author: Sebastian van de Meer
# Website: https://www.kernel-error.de
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#
# Description:
#   This tool allows security researchers and administrators to test
#   their own IP cameras for publicly accessible HTTP snapshot endpoints
#   without authentication or exploitation.
#
#   Use only on devices you own or have explicit written authorization to test.
#   Attribution required: © Sebastian van de Meer — https://www.kernel-error.de
#   The author and contributors assume no liability for misuse.



from __future__ import annotations

import argparse
import ast
import csv
import http.client
import ipaddress
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests import RequestException, Response
from datetime import datetime, UTC


RESET = "\033[0m"
GREEN = "\033[32m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_RED = "\033[91m"
MAGENTA = "\033[35m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"


def green(text: str) -> str:
    return f"{GREEN}{text}{RESET}"


def bright_green(text: str) -> str:
    return f"{BRIGHT_GREEN}{text}{RESET}"


def bright_red(text: str) -> str:
    return f"{BRIGHT_RED}{text}{RESET}"


def magenta(text: str) -> str:
    return f"{MAGENTA}{text}{RESET}"


def red(text: str) -> str:
    return f"{RED}{text}{RESET}"


def yellow(text: str) -> str:
    return f"{YELLOW}{text}{RESET}"


def dim(text: str) -> str:
    return f"{DIM}{text}{RESET}"


def reset() -> str:
    return RESET


DEFAULT_USER_AGENT = "cam-probe/1.0 (+defensive-test; no-auth)"

_DEFAULT_PATHS_RAW = [
    "/snapshot.jpg",
    "/snapshot.jpeg",
    "/snapshot.png",
    "/snapshot.bmp",
    "/snap.jpg",
    "/snap.jpeg",
    "/current.jpg",
    "/current.jpeg",
    "/image.jpg",
    "/image.jpeg",
    "/Image.jpg",
    "/img.jpg",
    "/getimage.jpg",
    "/getimage",
    "/get_image.cgi",
    "/getimage.cgi",
    "/getjpg.cgi",
    "/webcapture.jpg",
    "/web/snapshot.jpg",
    "/media/img.jpg",
    "/video.jpg",
    "/stream.jpg",
    "/stream/live.jpg",
    "/stream",
    "/stream/live.mjpg",
    # Axis (VAPIX)
    "/jpg/image.jpg",
    "/axis-cgi/jpg/image.cgi",
    "/axis-cgi/jpg/image.cgi?resolution=640x480",
    "/axis-cgi/jpg/image.cgi?camera=1",
    "/axis-cgi/jpg/image.cgi?date=1&clock=1",
    "/mjpg/video.mjpg",
    "/axis-cgi/mjpg/video.cgi",
    # Hikvision (ISAPI)
    "/Streaming/Channels/1/picture",
    "/Streaming/Channels/2/picture",
    "/Streaming/Channels/3/picture",
    "/Streaming/channels/1/picture",
    "/Streaming/channels/2/picture",
    "/ISAPI/Streaming/channels/1/picture",
    "/ISAPI/Streaming/channels/101/picture",
    "/ISAPI/Streaming/channels/102/picture",
    "/ISAPI/Streaming/channels/201/picture",
    "/ISAPI/Streaming/channels/202/picture",
    "/ISAPI/Streaming/channels/301/picture",
    "/ISAPI/Streaming/channels/302/picture",
    "/ISAPI/streaming/channels/101/httppreview",
    "/ISAPI/streaming/channels/102/httppreview",
    "/ISAPI/ContentMgmt/StreamingProxy/channels/101/picture",
    # Dahua / Amcrest / variants
    "/cgi-bin/snapshot.cgi",
    "/cgi-bin/snapshot.cgi?channel=1",
    "/cgi-bin/snapshot.cgi?chn=1",
    "/cgi-bin/snapshot.cgi?stream=0",
    "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2",
    "/CGIProxy.fcgi?cmd=snapPicture2",
    "/cgi-bin/CGIStream.cgi?cmd=GetMJStream",
    "/cgi-bin/CGIStream.cgi",
    "/cgi-bin/video.cgi",
    "/cgi-bin/mjpg/video.cgi",
    "/videostream.cgi",
    "/cgi-bin/videostream.cgi",
    "/cgi-bin/videostream.cgi?camera=1",
    "/webcapture.jpg?command=snap&channel=1",
    "/jpg/image.jpg?size=3",
    "/jpg/image.jpg?size=2",
    "/image.jpg?user=admin&pwd=",
    "/snapshot.jpg?size=3",
    # Foscam / HiSilicon (hi3510)
    "/snapshot.cgi",
    "/snapshot.cgi?ch=1",
    "/snapshot.cgi?user=&pwd=",
    "/cgi-bin/hi3510/param.cgi?cmd=snap",
    "/tmpfs/snap.jpg",
    "/tmpfs/auto.jpg",
    "/snapPic.jpg",
    "/snapPic/",
    "/snapPicture2",
    "/web/tmpfs/snap.jpg",
    # INSTAR
    "/tmpfs/snap.jpg",
    "/tmpfs/auto.jpg",
    "/tmpfs/auto2.jpg",
    # Vivotek
    "/cgi-bin/viewer/video.jpg",
    "/cgi-bin/viewer/video.mjpg",
    "/cgi-bin/snapshot.cgi",
    "/img/snapshot.cgi",
    # Panasonic
    "/SnapshotJPEG?Resolution=640x480&Quality=Clarity",
    "/nphMotionJpeg?Resolution=640x480&Quality=Standard",
    "/SnapshotJPEG",
    "/nphMotionJpeg",
    # Mobotix
    "/cgi-bin/image.jpg",
    "/control/cameraimage?size=640x480",
    # Bosch
    "/snap.jpg",
    "/jpg/image.jpg",
    # Hanwha / Wisenet
    "/stw-cgi/video.cgi?msubmenu=snapshot&action=view",
    "/stw-cgi/video.cgi?msubmenu=snapshot&action=view&Profile=1&Channel=0",
    # Uniview
    "/images/snapshot.jpg",
    "/video/mjpeg/stream2",
    "/video/mjpeg/stream3",
    "/cgi-bin/snapshot.cgi",
    # Ubiquiti (older AirCam)
    "/snap.jpeg",
    "/snapshot.jpeg",
    # Grandstream
    "/anonymous/snapshot/view.jpg",
    "/snapshot/view0.jpg",
    "/cgi-bin/still.cgi",
    "/jpeg/stream",
    "/jpg/image.jpg",
    # D-Link (DCS)
    "/image.jpg",
    "/Image.jpg",
    "/image/jpeg.cgi",
    "/dms.jpg",
    "/dms?nowprofileid=2",
    "/video/mjpg.cgi",
    "/video2.mjpg",
    "/cgi-bin/viewer/video.jpg?resolution=640x480",
    "/snapshot/view0.jpg",
    "/mjpeg.cgi",
    "/snapshot.jpg",
    # Brickcom
    "/cgi-bin/media.cgi?action=getSnapshot",
    "/getSnapshot.jpg",
    "/snapshot.jpg",
    # Sony (SNC)
    "/oneshotimage.jpg",
    "/image",
    "/img/mjpeg.cgi",
    "/jpeg/vga.jpg",
    "/image/qvga.jpg",
    # Canon (VB)
    "/-wvhttp-01-/GetOneShot?image_size=640x480",
    "/-wvhttp-01-/GetLiveImage",
    "/-wvhttp-01-/video.cgi",
    # XIMEA
    "/cparapi/jpg/image.cgi?profile=Small",
    "/cparapi/jpg/image.cgi?profile=Large",
    # TP-Link (older NC)
    "/video.mjpg",
    "/stream/video/mjpeg",
    # Netwave / Wansview (OEM families)
    "/api/v1/snap.cgi?chn=0",
    "/api/v1/snap.cgi?chn=1",
    "/axis-cgi/jpg/image.cgi",
    "/Streaming/Channels/1/picture",
    # More generics / viewers
    "/axis-cgi/jpg/image.cgi?resolution=800x600&clock=1&date=1",
    "/axis-cgi/virtualdirectory.cgi",
    "/ViewerFrame?Mode=jpeg",
    "/video.cgi?quality=0",
    "/video.cgi?resolution=VGA",
    "/vids/snapshot.jpg",
    "/web/snapshot.cgi",
    "/LiveStream/Channels/1",
    "/Streaming/Channels/101/picture",
    "/Streaming/channels/101/picture",
    "/onvif/snapshot",
    "/onvif-http/snapshot?Profile_1",
    # Motion/ZoneMinder style
    "/cgi-bin/nph-zms",
    "/cgi-bin/zm/nph-zms",
    "/cgi-bin/stream",
    "/?action=snapshot",
    "/?action=stream",
    # Misc extra commonly-seen aliases
    "/camera.jpg",
    "/cam.jpg",
    "/shot.jpg",
    "/still.jpg",
    "/capture.jpg",
    "/photo.jpg",
    "/snapshot/snap.jpg",
    "/snapshot/view.jpg",
]


def _dedupe_paths(paths: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for item in paths:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


DEFAULT_PATHS = _dedupe_paths(_DEFAULT_PATHS_RAW)

CSV_COLUMNS = [
    "timestamp",
    "url",
    "path",
    "status",
    "content_type",
    "is_image",
    "marker",
    "bytes_saved",
    "saved_file",
]

INTERESTING_STATUSES = {200, 401, 403, 302, 303}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
HTML_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\'][^"\'>]*?url=([^"\'>]+)',
    re.IGNORECASE,
)
HTML_IMG_SRC_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
HTML_JS_ASSIGN_RE = re.compile(
    r'(?:var\s+\w+|snapshotUrl)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def ensure_leading_slash(path: str) -> str:
    if not path.startswith("/"):
        return f"/{path}"
    return path


def sanitize_path_for_filename(path: str) -> str:
    if not path:
        return "root"
    cleaned = path.strip()
    cleaned = cleaned.replace("\\", "/")
    cleaned = cleaned.strip("/")
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", cleaned)
    cleaned = cleaned.strip("_")
    if not cleaned:
        cleaned = "root"
    return cleaned[:100]


def timestamp_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def extract_first_jpeg(buf: bytes) -> Optional[bytes]:
    start = buf.find(b"\xff\xd8\xff")
    while start != -1:
        end = buf.find(b"\xff\xd9", start + 3)
        if end != -1:
            return buf[start : end + 2]
        start = buf.find(b"\xff\xd8\xff", start + 1)
    return None


def extract_mjpeg_frame(buf: bytes, boundary: str) -> Optional[bytes]:
    boundary_clean = boundary.strip('"')
    if not boundary_clean:
        return None
    marker = ("--" + boundary_clean).encode("latin1", errors="ignore")
    start = buf.find(marker)
    if start == -1:
        return None
    start += len(marker)
    if buf[start:start + 2] == b"\r\n":
        start += 2
    header_end = buf.find(b"\r\n\r\n", start)
    if header_end == -1:
        return None
    part_data = buf[header_end + 4 :]
    next_boundary = part_data.find(marker)
    if next_boundary != -1:
        part_data = part_data[:next_boundary]
    part_data = part_data.strip()
    if not part_data:
        return None
    jpeg = extract_first_jpeg(part_data)
    return jpeg


def _coerce_to_bytes(value: Any) -> List[bytes]:
    candidates: List[bytes] = []
    if value is None:
        return candidates
    if isinstance(value, bytes):
        if value:
            candidates.append(bytes(value))
        return candidates
    if isinstance(value, str):
        encoded = value.encode("latin1", errors="ignore")
        if encoded:
            candidates.append(encoded)
        stripped = value.strip()
        if stripped.startswith(("b'", 'b"')) and stripped.endswith(("'", '"')):
            try:
                literal = ast.literal_eval(stripped)
            except (SyntaxError, ValueError):
                literal = None
            if isinstance(literal, bytes) and literal:
                candidates.append(literal)
        if "\\x" in value or "\\u00" in value:
            try:
                unescaped = bytes(value, "utf-8").decode("unicode_escape")
            except Exception:
                unescaped = ""
            if unescaped:
                unescaped_bytes = unescaped.encode("latin1", errors="ignore")
                if unescaped_bytes:
                    candidates.append(unescaped_bytes)
    return candidates


def extract_jpeg_from_exception(exc: Exception) -> Optional[bytes]:
    seen: set[bytes] = set()
    ordered: List[bytes] = []

    def add_value(value: Any) -> None:
        for candidate in _coerce_to_bytes(value):
            if candidate and candidate not in seen:
                seen.add(candidate)
                ordered.append(candidate)

    if isinstance(exc, http.client.BadStatusLine):
        add_value(getattr(exc, "line", None))

    for arg in getattr(exc, "args", ()):
        add_value(arg)

    add_value(str(exc))

    response = getattr(exc, "response", None)
    if response is not None:
        try:
            add_value(response.content)
        except Exception:
            pass

    cause = getattr(exc, "__cause__", None)
    if cause and cause is not exc:
        jpeg = extract_jpeg_from_exception(cause)
        if jpeg:
            return jpeg

    context = getattr(exc, "__context__", None)
    if context and context is not exc:
        jpeg = extract_jpeg_from_exception(context)
        if jpeg:
            return jpeg

    for candidate in ordered:
        jpeg = extract_first_jpeg(candidate)
        if jpeg:
            return jpeg
    return None


def save_image_bytes(
    data: bytes,
    output_dir: Path,
    host: str,
    port: int,
    path: str,
    ext: str,
    derived: bool = False,
) -> Tuple[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = sanitize_path_for_filename(path)
    if derived:
        base = f"{base}_derived"
    filename = f"{host}_{port}_{base}{ext}"
    candidate = output_dir / filename
    counter = 1
    while candidate.exists():
        candidate = output_dir / f"{host}_{port}_{base}_{counter}{ext}"
        counter += 1
    with candidate.open("wb") as handle:
        handle.write(data)
    return str(candidate), len(data)


def process_buffer(
    buffer: bytes,
    content_type: str,
    host: str,
    port: int,
    path: str,
    output_dir: Path,
    derived: bool = False,
) -> Dict[str, Any]:
    marker_parts: List[str] = []
    content_type_raw = content_type or ""
    content_type_lower = content_type_raw.lower()

    if "multipart/x-mixed-replace" in content_type_lower:
        boundary_match = re.search(
            r'boundary="?([^";]+)"?', content_type_raw, re.IGNORECASE
        )
        if boundary_match:
            jpeg = extract_mjpeg_frame(buffer, boundary_match.group(1))
            if jpeg:
                saved_file, saved_bytes = save_image_bytes(
                    jpeg, output_dir, host, port, path, ".jpg", derived
                )
                return {
                    "is_image": True,
                    "marker": "mjpeg_frame_saved",
                    "saved_file": saved_file,
                    "bytes_saved": saved_bytes,
                }
            marker_parts.append("mjpeg_extract_failed")
        else:
            marker_parts.append("mjpeg_no_boundary")

    if content_type_lower.startswith("image/"):
        ext_map = {
            "image/jpeg": ".jpg",
            "image/jpg": ".jpg",
            "image/png": ".png",
            "image/bmp": ".bmp",
            "image/gif": ".gif",
            "image/webp": ".webp",
        }
        mime_type = content_type_lower.split(";", 1)[0].strip()
        ext = ext_map.get(mime_type, ".img")
        saved_file, saved_bytes = save_image_bytes(
            bytes(buffer), output_dir, host, port, path, ext, derived
        )
        return {
            "is_image": True,
            "marker": f"image_content_type:{mime_type or content_type_lower}",
            "saved_file": saved_file,
            "bytes_saved": saved_bytes,
        }

    jpeg_candidate = extract_first_jpeg(buffer)
    if jpeg_candidate:
        saved_file, saved_bytes = save_image_bytes(
            jpeg_candidate, output_dir, host, port, path, ".jpg", derived
        )
        return {
            "is_image": True,
            "marker": "jpeg_signature_found",
            "saved_file": saved_file,
            "bytes_saved": saved_bytes,
        }

    marker = ";".join(marker_parts) if marker_parts else ""
    return {
        "is_image": False,
        "marker": marker,
        "saved_file": "",
        "bytes_saved": 0,
    }


def read_stream_with_cap(resp: Response, max_bytes: int) -> bytes:
    cap = max(0, max_bytes)
    buffer = bytearray()
    for chunk in resp.iter_content(chunk_size=8192):
        if not chunk:
            continue
        if cap and len(buffer) + len(chunk) > cap:
            buffer.extend(chunk[: cap - len(buffer)])
            break
        buffer.extend(chunk)
        if cap and len(buffer) >= cap:
            break
    return bytes(buffer)


def head_with_redirects(
    session: requests.Session, url: str, timeout: float, max_redirects: int = 2
) -> Response:
    current = url
    redirects = 0
    while True:
        resp = session.head(current, timeout=timeout, allow_redirects=False)
        if resp.is_redirect and redirects < max_redirects:
            location = resp.headers.get("Location")
            if not location:
                return resp
            next_url = urljoin(current, location)
            resp.close()
            current = next_url
            redirects += 1
            continue
        return resp


def get_with_redirects(
    session: requests.Session,
    url: str,
    timeout: float,
    headers: Optional[Dict[str, str]] = None,
    max_redirects: int = 2,
) -> Tuple[Response, str]:
    current = url
    redirects = 0
    while True:
        resp = session.get(
            current,
            timeout=timeout,
            allow_redirects=False,
            headers=headers,
            stream=True,
        )
        if resp.is_redirect and redirects < max_redirects:
            location = resp.headers.get("Location")
            if not location:
                return resp, current
            next_url = urljoin(current, location)
            resp.close()
            current = next_url
            redirects += 1
            continue
        return resp, current


def maybe_follow_html_once(
    session: requests.Session,
    base_url: str,
    html: str,
    timeout: float,
    max_bytes: int,
    host: str,
    port: int,
    original_path: str,
    output_dir: Path,
) -> Optional[Dict[str, Any]]:
    candidate = None
    marker_base = ""

    meta_match = HTML_META_REFRESH_RE.search(html)
    if meta_match:
        candidate = meta_match.group(1).strip()
        marker_base = "html_meta_refresh"
    else:
        img_match = HTML_IMG_SRC_RE.search(html)
        if img_match:
            candidate = img_match.group(1).strip()
            marker_base = "html_img_src"
        else:
            js_match = HTML_JS_ASSIGN_RE.search(html)
            if js_match:
                candidate = js_match.group(1).strip()
                marker_base = "html_js_path"

    if not candidate:
        return None

    resolved = urljoin(base_url, candidate)
    range_header = None
    if max_bytes > 0:
        range_header = {"Range": f"bytes=0-{max_bytes - 1}"}

    try:
        resp, final_url = get_with_redirects(
            session, resolved, timeout, headers=range_header
        )
    except RequestException as exc:
        return {
            "is_image": False,
            "marker": f"{marker_base}_error:{exc}",
            "saved_file": "",
            "bytes_saved": 0,
            "content_type": "",
        }

    try:
        content_type = resp.headers.get("Content-Type", "") or ""
        buffer = read_stream_with_cap(resp, max_bytes)
    finally:
        resp.close()

    analysis = process_buffer(
        buffer,
        content_type,
        host,
        port,
        candidate,
        output_dir,
        derived=True,
    )

    markers = [f"{marker_base}:{final_url}"]
    if analysis["marker"]:
        markers.append(analysis["marker"])
    if not analysis["is_image"]:
        markers.append("derived_no_image")

    return {
        "is_image": analysis["is_image"],
        "marker": ";".join(markers),
        "saved_file": analysis["saved_file"],
        "bytes_saved": analysis["bytes_saved"],
        "content_type": content_type,
        "url": final_url,
    }


def format_marker(marker: str, highlight_no_image: bool = False) -> str:
    if not marker:
        return ""
    parts: List[str] = []
    for part in marker.split(";"):
        part = part.strip()
        if not part:
            continue
        if highlight_no_image and part == "no_image_detected":
            parts.append(bright_red(part))
        else:
            parts.append(part)
    if not parts:
        return ""
    return " " + ";".join(parts)


def print_outcome(
    url: str,
    status: Optional[int],
    content_type: str,
    marker: str,
    saved_file: str,
    is_image: bool,
) -> None:
    if is_image:
        details = f"[IMAGE] {url}"
        if saved_file:
            details += f" -> saved {saved_file}"
        if marker:
            details += f" ({marker})"
        print(bright_green(details))
        return

    if status is None:
        message = f"[ERR] {url}{format_marker(marker)}"
        print(red(message))
        return

    marker_str = format_marker(marker, highlight_no_image=(status == 200))
    base_message = f"[{status}] {url}"
    ct = content_type or "unknown"
    base_message += f" (ct={ct})"

    if status == 200:
        colored = green(base_message) + marker_str
        print(colored)
    elif status in {401, 403}:
        print(magenta(base_message + marker_str))
    elif status == 404:
        print(dim(base_message + marker_str))
    elif status in REDIRECT_STATUSES:
        print(yellow(base_message + marker_str))
    else:
        print(base_message + marker_str)


def probe_one(
    session: requests.Session,
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    max_bytes: int,
) -> Dict[str, Any]:
    output_dir = Path(f"cam_probe_{host}_{port}")
    timestamp = timestamp_utc()
    normalized_path = ensure_leading_slash(path)
    url = f"{scheme}://{host}:{port}{normalized_path}"
    result: Dict[str, Any] = {
        "timestamp": timestamp,
        "url": url,
        "path": normalized_path,
        "status": "",
        "content_type": "",
        "is_image": False,
        "marker": "",
        "bytes_saved": 0,
        "saved_file": "",
    }
    markers: List[str] = []
    status_code: Optional[int] = None
    content_type = ""

    try:
        head_resp = head_with_redirects(session, url, timeout)
        status_code = head_resp.status_code
        content_type = head_resp.headers.get("Content-Type", "") or ""
        result["status"] = str(status_code)
        result["content_type"] = content_type
        head_resp.close()
    except (RequestException, http.client.BadStatusLine) as exc:
        jpeg_payload = extract_jpeg_from_exception(exc)
        if jpeg_payload:
            saved_file, saved_bytes = save_image_bytes(
                jpeg_payload, output_dir, host, port, normalized_path, ".jpg"
            )
            markers.clear()
            markers.append("jpeg_from_badstatusline")
            result.update(
                {
                    "is_image": True,
                    "marker": "jpeg_from_badstatusline",
                    "bytes_saved": saved_bytes,
                    "saved_file": saved_file,
                    "content_type": "image/jpeg",
                }
            )
            print_outcome(
                url,
                None,
                result["content_type"],
                result["marker"],
                result["saved_file"],
                True,
            )
            return result
        markers.append(f"head_error:{exc}")
        result["marker"] = ";".join(markers)
        print_outcome(url, None, content_type, result["marker"], "", False)
        return result

    should_get = False
    if status_code in INTERESTING_STATUSES:
        should_get = True
    elif status_code in REDIRECT_STATUSES:
        should_get = True
    elif status_code == 405:
        should_get = True
    elif content_type.lower().startswith("image/"):
        should_get = True
    elif "mjpeg" in content_type.lower():
        should_get = True

    if not should_get:
        result["marker"] = ";".join(markers)
        print_outcome(url, status_code, content_type, result["marker"], "", False)
        return result

    range_header = None
    if max_bytes > 0:
        range_header = {"Range": f"bytes=0-{max_bytes - 1}"}

    try:
        resp, final_url = get_with_redirects(
            session, url, timeout, headers=range_header
        )
    except (RequestException, http.client.BadStatusLine) as exc:
        jpeg_payload = extract_jpeg_from_exception(exc)
        if jpeg_payload:
            saved_file, saved_bytes = save_image_bytes(
                jpeg_payload, output_dir, host, port, normalized_path, ".jpg"
            )
            markers.clear()
            markers.append("jpeg_from_badstatusline")
            result.update(
                {
                    "is_image": True,
                    "marker": "jpeg_from_badstatusline",
                    "bytes_saved": saved_bytes,
                    "saved_file": saved_file,
                    "content_type": "image/jpeg",
                }
            )
            print_outcome(
                url,
                None,
                result["content_type"],
                result["marker"],
                result["saved_file"],
                True,
            )
            return result
        markers.append(f"get_error:{exc}")
        result["marker"] = ";".join(markers)
        print_outcome(url, None, content_type, result["marker"], "", False)
        return result

    resp_encoding = None
    try:
        status_code = resp.status_code
        content_type = resp.headers.get("Content-Type", "") or ""
        resp_encoding = resp.encoding
        result["status"] = str(status_code)
        result["content_type"] = content_type
        buffer = read_stream_with_cap(resp, max_bytes)
    finally:
        resp.close()

    analysis = process_buffer(
        buffer,
        content_type,
        host,
        port,
        normalized_path,
        output_dir,
    )

    if analysis["marker"]:
        markers.append(analysis["marker"])

    if analysis["is_image"]:
        result.update(
            {
                "is_image": True,
                "marker": ";".join(markers),
                "bytes_saved": analysis["bytes_saved"],
                "saved_file": analysis["saved_file"],
            }
        )
        print_outcome(
            final_url,
            status_code,
            content_type,
            result["marker"],
            result["saved_file"],
            True,
        )
        return result

    if content_type.lower().startswith("text/html"):
        try:
            html_text = buffer.decode(resp_encoding or "utf-8")
        except Exception:
            html_text = buffer.decode("utf-8", errors="ignore")
        derived = maybe_follow_html_once(
            session,
            final_url,
            html_text,
            timeout,
            max_bytes,
            host,
            port,
            normalized_path,
            output_dir,
        )
        if derived:
            if derived["marker"]:
                markers.append(derived["marker"])
            if derived["is_image"]:
                result.update(
                    {
                        "is_image": True,
                        "marker": ";".join(markers),
                        "bytes_saved": derived["bytes_saved"],
                        "saved_file": derived["saved_file"],
                        "content_type": derived.get(
                            "content_type", result["content_type"]
                        ),
                    }
                )
                print_outcome(
                    derived.get("url", final_url),
                    status_code,
                    result["content_type"],
                    result["marker"],
                    result["saved_file"],
                    True,
                )
                return result

    if status_code == 200 and "no_image_detected" not in markers:
        markers.append("no_image_detected")

    result["marker"] = ";".join(markers)
    print_outcome(final_url, status_code, content_type, result["marker"], "", False)
    return result


def write_csv(rows: List[Dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "results.csv"
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            output_row = {key: row.get(key, "") for key in CSV_COLUMNS}
            writer.writerow(output_row)


def load_extra_paths(file_path: Optional[str]) -> List[str]:
    if not file_path:
        return []
    extra: List[str] = []
    path_obj = Path(file_path)
    if not path_obj.is_file():
        raise FileNotFoundError(f"Paths file not found: {file_path}")
    with path_obj.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.startswith("/"):
                stripped = f"/{stripped}"
            extra.append(stripped)
    return extra


def parse_ports(port: Optional[int], ports_list: Optional[str]) -> List[int]:
    if port is None and not ports_list:
        raise ValueError("Either --port or --ports must be provided.")
    if port is not None and ports_list:
        raise ValueError("Specify only one of --port or --ports.")
    ports: List[int] = []
    if port is not None:
        if port <= 0 or port > 65535:
            raise ValueError("Port must be between 1 and 65535.")
        ports.append(port)
    else:
        for part in ports_list.split(","):  # type: ignore[union-attr]
            stripped = part.strip()
            if not stripped:
                continue
            try:
                value = int(stripped)
            except ValueError as exc:
                raise ValueError(f"Invalid port value: {stripped}") from exc
            if value <= 0 or value > 65535:
                raise ValueError(f"Port out of range: {value}")
            ports.append(value)
    if not ports:
        raise ValueError("No valid ports were provided.")
    return ports


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe owned IP cameras for publicly reachable HTTP snapshots (no auth).",
    )
    parser.add_argument(
        "-H",
        "--host",
        required=True,
        help="IPv4 address of the target camera (owned devices only).",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Single port to probe.",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated list of ports to probe.",
    )
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        default="http",
        help="URL scheme to use (default: http).",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=24,
        help="Number of concurrent workers (default: 24).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8.0,
        help="Request timeout in seconds (default: 8.0).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=524288,
        help="Maximum bytes to read from responses (default: 524288).",
    )
    parser.add_argument(
        "--paths-file",
        help="File with additional paths to probe (one per line).",
    )
    parser.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help=f"User-Agent header to send (default: {DEFAULT_USER_AGENT}).",
    )
    parser.epilog = (
        "Examples:\n"
        "  python3 cam_probe.py -H 192.0.2.10 -p 88\n"
        "  python3 cam_probe.py -H 198.51.100.5 --ports 80,81,88,8080 -w 32 -t 10\n"
        "  python3 cam_probe.py -H 203.0.113.7 -p 81 --paths-file camera_paths_mega.txt"
    )
    return parser


def main() -> None:
    print("Use only on devices you own or are authorized to test. No auth, no RTSP, HTTP endpoints only.")
    parser = build_cli()
    args = parser.parse_args()

    try:
        ipaddress.IPv4Address(args.host)
    except ValueError as exc:
        raise SystemExit(f"Invalid IPv4 address: {args.host}") from exc

    if args.workers <= 0:
        raise SystemExit("Workers must be a positive integer.")
    if args.timeout <= 0:
        raise SystemExit("Timeout must be positive.")
    if args.max_bytes < 0:
        raise SystemExit("max-bytes must be zero or positive.")

    try:
        ports = parse_ports(args.port, args.ports)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    extra_paths = load_extra_paths(args.paths_file)
    paths = _dedupe_paths(DEFAULT_PATHS + extra_paths)

    thread_local = threading.local()

    def get_session() -> requests.Session:
        sess = getattr(thread_local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(
                {
                    "User-Agent": args.user_agent,
                    "Accept": "*/*",
                }
            )
            thread_local.session = sess
        return sess

    for port in ports:
        output_dir = Path(f"cam_probe_{args.host}_{port}")
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n-- Probing {args.scheme}://{args.host}:{port} ({len(paths)} paths) --")
        results: List[Dict[str, Any]] = []

        def task(path_item: str) -> Dict[str, Any]:
            session = get_session()
            return probe_one(
                session,
                args.scheme,
                args.host,
                port,
                path_item,
                args.timeout,
                args.max_bytes,
            )

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_path = {
                executor.submit(task, path): path
                for path in paths
            }
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    url = f"{args.scheme}://{args.host}:{port}{ensure_leading_slash(path)}"
                    print(red(f"[ERR] {url} worker_error:{exc}"))
                else:
                    results.append(result)
                finally:
                    time.sleep(random.uniform(0.05, 0.25))

        results.sort(key=lambda row: row["path"])
        write_csv(results, output_dir)


if __name__ == "__main__":
    main()
