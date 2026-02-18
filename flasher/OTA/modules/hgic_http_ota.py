#!/usr/bin/env python3
"""HTTP OTA upload helpers.

Implements the same flow as the web UI:
  POST /api/ota_begin {size, crc32}
  POST /api/ota_chunk {off, b64}  (repeated)
  POST /api/ota_end   {crc32}
  POST /api/ota_write {}

This module is intentionally UI-agnostic. Use callbacks for stage/progress.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
import socket
from urllib.parse import urlsplit

StageCb = Callable[[str], None]
ProgressCb = Callable[[int, int, float], None]  # done, total, speed (bytes/s)


@dataclass(frozen=True)
class HttpOtaConfig:
    chunk_size: int = 512
    tries: int = 6
    base_delay_ms: int = 80
    timeout_s: float = 4.0


def ping_host(ip: str, *, timeout_ms: int = 700) -> bool:
    """Best-effort ping, cross-platform."""

    if not ip:
        return False

    # Windows: ping -n 1 -w <ms>
    # Linux/macOS: ping -c 1 -W <sec>
    try:
        is_windows = subprocess.run(["cmd", "/c", "ver"], capture_output=True).returncode == 0
    except Exception:
        is_windows = False

    if is_windows:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int((timeout_ms + 999) / 1000))), ip]

    try:
        r = subprocess.run(cmd, capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


def _http_post_json(url: str, obj: dict[str, Any], *, timeout_s: float) -> dict[str, Any]:
    """POST JSON через сырой сокет одним sendall().

    Это костыль под сервер, который читает body одним recv().
    """

    u = urlsplit(url)
    host = u.hostname or ""
    port = int(u.port or 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + body

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(float(timeout_s))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.connect((host, port))
        s.sendall(req)

        # читаем до конца (connection: close)
        resp = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except Exception as e:
        raise RuntimeError(str(e))
    finally:
        try:
            s.close()
        except Exception:
            pass

    # парсим статус и body
    try:
        head, _, rb = bytes(resp).partition(b"\r\n\r\n")
        head_txt = head.decode("iso-8859-1", errors="replace")
        # HTTP/1.1 200 OK
        first = head_txt.split("\r\n", 1)[0].strip()
        parts = first.split(" ", 2)
        code = int(parts[1]) if len(parts) >= 2 else 0

        if code < 200 or code >= 300:
            msg = rb.decode("utf-8", errors="replace").replace("\r", "").replace("\n", " ").strip()
            if len(msg) > 240:
                msg = msg[:240] + "..."
            raise RuntimeError(f"HTTP {code}: {msg}".strip())

        try:
            return json.loads(rb.decode("utf-8"))
        except Exception:
            return {}
    except RuntimeError:
        raise
    except Exception:
        # если совсем криво — просто скажем, что ответ не распарсился
        return {}



def _post_json_retry(
    url: str,
    obj: dict[str, Any],
    *,
    tries: int,
    base_delay_ms: int,
    timeout_s: float,
) -> dict[str, Any]:

    # Fire-and-forget режим
    if timeout_s <= 0:
        try:
            # вызываем без ожидания ответа
            _http_post_json(url, obj, timeout_s=1.0)
        except Exception:
            pass
        return {}

    last: Optional[BaseException] = None

    for i in range(max(1, int(tries))):
        try:
            return _http_post_json(url, obj, timeout_s=timeout_s)
        except Exception as e:
            last = e

        delay = (float(base_delay_ms) / 1000.0) * (2.0 ** i)
        time.sleep(delay)

    raise RuntimeError(str(last) if last else "request failed")


def calc_crc32_u32(data: bytes) -> int:
    return int(zlib.crc32(data) & 0xFFFFFFFF)


def upload_ota_file_http(
    ip: str,
    ota_path: Path | str,
    *,
    cfg: HttpOtaConfig = HttpOtaConfig(),
    stage_cb: Optional[StageCb] = None,
    progress_cb: Optional[ProgressCb] = None,
) -> None:
    """Upload ota.tar to the device over HTTP and trigger ota_write."""

    p = Path(ota_path)
    if not p.is_file():
        raise FileNotFoundError(str(p))

    base = f"http://{ip}"

    def stage(msg: str) -> None:
        if stage_cb:
            stage_cb(msg)

    stage(f"Reading file: {p.name}")
    data = p.read_bytes()
    if not data:
        raise ValueError("ota file is empty")

    crc = calc_crc32_u32(data)
    stage(f"CRC32 = 0x{crc:08x}")

    stage("Starting OTA session...")
    _post_json_retry(
        base + "/api/ota_begin",
        {"size": len(data), "crc32": crc},
        tries=cfg.tries,
        base_delay_ms=cfg.base_delay_ms,
        timeout_s=cfg.timeout_s,
    )

    stage("Uploading OTA file...")
    off = 0
    t0 = time.time()
    total = len(data)

    while off < total:
        nxt = min(off + int(cfg.chunk_size), total)
        chunk = data[off:nxt]
        b64 = base64.b64encode(chunk).decode("ascii")

        _post_json_retry(
            base + "/api/ota_chunk",
            {"off": int(off), "b64": b64},
            tries=cfg.tries,
            base_delay_ms=cfg.base_delay_ms,
            timeout_s=cfg.timeout_s,
        )

        off = nxt

        if progress_cb:
            elapsed = time.time() - t0
            speed = off / elapsed if elapsed > 0 else 0.0
            progress_cb(off, total, speed)

    _post_json_retry(
        base + "/api/ota_end",
        {"crc32": crc},
        tries=cfg.tries,
        base_delay_ms=cfg.base_delay_ms,
        timeout_s=cfg.timeout_s,
    )

    stage("Writing firmware to flash...")
    _post_json_retry(
        base + "/api/ota_write",
        {"write": True},
        tries=2,
        base_delay_ms=cfg.base_delay_ms,
        timeout_s=30,
    )

    stage("Rebooting device...")
    _post_json_retry(
        base + "/api/reboot",
        {"reboot": True},
        tries=1,
        base_delay_ms=cfg.base_delay_ms,
        timeout_s=0,
    )

    stage("OTA finished.")
