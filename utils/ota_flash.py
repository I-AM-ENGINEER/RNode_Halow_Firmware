#!/usr/bin/env python3
"""
Flash firmware to a HaLow node over the web OTA API (JSON/base64/chunked).
This is the same mechanism the browser uses at http://node/#firmware.

Uploads ONLY fw.bin (skips the www/ files) — fastest path, leaves web UI intact.
Endpoint sequence: ota_fw_begin -> ota_fw_chunk* -> ota_fw_end -> reboot.

Usage:
  python ota_flash.py --host 192.168.1.42 out/fw.bin
  python ota_flash.py --host 192.168.1.42 --tar out/ota_firmware.tar   # full tar (incl www)
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import time
import urllib.request

CHUNK = 512
HTTP_TO = 30.0


def _post(host, endpoint, payload, timeout=HTTP_TO):
    url = f"http://{host}/api/{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"_raw": body.decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read())
        except Exception:
            err = {"_raw": str(e)}
        return {"_http_error": e.code, **err}
    except (TimeoutError, OSError) as e:
        return {"_timeout": str(e)}


def _check(r, what, off=None):
    where = f"{what}" + (f" @off={off}" if off is not None else "")
    if r.get("_http_error") or r.get("_timeout"):
        raise RuntimeError(f"{where} failed: {r}")
    if r.get("rc") not in (None, 0) and r.get("error") is not None:
        raise RuntimeError(f"{where} failed: {r}")


def upload_fw(host, fw_bytes):
    crc = binascii.crc32(fw_bytes) & 0xFFFFFFFF
    size = len(fw_bytes)
    print(f"[ota] fw.bin size={size} crc32=0x{crc:08x}")

    r = _post(host, "ota_fw_begin", {"size": size, "crc32": crc}, timeout=60.0)
    print(f"[ota] begin: {r}")
    _check(r, "ota_fw_begin")

    off = 0
    n = 0
    t0 = time.monotonic()
    while off < size:
        chunk = fw_bytes[off:off + CHUNK]
        b64 = base64.b64encode(chunk).decode("ascii")
        r = _post(host, "ota_fw_chunk", {"off": off, "b64": b64})
        _check(r, "ota_fw_chunk", off)
        off += len(chunk)
        n += 1
        if n % 100 == 0:
            pct = off * 100.0 / size
            print(f"[ota]   {off}/{size} bytes ({pct:.0f}%)", flush=True)

    r = _post(host, "ota_fw_end", {}, timeout=60.0)
    dt = time.monotonic() - t0
    print(f"[ota] end: {r}  ({dt:.1f}s, {n} chunks)")
    if r.get("_timeout"):
        raise RuntimeError(
            "ota_fw_end response lost: device CRC state UNKNOWN. "
            "NOT rebooting (a reboot now can brick the node). "
            "Re-run this upload or power-cycle the node first."
        )
    _check(r, "ota_fw_end")


def main():
    ap = argparse.ArgumentParser(description="OTA flash fw.bin to HaLow node")
    ap.add_argument("path", help="out/fw.bin (or --tar to use the tar)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--tar", action="store_true", help="path is an ota_firmware.tar")
    ap.add_argument("--no-reboot", action="store_true", help="skip reboot at end")
    args = ap.parse_args()

    if args.tar:
        # full tar path: wipe lfs + upload www files + fw + reboot
        import tarfile
        print(f"[ota] extracting tar {args.path}")
        with tarfile.open(args.path, "r") as tf:
            members = tf.getmembers()
            fw_data = None
            www_files = []
            for m in members:
                if m.name == "fw.bin":
                    fw_data = tf.extractfile(m).read()
                elif m.name.startswith("www/"):
                    www_files.append((m.name, tf.extractfile(m).read()))
            if fw_data is None:
                raise SystemExit("no fw.bin in tar")
            print(f"[ota] tar: fw.bin + {len(www_files)} www files")
            if www_files:
                r = _post(args.host, "ota_wipe_lfs", {})
                print(f"[ota] wipe_lfs: {r}")
                _check(r, "ota_wipe_lfs")
                for name, data in www_files:
                    crc = binascii.crc32(data) & 0xFFFFFFFF
                    r = _post(args.host, "ota_file_begin",
                              {"path": "/" + name, "size": len(data), "crc32": crc})
                    _check(r, f"ota_file_begin {name}")
                    off = 0
                    while off < len(data):
                        c = data[off:off + CHUNK]
                        r = _post(args.host, "ota_file_chunk",
                                  {"b64": base64.b64encode(c).decode("ascii")})
                        _check(r, f"ota_file_chunk {name}", off)
                        off += len(c)
                    r = _post(args.host, "ota_file_end", {})
                    _check(r, f"ota_file_end {name}")
                    print(f"[ota]   {name} ({len(data)}B) uploaded")
            upload_fw(args.host, fw_data)
    else:
        with open(args.path, "rb") as f:
            fw_data = f.read()
        upload_fw(args.host, fw_data)

    if not args.no_reboot:
        print("[ota] rebooting...")
        r = _post(args.host, "reboot", {})
        print(f"[ota] reboot: {r}")
    print("[ota] done. Wait ~30s for the node to come back up.")


if __name__ == "__main__":
    raise SystemExit(main())
