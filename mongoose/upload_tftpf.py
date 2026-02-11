#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from pathlib import Path

import tftpy


def _sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Upload file to TFTP server (file-object) + verify by readback")
    ap.add_argument("host", help="TFTP server host/ip")
    ap.add_argument("--port", type=int, default=69)
    ap.add_argument("--local", type=Path, required=True)
    ap.add_argument("--remote", required=True)
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--no-verify", action="store_true")
    args = ap.parse_args()

    if not args.local.is_file():
        print(f"error: local file not found: {args.local}", file=sys.stderr)
        return 2

    if args.local.stat().st_size == 0:
        print("error: local file is empty", file=sys.stderr)
        return 2

    local_hash = _sha256_path(args.local)
    local_size = args.local.stat().st_size

    try:
        c = tftpy.TftpClient(args.host, args.port)

        # ВАЖНО: передаём реальный file object -> у него есть .name
        with args.local.open("rb") as f:
            c.upload(args.remote, f, timeout=args.timeout, retries=args.retries)

        if args.no_verify:
            print(f"[ok] uploaded {args.local} ({local_size} bytes) -> tftp://{args.host}:{args.port}/{args.remote}")
            return 0

        # VERIFY: читаем обратно во временный файл
        fd, tmpname = tempfile.mkstemp(prefix="tftp_readback_", suffix=".bin")
        os.close(fd)
        tmp = Path(tmpname)
        try:
            c.download(args.remote, str(tmp), timeout=args.timeout, retries=args.retries)
            remote_size = tmp.stat().st_size
            remote_hash = _sha256_path(tmp)
        finally:
            try:
                tmp.unlink()
            except Exception:
                pass

        if remote_size != local_size or remote_hash != local_hash:
            print(
                "error: verify failed\n"
                f"  local:  {local_size} bytes  sha256={local_hash}\n"
                f"  remote: {remote_size} bytes  sha256={remote_hash}\n",
                file=sys.stderr,
            )
            return 1

    except Exception as e:
        print(f"error: tftp upload failed: {e}", file=sys.stderr)
        return 1

    print(f"[ok] uploaded+verified {args.local} ({local_size} bytes) -> tftp://{args.host}:{args.port}/{args.remote}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
