#!/usr/bin/env python3
"""
Flash RNode-Halow and capture boot logs from UART.

Usage:
    python flashlog.py
    python flashlog.py -n 500
    python flashlog.py --elf project/Obj/RNode-Halow.elf --port COM19
"""
from __future__ import annotations

import argparse
import collections
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).parent

LOG_PORT = "COM19"
LOG_BAUD = 2_000_000


def _serial_buffer(port: str, baud: int, buf: collections.deque,
                   stop: threading.Event) -> None:
    try:
        import serial
    except ImportError:
        print("[LOG] pyserial not installed -- pip install pyserial", file=sys.stderr)
        return

    while not stop.is_set():
        try:
            with serial.Serial(port, baud, timeout=0.5) as ser:
                while not stop.is_set():
                    data = ser.read(ser.in_waiting or 128)
                    if data:
                        buf.append(data)
        except Exception:
            if not stop.is_set():
                time.sleep(0.5)


def main() -> int:
    ap = argparse.ArgumentParser(description="Flash RNode-Halow and capture boot logs.")
    ap.add_argument("--elf",  type=Path, default=HERE / "build" / "Debug" / "TXW8301-PHY.elf")
    ap.add_argument("--port", default=LOG_PORT)
    ap.add_argument("--baud", type=int, default=LOG_BAUD)
    ap.add_argument("-n", "--lines", type=int, default=200,
                    help="Number of log lines to capture (default: 200)")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    if not args.elf.exists():
        print(f"[ERR] ELF not found: {args.elf}", file=sys.stderr)
        return 1

    sys.path.insert(0, str(HERE))
    from flash import flash

    # Start buffering serial data BEFORE flash so we catch early boot output.
    buf: collections.deque[bytes] = collections.deque()
    stop = threading.Event()
    reader = threading.Thread(target=_serial_buffer,
                             args=(args.port, args.baud, buf, stop),
                             daemon=True)
    reader.start()
    time.sleep(0.3)

    print(f"[FLASH] Flashing {args.elf.name} ...", flush=True)
    try:
        flash(args.elf)
    except Exception as e:
        print(f"[FLASH] FAILED: {e}", file=sys.stderr)
        stop.set()
        return 1

    # Discard stale data from before the reset so we only capture fresh boot logs.
    buf.clear()

    print(f"[LOG] Capturing up to {args.lines} lines ...", flush=True)
    partial = b""
    count = 0
    deadline = time.monotonic() + args.timeout

    while count < args.lines and time.monotonic() < deadline:
        # Drain buffer
        while buf and count < args.lines:
            partial += buf.popleft()
            while b"\n" in partial and count < args.lines:
                line, partial = partial.split(b"\n", 1)
                sys.stdout.buffer.write(line + b"\n")
                sys.stdout.buffer.flush()
                count += 1

        if count >= args.lines:
            break
        time.sleep(0.05)

    stop.set()
    print(f"[LOG] Captured {count} lines.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
