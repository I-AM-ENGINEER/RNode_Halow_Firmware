#!/usr/bin/env python3
"""
Flash RNode-Halow via CK-Link + DebugServer.

Usage:
    python flash.py
    python flash.py --elf build/Debug/TXW8301-PHY.elf
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
ENV_FILE = HERE / "utils" / "flash_env.sh"


def _load_env(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from a shell-env file (ignores comments / blanks)."""
    defaults: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if _:
            defaults[key.strip()] = value.strip()
    return defaults


_defaults = _load_env(ENV_FILE) if ENV_FILE.exists() else {}

DEBUGSERVER = Path(os.environ.get("CSKY_DEBUGSERVER", _defaults.get("CSKY_DEBUGSERVER", "")))
GDB         = Path(os.environ.get("CSKY_GDB", _defaults.get("CSKY_GDB", "")))
GDB_INIT    = HERE / "flasher" / "gdb.init"
DEFAULT_ELF = HERE / "build" / "Debug" / "TXW8301-PHY.elf"

if sys.platform == "win32":
    _MINGW_BIN = os.environ.get("CSKY_MINGW_BIN", _defaults.get("CSKY_MINGW_BIN", ""))
    if _MINGW_BIN and _MINGW_BIN not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _MINGW_BIN + os.pathsep + os.environ.get("PATH", "")

DS_PORT = 1025
DS_ARCH = "thead"
DS_CLOCK = "12M"


def elf_entry(elf: Path) -> int:
    with elf.open("rb") as f:
        hdr = f.read(0x34)
    return struct.unpack_from("<I", hdr, 0x18)[0]


def wait_for_ds(proc: subprocess.Popen, timeout_s: float = 15.0) -> str:
    pat = re.compile(r"target remote ([0-9.]+):(\d+)")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"DebugServer exited early (code {proc.returncode})")
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        print(line, end="", flush=True)
        m = pat.search(line)
        if m:
            return m.group(1)
    raise TimeoutError("Timed out waiting for DebugServer")


def flash(elf: Path) -> None:
    """
    Download ELF to target SRAM via GDB + DebugServer and start CPU.

    Asserts nRESET via JTAG SRST (-trst, -prereset), then does soft reset
    (sreset -c 0xABCD0048). Writes to VIC ICER+ICPR to clear stale IRQ
    state, then kills GDB (TCP drop triggers detech-resume-target, CPU runs).
    """
    entry = elf_entry(elf)

    ds_cmd = [
        str(DEBUGSERVER),
        "-port", str(DS_PORT),
        "-arch", DS_ARCH,
        "-setclk", DS_CLOCK,
        "-ddc",
        "-trst",
        "-prereset",
        "-disable-cmdline",
    ]
    ds = subprocess.Popen(
        ds_cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True, bufsize=1, universal_newlines=True,
    )

    try:
        host = wait_for_ds(ds)
    except Exception as e:
        ds.terminate()
        ds.wait(5)
        raise RuntimeError(f"DebugServer: {e}") from e

    script_lines = [
        "set pagination off",
        "set confirm off",
        "set complaints 0",
        f'file "{elf.resolve().as_posix()}"',
        f"target remote {host}:{DS_PORT}",
        "monitor set detech-resume-target on",
        "monitor sreset -c 0xABCD0048",
    ]

    script_lines += [
        "interpreter-exec mi -target-download",
        f'source "{GDB_INIT.resolve().as_posix()}"',
        f"set $pc = 0x{entry:08x}",
        # VIC ICER: disable all IRQs. VIC ICPR: clear all pending.
        "set *(unsigned int *)0xE000E180 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E184 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E188 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E18C = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E280 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E284 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E288 = 0xFFFFFFFF",
        "set *(unsigned int *)0xE000E28C = 0xFFFFFFFF",
        "continue",
    ]

    script = "\n".join(script_lines) + "\n"

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".gdb",
                                     encoding="utf-8") as f:
        f.write(script)
        script_path = Path(f.name)

    gdb_proc = subprocess.Popen(
        [str(GDB), "-q", "-nx", "-batch", "-x", str(script_path)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )

    download_done = False
    deadline = time.monotonic() + 60

    while time.monotonic() < deadline:
        if gdb_proc.poll() is not None:
            break
        line = gdb_proc.stdout.readline()
        if not line:
            time.sleep(0.02)
            continue
        print(line, end="", flush=True)
        if "write-rate=" in line or "load-size=" in line:
            download_done = True
        if download_done and "^done" in line:
            break

    if not download_done:
        gdb_proc.kill()
        ds.terminate()
        script_path.unlink(missing_ok=True)
        raise RuntimeError("Download did not complete")

    # Wait for remaining GDB script commands (gdb.init, set $pc, VIC, continue)
    # to execute before killing GDB. After `continue` GDB blocks waiting for
    # the target to stop, so we give it a short window then SIGKILL.
    time.sleep(3)

    # Kill GDB first → TCP drop → DebugServer detech-resume-target → CPU runs.
    if gdb_proc.poll() is None:
        gdb_proc.kill()
        try:
            gdb_proc.wait(3)
        except subprocess.TimeoutExpired:
            pass

    # Small delay for DebugServer to process disconnect and resume target.
    time.sleep(0.5)

    # Now kill DebugServer.
    if ds.poll() is None:
        ds.kill()
        try:
            ds.wait(3)
        except subprocess.TimeoutExpired:
            pass
    script_path.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Flash RNode-Halow via CK-Link.")
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    args = ap.parse_args()

    if not args.elf.exists():
        print(f"[ERR] ELF not found: {args.elf}", file=sys.stderr)
        return 1

    print(f"[FLASH] Flashing {args.elf.name} ...", flush=True)
    try:
        flash(args.elf)
    except Exception as e:
        print(f"[FLASH] FAILED: {e}", file=sys.stderr)
        return 1

    print("[FLASH] Done. Firmware running.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
