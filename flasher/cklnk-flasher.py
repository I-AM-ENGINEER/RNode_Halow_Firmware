#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import struct
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def resolve_exe(p: Path) -> Path:
    """
    Разрешаем путь к exe:
      - если передан абсолютный/относительный путь и он существует -> ок
      - иначе ищем по PATH через shutil.which()
    """
    if p.exists():
        return p.resolve()

    found = shutil.which(str(p))
    if found:
        return Path(found).resolve()

    raise FileNotFoundError(f"gdb not found (neither file nor in PATH): {p}")


def stream_debugserver_until_ready(proc: subprocess.Popen[str], timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    host_re = re.compile(r"target remote ([0-9.]+):(\d+)")
    lines: list[str] = []

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break

        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue

        print(line, end="")
        lines.append(line)
        m = host_re.search(line)
        if m:
            return m.group(1)

    if proc.poll() is not None:
        raise RuntimeError(f"DebugServer exited before ready (code {proc.returncode})")

    raise TimeoutError("timed out waiting for DebugServer to print a GDB connection address")


def elf_entry_point(elf: Path) -> int:
    with elf.open("rb") as f:
        hdr = f.read(0x34)

    if len(hdr) < 0x34 or hdr[:4] != b"\x7fELF":
        raise ValueError(f"not a valid ELF file: {elf}")

    ei_class = hdr[4]
    ei_data = hdr[5]

    if ei_class != 1:
        raise ValueError(f"only ELF32 is supported: {elf}")

    if ei_data == 1:
        endian = "<"
    elif ei_data == 2:
        endian = ">"
    else:
        raise ValueError(f"unknown ELF endianness: {elf}")

    return struct.unpack_from(f"{endian}I", hdr, 0x18)[0]


def run_gdb(
    gdb: Path,
    elf: Path,
    host: str,
    port: int,
    *,
    init_script: Path | None,
    pc: int | None,
    clear_ram: bool,
    clear_ram_start: int,
    clear_ram_end: int,
    do_reset: bool,
    do_download: bool,
    do_continue: bool,
    do_detach: bool,
    extra: list[str],
) -> int:
    gdb = resolve_exe(gdb)

    if not elf.exists():
        raise FileNotFoundError(f"elf not found: {elf}")

    if pc is None:
        pc = elf_entry_point(elf)

    lines: list[str] = []
    lines += [
        "set pagination off",
        "set confirm off",
        "set complaints 0",
        f'file "{elf.resolve().as_posix()}"',
        f"target remote {host}:{port}",
        "monitor set detech-resume-target on",
    ]

    if init_script is not None:
        if not init_script.exists():
            raise FileNotFoundError(f"gdb init script not found: {init_script}")
        lines += [f'source "{init_script.resolve().as_posix()}"']

    if do_reset:
        lines += ["interpreter-exec mi -target-reset"]

    if clear_ram:
        if clear_ram_end <= clear_ram_start:
            raise ValueError("clear RAM range must have end > start")

        lines += [
            f"set $ram_addr = 0x{clear_ram_start:08x}",
            f"set $ram_end = 0x{clear_ram_end:08x}",
            "while $ram_addr < $ram_end",
            "  set *(unsigned int *)$ram_addr = 0x00000000",
            "  set $ram_addr = $ram_addr + 4",
            "end",
        ]

    if do_download:
        lines += ["interpreter-exec mi -target-download"]

    if pc is not None:
        lines += [f"set $pc = 0x{pc:08x}"]

    for cmd in extra:
        lines.append(cmd)

    if do_continue:
        lines += ["continue"]

    if do_detach:
        lines += ["detach"]

    lines += ["quit"]

    script = "\n".join(lines) + "\n"

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".gdb", encoding="utf-8") as f:
        f.write(script)
        script_path = Path(f.name)

    try:
        proc = subprocess.run(
            [str(gdb), "-q", "-nx", "-batch", "-x", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        print(proc.stdout, end="")
        return proc.returncode
    finally:
        script_path.unlink(missing_ok=True)


def run_with_debugserver(
    debugserver: Path,
    elf: Path,
    gdb: Path,
    *,
    init_script: Path | None,
    pc: int | None,
    clear_ram: bool,
    clear_ram_start: int,
    clear_ram_end: int,
    do_reset: bool,
    do_download: bool,
    do_continue: bool,
    do_detach: bool,
    extra: list[str],
    ds_port: int,
    ds_select_ice: str | None,
    ds_arch: str,
    ds_clock: str,
    ds_timeout_s: float,
) -> int:
    debugserver = resolve_exe(debugserver)

    ds_cmd = [
        str(debugserver),
        "-port", str(ds_port),
        "-arch", ds_arch,
        "-setclk", ds_clock,
        "-ddc",
        "-no-trst",
        "-disable-cmdline",
    ]
    if ds_select_ice:
        ds_cmd += ["-select-ice", ds_select_ice]

    proc = subprocess.Popen(
        ds_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    try:
        host = stream_debugserver_until_ready(proc, ds_timeout_s)
        return run_gdb(
            gdb,
            elf,
            host,
            ds_port,
            init_script=init_script,
            pc=pc,
            clear_ram=clear_ram,
            clear_ram_start=clear_ram_start,
            clear_ram_end=clear_ram_end,
            do_reset=do_reset,
            do_download=do_download,
            do_continue=do_continue,
            do_detach=do_detach,
            extra=extra,
        )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Flash ELF into target via csky-elfabiv2-gdb + XuanTie DebugServer (remote)."
    )
    ap.add_argument("elf", type=Path, help="Path to ELF")
    ap.add_argument(
        "--gdb",
        type=Path,
        default=Path("csky-elfabiv2-gdb.exe"),
        help="Path/name of csky-elfabiv2-gdb(.exe). If only name, searched in PATH.",
    )
    ap.add_argument(
        "--init-script",
        type=Path,
        default=Path(__file__).with_name("gdb.init"),
        help="Optional GDB init script with target-specific register pokes.",
    )
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=1025)
    ap.add_argument("--debugserver", type=Path, default=None,
                    help="Optional path to DebugServerConsole(.exe). If set, the script starts DebugServer automatically.")
    ap.add_argument("--debugserver-port", type=int, default=1025,
                    help="Socket port for auto-started DebugServer. Default: 1025")
    ap.add_argument("--debugserver-ice", default=None,
                    help="Optional CKLink serial for auto-started DebugServer.")
    ap.add_argument("--debugserver-arch", default="thead",
                    help="Architecture passed to DebugServer. Default: thead")
    ap.add_argument("--debugserver-clock", default="12M",
                    help="ICE clock passed to DebugServer. Default: 12M")
    ap.add_argument("--debugserver-timeout", type=float, default=15.0,
                    help="Seconds to wait for DebugServer readiness. Default: 15")
    ap.add_argument("--pc", type=lambda s: int(s, 0), default=None,
                    help="Set PC after download, e.g. 0x20001000. Defaults to ELF entry point.")
    ap.add_argument("--clear-ram", dest="clear_ram", action="store_true",
                    help="Clear target RAM before download.")
    ap.add_argument("--no-clear-ram", dest="clear_ram", action="store_false",
                    help="Do not clear target RAM before download.")
    ap.add_argument("--clear-ram-start", type=lambda s: int(s, 0), default=0x20000000,
                    help="RAM clear start address. Default: 0x20000000")
    ap.add_argument("--clear-ram-end", type=lambda s: int(s, 0), default=0x200B0000,
                    help="RAM clear end address (exclusive). Default: 0x200B0000")
    ap.add_argument("--clear-sleep-ram", action="store_true",
                    help="Convenience option: clear only the low 4 KB sleep/persistent RAM region.")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--continue", dest="do_continue", action="store_true")
    ap.add_argument("--no-detach", dest="do_detach", action="store_false",
                    help="Do not detach after setup. By default detach resumes target.")
    ap.add_argument("--cmd", action="append", default=[])
    ap.set_defaults(do_detach=True, clear_ram=False)

    args = ap.parse_args()

    if args.clear_sleep_ram and not args.clear_ram:
        args.clear_ram = True
        args.clear_ram_start = 0x20000000
        args.clear_ram_end = 0x20001000

    try:
        if args.debugserver is not None:
            return run_with_debugserver(
                args.debugserver,
                args.elf,
                args.gdb,
                init_script=args.init_script,
                pc=args.pc,
                clear_ram=args.clear_ram,
                clear_ram_start=args.clear_ram_start,
                clear_ram_end=args.clear_ram_end,
                do_reset=args.reset,
                do_download=not args.no_download,
                do_continue=args.do_continue,
                do_detach=args.do_detach,
                extra=args.cmd,
                ds_port=args.debugserver_port,
                ds_select_ice=args.debugserver_ice,
                ds_arch=args.debugserver_arch,
                ds_clock=args.debugserver_clock,
                ds_timeout_s=args.debugserver_timeout,
            )

        return run_gdb(
            args.gdb,
            args.elf,
            args.host,
            args.port,
            init_script=args.init_script,
            pc=args.pc,
            clear_ram=args.clear_ram,
            clear_ram_start=args.clear_ram_start,
            clear_ram_end=args.clear_ram_end,
            do_reset=args.reset,
            do_download=not args.no_download,
            do_continue=args.do_continue,
            do_detach=args.do_detach,
            extra=args.cmd,
        )
    except Exception as e:
        print(f"[ERR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
