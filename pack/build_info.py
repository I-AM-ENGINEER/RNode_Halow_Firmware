#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HDR_PATH = ROOT / "inc" / "build_info_gen.h"
NUM_PATH = ROOT / "build_number.txt"


def build_header(mode: str) -> str:
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if mode == "beta":
        try:
            num = int(NUM_PATH.read_text(encoding="ascii").strip())
        except Exception:
            num = 0
        num += 1
        try:
            NUM_PATH.write_text(f"{num}\n", encoding="ascii")
        except Exception:
            pass
        defs = (
            "#define FW_BUILD_BETA       1\n"
            f"#define FW_BUILD_NUMBER     {num}\n"
            f'#define FW_BUILD_NUMBER_STR "{num}"\n'
            f'#define FW_BUILD_DATE       "{date}"\n'
            '#define FW_BUILD_VERSION    FW_VERSION "b" FW_BUILD_NUMBER_STR " (" FW_BUILD_DATE ")"\n'
        )
    else:
        defs = (
            f'#define FW_BUILD_DATE       "{date}"\n'
            '#define FW_BUILD_VERSION    FW_VERSION " (" FW_BUILD_DATE ")"\n'
        )
    return (
        f"/* AUTO-GENERATED at build time by pack/build_info.py ({mode}) - do not edit. */\n"
        "#ifndef __BUILD_INFO_GEN_H__\n"
        "#define __BUILD_INFO_GEN_H__\n"
        '#include "sys_config.h"\n'
        f"{defs}"
        "#endif\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate inc/build_info_gen.h")
    ap.add_argument("mode", choices=["beta", "release"])
    args = ap.parse_args()

    text = build_header(args.mode)
    try:
        if HDR_PATH.exists() and HDR_PATH.read_text(encoding="ascii") == text:
            return 0
        tmp = HDR_PATH.with_suffix(".h.tmp")
        tmp.write_text(text, encoding="ascii", newline="\n")
        tmp.replace(HDR_PATH)
    except Exception as e:
        print(f"build_info: {e} (keeping stale header)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
