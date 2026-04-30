#!/usr/bin/env python3
"""
Disassemble C-SKY object files and annotate relocation-backed call targets.

Usage:
    python3 libs/disasm_with_reloc.py libs/obj/liblmac/mars_lmac_tx.o > mars_lmac_tx_with_reloc.S
    python3 libs/disasm_with_reloc.py libs/obj/liblmac/mars_lmac_tx.o | grep -A 50 "<lmac_tx_init>"
"""

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

TOOLCHAIN = r"C:\toolchain-scky\bin"
OBJDUMP = f"{TOOLCHAIN}/csky-elfabiv2-objdump.exe"


def run_objdump(obj_file, flags=None):
    """Run objdump and return its output."""
    if flags is None:
        flags = ["-r", "-d", "-z"]

    cmd = [OBJDUMP, *flags, obj_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        print(f"ERROR running objdump: {exc}", file=sys.stderr)
        return None

    if result.returncode != 0:
        print(f"ERROR: {result.stderr}", file=sys.stderr)
        return None

    return result.stdout


def parse_relocations(output):
    """
    Parse relocations from `objdump -r -d` output.

    Returns:
        dict[str, dict[int, str]] mapping section -> instruction offset -> symbol
    """
    relocs = defaultdict(dict)
    current_section = None

    for line in output.splitlines():
        section_match = re.match(r"Disassembly of section (.+?):", line)
        if section_match:
            current_section = section_match.group(1)
            continue

        reloc_match = re.match(r"^\s+([0-9a-f]+):\s+R_CKCORE_\w+\s+(\S+)", line)
        if reloc_match and current_section:
            offset = int(reloc_match.group(1), 16)
            relocs[current_section][offset] = reloc_match.group(2)

    return relocs


def annotate_disasm(output, relocs):
    """Replace objdump's placeholder comments with relocation-derived symbols."""
    result = []
    current_section = None

    for line in output.splitlines():
        section_match = re.match(r"Disassembly of section (.+?):", line)
        if section_match:
            current_section = section_match.group(1)
            result.append(line)
            continue

        if re.match(r"^\s+[0-9a-f]+:\s+R_CKCORE_", line):
            continue

        insn_match = re.match(r"^(\s+)([0-9a-f]+):\s+(.+)", line)
        if insn_match and current_section:
            indent = insn_match.group(1)
            offset_str = insn_match.group(2)
            rest = insn_match.group(3)
            offset = int(offset_str, 16)

            symbol = relocs.get(current_section, {}).get(offset)
            if symbol:
                if "//" in rest:
                    rest = re.sub(r"//\s+.*", f"// <{symbol}>", rest)
                else:
                    rest = f"{rest}\t// <{symbol}>"

            result.append(f"{indent}{offset_str}:\t{rest}")
            continue

        result.append(line)

    return "\n".join(result)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 libs/disasm_with_reloc.py <object_file>", file=sys.stderr)
        sys.exit(1)

    obj_file = sys.argv[1]
    if not Path(obj_file).exists():
        print(f"ERROR: File not found: {obj_file}", file=sys.stderr)
        sys.exit(1)

    output = run_objdump(obj_file)
    if output is None:
        sys.exit(1)

    relocs = parse_relocations(output)
    annotated = annotate_disasm(output, relocs)
    print(annotated)


if __name__ == "__main__":
    main()
