#!/usr/bin/env python3
"""
Object -> relocation-annotated assembly pipeline for C-SKY firmware blobs.

Input:
    - a single .o file, or
    - a directory containing .o files

Output:
    - writes relocation-annotated .S files into the requested output directory
    - no intermediate files are required

Usage:
    python libs/disasm_pipeline.py build/Debug/.obj/sdk/lib/lmac/mars_rfspi.o libs/disasm/liblmac/recover_asm
    python libs/disasm_pipeline.py tmp/liblmac_for_libs/obj libs/disasm/liblmac/recover_asm
"""

import sys
from pathlib import Path

import annotate_arg_bytes
import annotate_control_flow
import annotate_register_state
import disasm_with_reloc
def render_object(obj_path: Path) -> str:
    output = disasm_with_reloc.run_objdump(str(obj_path))
    if output is None:
        raise RuntimeError(f"objdump failed for {obj_path}")

    relocs = disasm_with_reloc.parse_relocations(output)
    with_reloc = disasm_with_reloc.annotate_disasm(output, relocs)
    with_arg_bytes = annotate_arg_bytes.annotate_lines(with_reloc.splitlines())
    with_cf = annotate_control_flow.annotate_lines(with_arg_bytes)
    with_regs = annotate_register_state.annotate_lines(with_cf)
    return "\n".join(with_regs) + "\n"


def output_name(obj_path: Path) -> str:
    return f"{obj_path.stem}.S"


def process(input_path: Path, output_dir: Path) -> int:
    if not input_path.exists():
        raise FileNotFoundError(f"Input path not found: {input_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    if input_path.is_file():
        if input_path.suffix.lower() != ".o":
            raise ValueError(f"Expected .o file, got: {input_path}")
        targets = [input_path]
    else:
        targets = sorted(p for p in input_path.glob("*.o") if p.is_file())
        if not targets:
            raise ValueError(f"No .o files found in: {input_path}")

    for obj_path in targets:
        rendered = render_object(obj_path)
        out_path = output_dir / output_name(obj_path)
        out_path.write_text(rendered, encoding="utf-8")

    return len(targets)


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python libs/disasm_pipeline.py <object_file_or_dir> <output_dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])

    try:
        count = process(input_path, output_dir)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Wrote {count} file(s) to {output_dir}")


if __name__ == "__main__":
    main()
