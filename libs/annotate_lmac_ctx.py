#!/usr/bin/env python3
"""Extract lmac_ctx field offsets from assembly listings."""

import re
import os
from collections import defaultdict

def extract_offsets(asm_text):
    """Extract all memory access offsets from assembly."""
    offsets = defaultdict(set)

    # Pattern: ld/st.X rX, (rY, 0xOFFSET)
    pattern = r'[ls]d\.[wbh]\s+\w+,\s*\(\w+,\s*(0x[0-9a-f]+)\)'

    for line in asm_text.split('\n'):
        matches = re.findall(pattern, line)
        for offset in matches:
            offsets[int(offset, 16)].add(line.strip())

    return offsets

def analyze_asm_files(base_path):
    """Analyze all .S files in a directory."""
    all_offsets = defaultdict(list)

    asm_dir = os.path.join(base_path, 'libs', 'disasm', 'liblmac', 'asm_test')

    for filename in sorted(os.listdir(asm_dir)):
        if filename.endswith('.S'):
            filepath = os.path.join(asm_dir, filename)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                offsets = extract_offsets(content)

                for offset, lines in sorted(offsets.items()):
                    all_offsets[offset].append((filename, list(lines)[:2]))

    return all_offsets

def main():
    base_path = os.getcwd()
    offsets = analyze_asm_files(base_path)

    print("=" * 80)
    print("LMAC_CTX FIELD OFFSETS FOUND IN ASSEMBLY")
    print("=" * 80)

    # Group by offset
    for offset in sorted(offsets.keys()):
        print(f"\n[0x{offset:03X}] - Referenced in:")
        for filename, lines in offsets[offset]:
            print(f"  {filename}:")
            for line in lines:
                print(f"    {line[:100]}")

if __name__ == '__main__':
    main()
