#!/usr/bin/env python3
"""
Validation script for lmac_structure.h
Checks:
1. Byte offset consistency (running counter matches accumulated size)
2. Hex offset comments match byte offsets
3. Total structure size equals 3012 (0xbc4)
4. No overlapping ranges
5. Assembly access patterns have corresponding fields
"""

import re
import sys
import glob
import os

STRUCT_FILE = "lmac_structure.h"
TOTAL_SIZE = 3012  # 0xbc4
TOTAL_SIZE_HEX = 0xbc4

def parse_structure_file(filepath):
    entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            # Pattern: BYTE_OFFSET (SIZE) - DESCRIPTION // HEX_OFFSET comment
            match = re.match(r'^(\d+)\s+\((\d+)\)\s*-\s*(.+)$', line)
            if match:
                byte_offset = int(match.group(1))
                size = int(match.group(2))
                description = match.group(3).strip()
                
                # Extract hex offset if present
                hex_match = re.search(r'//\s*0x([0-9a-fA-F]+)', description)
                hex_offset = int(hex_match.group(1), 16) if hex_match else None
                
                entries.append({
                    'line': line_num,
                    'byte_offset': byte_offset,
                    'size': size,
                    'description': description,
                    'hex_offset': hex_offset
                })
    return entries

def extract_assembly_offsets():
    """Extract all unique byte offsets accessed in assembly files."""
    offsets = set()
    asm_dirs = [
        "libs/disasm/liblmac/asm",
    ]
    for asm_dir in asm_dirs:
        if not os.path.exists(asm_dir):
            continue
        for asm_file in glob.glob(os.path.join(asm_dir, "*.S")):
            with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            # Find patterns like (rN, 0xXXX)
            matches = re.findall(r'\(r\d+,\s*0x([0-9a-fA-F]+)\)', content)
            for m in matches:
                offset = int(m, 16)
                if offset < TOTAL_SIZE:
                    offsets.add(offset)
    return sorted(offsets)

def validate_structure(entries):
    errors = []
    warnings = []
    
    # Check 1: Byte offset consistency
    current_offset = 0
    for entry in entries:
        if entry['byte_offset'] != current_offset:
            errors.append(f"Line {entry['line']}: Byte offset mismatch. "
                          f"Expected {current_offset}, got {entry['byte_offset']}. "
                          f"Description: {entry['description'][:50]}")
        current_offset = entry['byte_offset'] + entry['size']
    
    # Check 2: Total size
    total = entries[-1]['byte_offset'] + entries[-1]['size'] if entries else 0
    if total != TOTAL_SIZE:
        errors.append(f"Total size mismatch: got {total}, expected {TOTAL_SIZE} (0x{TOTAL_SIZE_HEX:x})")
    else:
        print(f"[OK] Total size = {TOTAL_SIZE} bytes (0x{TOTAL_SIZE_HEX:x})")
    
    # Check 3: Hex offset comments consistency
    for entry in entries:
        if entry['hex_offset'] is not None:
            if entry['hex_offset'] != entry['byte_offset']:
                errors.append(f"Line {entry['line']}: Hex offset comment mismatch. "
                              f"Byte offset: {entry['byte_offset']} (0x{entry['byte_offset']:x}), "
                              f"Comment hex: 0x{entry['hex_offset']:x} ({entry['hex_offset']}). "
                              f"Description: {entry['description'][:50]}")
    
    # Check 4: No overlapping ranges
    for i in range(len(entries) - 1):
        end = entries[i]['byte_offset'] + entries[i]['size']
        start_next = entries[i+1]['byte_offset']
        if end > start_next:
            errors.append(f"Lines {entries[i]['line']}-{entries[i+1]['line']}: Overlapping ranges. "
                          f"Entry {i} ends at {end}, next starts at {start_next}")
    
    # Check 5: Assembly offset coverage
    asm_offsets = extract_assembly_offsets()
    covered_offsets = set()
    for entry in entries:
        if entry['size'] > 0:
            for off in range(entry['byte_offset'], entry['byte_offset'] + entry['size']):
                covered_offsets.add(off)
    
    uncovered = [off for off in asm_offsets if off not in covered_offsets]
    if uncovered:
        warnings.append(f"\nAssembly offsets not covered by structure ({len(uncovered)} offsets):")
        # Group contiguous uncovered ranges
        ranges = []
        start = uncovered[0]
        prev = uncovered[0]
        for off in uncovered[1:]:
            if off == prev + 1:
                prev = off
            else:
                ranges.append((start, prev))
                start = off
                prev = off
        ranges.append((start, prev))
        
        for s, e in ranges:
            if s == e:
                warnings.append(f"  0x{s:x} ({s}) - no field")
            else:
                warnings.append(f"  0x{s:x}-0x{e:x} ({s}-{e}) - no field")
    
    return errors, warnings

def main():
    print(f"Validating {STRUCT_FILE}...")
    print(f"Expected total size: {TOTAL_SIZE} bytes (0x{TOTAL_SIZE_HEX:x})\n")
    
    entries = parse_structure_file(STRUCT_FILE)
    
    if not entries:
        print("ERROR: No entries found in structure file!")
        sys.exit(1)
    
    errors, warnings = validate_structure(entries)
    
    if errors:
        print(f"ERRORS ({len(errors)}):")
        for err in errors:
            print(f"  [ERROR] {err}")
    
    if warnings:
        print(f"\nWARNINGS ({len(warnings)}):")
        for warn in warnings:
            print(f"  [WARN] {warn}")
    
    if not errors and not warnings:
        print("\n[OK] All checks passed!")
        print(f"  Entries: {len(entries)}")
        print(f"  Total size: {entries[-1]['byte_offset'] + entries[-1]['size']} bytes")
        sys.exit(0)
    elif not errors:
        print(f"\n[OK] Structure is byte-consistent. See warnings for uncovered assembly offsets.")
        sys.exit(0)
    else:
        print(f"\n[FAIL] {len(errors)} error(s) found.")
        sys.exit(1)

if __name__ == '__main__':
    main()
