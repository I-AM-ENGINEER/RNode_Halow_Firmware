#!/usr/bin/env python3
"""
Generate lmac_ctx_t struct and offset macros from lmac_structure.h.

Usage:
    # Print offset macros to stdout
    python utils/export_lmac_fields.py

    # Rewrite sdk/include/lib/lmac/lmac_ctx.h in place
    python utils/export_lmac_fields.py --write-sdk

    # Dump generated struct to stdout (for review before --write-sdk)
    python utils/export_lmac_fields.py --dump-struct
"""

import re
import sys
import argparse
from pathlib import Path

# Force UTF-8 output so Windows console codepage doesn't choke
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ROOT        = Path(__file__).parent.parent
STRUCT_FILE = ROOT / 'lmac_structure.h'
SDK_HDR     = ROOT / 'sdk/include/lib/lmac/lmac_ctx.h'

TOTAL_SIZE  = 0xBC4

LINE_RE     = re.compile(r'^\s*(\d+)\s+\((\d+)\)\s*-\s*(.+)$')
COMMENT_RE  = re.compile(r'\s*//.*$')

# Struct types that are DEFINED in OSAL headers or SDK sub-struct section
KNOWN_STRUCT_TYPES = {
    # OSAL
    'os_task', 'os_semaphore', 'os_mutex', 'os_timer',
    # lmac_ctx sub-structs defined in the SDK header
    'rx_vendor_bss_cache_entry', 'lmac_ctx_extra_ies',
    'lmac_ctx_s1g_capabilities', 'lmac_ctx_edca_params',
    'lmac_ctx_key', 'lmac_ctx_ssid',
}

OSAL_TYPES = {
    'os_task':      20,
    'os_semaphore':  8,
    'os_mutex':      8,
    'os_timer':     28,
}

PRIMITIVE_TYPES = {
    'uint8_t', 'int8_t', 'uint16_t', 'int16_t', 'uint32_t', 'int32_t',
    'uint64_t', 'int64_t', 'bool', 'char',
}

SCALAR_SIZES = {
    'uint8_t': 1, 'int8_t': 1,
    'uint16_t': 2, 'int16_t': 2,
    'uint32_t': 4, 'int32_t': 4,
    'uint64_t': 8, 'int64_t': 8,
    'bool': 1, 'char': 1,
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def normalize_name(name, typ, size):
    """Convert element-index notation name[N] to name_N where [N] is an index, not count."""
    arr = re.search(r'\[(\d+)\]', name)
    if not arr:
        return name
    N = int(arr.group(1))
    base = name[:arr.start()]
    elem = SCALAR_SIZES.get(typ, 1)
    if N == 0 or size != N * elem:
        return f'{base}_{N}'
    return name

# ─── Parser ──────────────────────────────────────────────────────────────────

def strip_comment(s):
    return COMMENT_RE.sub('', s).strip()


def parse_type_name(desc_raw):
    """
    Return (type_str, name) or (None, None) for padding / unrecognised.
    name == '' means anonymous field.
    """
    desc = strip_comment(desc_raw)
    if not desc or re.match(r'^padding\b', desc, re.IGNORECASE):
        return None, None

    # struct TYPE [name[N]] [extra words...]
    m = re.match(r'^struct\s+(\w+)(?:\s+(\w+(?:\[\d+\])?))?', desc)
    if m:
        return f'struct {m.group(1)}', m.group(2) or ''

    # void *[name]
    m = re.match(r'^void\s*\*\s*(\w+)?', desc)
    if m:
        return 'void *', m.group(1) or ''

    # TYPE *[name]  (non-void pointer, e.g. "lmac_ops *ops")
    m = re.match(r'^(\w+)\s*\*\s*(\w+)?', desc)
    if m:
        return f'{m.group(1)} *', m.group(2) or ''

    # TYPE name[N]  or  TYPE name  (scalar, possibly with trailing noise)
    m = re.match(r'^(\w+)\s+(\w+(?:\[\d+\])?)', desc)
    if m:
        typ, name = m.group(1), m.group(2)
        if ',' in typ or ';' in typ:
            return None, None
        return typ, name

    return None, None


def parse_file(path):
    fields = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            offset = int(m.group(1))
            size   = int(m.group(2))
            if size == 0:
                continue
            desc = m.group(3).strip()

            type_str, name = parse_type_name(desc)
            fields.append({
                'offset':   offset,
                'size':     size,
                'type':     type_str,          # None means padding/unrecognised
                'name':     name or '',
                'raw_desc': strip_comment(desc),
                'is_pad':   type_str is None,
            })
    return fields

# ─── Stub generation for unknown compound types ───────────────────────────────

def collect_stubs(fields):
    """
    Return {stype: elem_size} for struct types not in KNOWN_STRUCT_TYPES.
    elem_size is computed as total_size / array_count.
    """
    stubs = {}
    for f in fields:
        if f['is_pad']:
            continue
        sm = re.match(r'^struct\s+(\w+)$', f['type'] or '')
        if not sm:
            continue
        stype = sm.group(1)
        if stype in KNOWN_STRUCT_TYPES:
            continue
        arr = re.search(r'\[(\d+)\]', f['name'])
        count = int(arr.group(1)) if arr else 1
        elem_size = f['size'] // count if count else f['size']
        stubs.setdefault(stype, elem_size)
    return stubs


def gen_stubs(stubs):
    if not stubs:
        return ''
    lines = ['/* --- Opaque stubs for compound types not defined elsewhere --- */']
    for stype, esz in sorted(stubs.items()):
        lines.append(f'struct {stype} {{ uint8_t _opaque[{esz}]; }};')
    return '\n'.join(lines) + '\n'

# ─── Struct member emission ───────────────────────────────────────────────────

def field_decl(f, unknown_as_stub=True):
    """
    Return (declaration_body, comment_str).
    declaration_body does NOT include the trailing semicolon.
    """
    off     = f['offset']
    size    = f['size']
    typ     = f['type']
    name    = f['name']

    hex_off = f'0x{off:x}'

    # padding / unrecognised
    if f['is_pad'] or typ is None:
        label = f'_rsv_{off:x}' if size > 1 else f'_rsv_{off:x}'
        return f'uint8_t {label}[{size}]', f'{hex_off}, {size}B'

    # struct type
    sm = re.match(r'^struct\s+(\w+)$', typ)
    if sm:
        stype = sm.group(1)
        ename = name or f'_{stype}_{off:x}'

        if stype in KNOWN_STRUCT_TYPES:
            # Keep array notation in name; strip only for OSAL (they never have arrays)
            if stype in OSAL_TYPES:
                ename = re.sub(r'\[.*?\]', '', ename)
            return f'struct {stype:<22} {ename}', f'{hex_off}, {size}B'

        # Unknown struct - use stub type (if unknown_as_stub) or opaque blob
        if unknown_as_stub:
            return f'struct {stype:<22} {ename}', f'{hex_off}, {size}B'
        else:
            return (f'uint8_t _opaque_{off:x}[{size}]',
                    f'{hex_off}, {size}B  ({typ} {name})')

    # pointer type
    if '*' in typ:
        base  = typ.rstrip('*').strip()
        ename = name or f'_ptr_{off:x}'
        if base == 'void':
            return f'void *{ename}', f'{hex_off}, {size}B'
        # lmac_ops → lmac_ops_t for typedef consistency
        if not base.endswith('_t') and base not in {'uint8_t','uint16_t','uint32_t',
                                                     'int8_t','int16_t','int32_t'}:
            base = base + '_t'
        return f'{base} *{ename}', f'{hex_off}, {size}B'

    # scalar
    ename = name or f'_rsv_{off:x}'

    # Unknown typedef/enum → map to appropriately-sized primitive
    if typ not in PRIMITIVE_TYPES:
        typ = {1: 'uint8_t', 2: 'uint16_t', 4: 'uint32_t', 8: 'uint64_t'}.get(size, 'uint8_t')

    # Normalize element-index names (e.g. chan_scan_rssi[0] → chan_scan_rssi_0)
    ename = normalize_name(ename, typ, size)

    # Size mismatch: scalar type smaller than field → emit as array
    elem_sz = SCALAR_SIZES.get(typ, 1)
    if size > elem_sz and '[' not in ename:
        ename = f'{ename}[{size // elem_sz}]'

    return f'{typ:<8} {ename}', f'{hex_off}, {size}B'


def gen_struct(fields):
    stubs     = collect_stubs(fields)
    stub_text = gen_stubs(stubs)

    lines = []
    if stub_text:
        lines.append(stub_text)

    lines.append('typedef struct lmac_ctx {')
    for f in fields:
        decl, cmt = field_decl(f)
        lines.append(f'    {decl};  /* {cmt} */')
    lines.append('} lmac_ctx_t;')
    lines.append('')

    lines.append(f'_Static_assert(sizeof(lmac_ctx_t) == 0x{TOTAL_SIZE:X}U,'
                 f' "lmac_ctx_t total size");')
    lines.append('')

    lines.append('/* OSAL type size anchors */')
    for ot, sz in OSAL_TYPES.items():
        lines.append(f'_Static_assert(sizeof(struct {ot}) == {sz}U, "{ot} size");')
    lines.append('')

    lines.append('/* Field offset anchors -- tasks and semaphores */')
    for f in fields:
        if f['is_pad'] or not f['type']:
            continue
        sm = re.match(r'^struct\s+(\w+)$', f['type'])
        if not sm or sm.group(1) not in OSAL_TYPES:
            continue
        stype = sm.group(1)
        ename = f['name'] or f'_{stype}_{f["offset"]:x}'
        ename = re.sub(r'\[.*?\]', '', ename)
        off   = f['offset']
        sz    = OSAL_TYPES[stype]
        lines.append(
            f'_Static_assert(offsetof(lmac_ctx_t, {ename}) == 0x{off:X}U,'
            f' "lmac_ctx_t::{ename} offset");')
        lines.append(
            f'_Static_assert(sizeof(((lmac_ctx_t *)0)->{ename}) == {sz}U,'
            f' "lmac_ctx_t::{ename} size");')

    return '\n'.join(lines)

# ─── Offset macro emission ────────────────────────────────────────────────────

def macro_name(f):
    name = f['name']
    if not name:
        sm = re.match(r'^struct\s+(\w+)$', f['type'] or '')
        stype = sm.group(1) if sm else None
        if stype and stype in OSAL_TYPES:
            name = f'_{stype}_{f["offset"]:x}'
        else:
            return None
    # Normalize element-index names before stripping brackets
    name = normalize_name(name, f['type'], f['size'])
    name = re.sub(r'\[.*?\]', '', name)
    return f'LMAC_OFF_{name.upper()}'


def gen_macros(fields):
    lines = ['/* --- Field offset macros --- */']
    for f in fields:
        if f['is_pad'] or not f['type']:
            continue
        mn = macro_name(f)
        if not mn:
            continue
        lines.append(f'#define {mn:<44} 0x{f["offset"]:03X}U'
                     f'  /* {f["type"]}, {f["size"]}B */')
    return '\n'.join(lines)

# ─── SDK header rewrite ───────────────────────────────────────────────────────

SDK_GEN_BEGIN = '/* LMAC_CTX_GENERATED_BEGIN */'
SDK_GEN_END   = '/* LMAC_CTX_GENERATED_END */'

SDK_HELPERS_START = '/* ============================================================================\n   Inline Helpers'
SDK_HELPERS_END   = '#define LMAC_GET_RATE(mcs) (rate_tbl[(mcs) & 0x07])'


def rewrite_sdk_header(fields):
    text = SDK_HDR.read_text(encoding='utf-8')

    s = text.find(SDK_GEN_BEGIN)
    e = text.find(SDK_GEN_END)

    if s != -1 and e != -1:
        e += len(SDK_GEN_END)
    else:
        # First run or recovery: find struct and walk back to include any stubs,
        # then use TX-subsystem comment as the end boundary.
        struct_pos = text.find('typedef struct lmac_ctx {')
        if struct_pos == -1:
            sys.exit('ERROR: cannot locate lmac_ctx_t in SDK header')
        stub_pos = text.rfind('/* --- Opaque stubs', 0, struct_pos)
        s = stub_pos if stub_pos != -1 else struct_pos

        tx_pos = text.find('/* ============================================================================\n   TX Subsystem Context')
        if tx_pos == -1:
            # Original header: use old single-line assert
            old = '_Static_assert(sizeof(lmac_ctx_t) == 0xBC4, "lmac_ctx size");'
            tx_pos = text.find(old)
            if tx_pos == -1:
                sys.exit('ERROR: cannot locate section end in SDK header')
            tx_pos += len(old)
        e = tx_pos

    new_section = SDK_GEN_BEGIN + '\n' + gen_struct(fields) + '\n' + SDK_GEN_END
    text = text[:s].rstrip() + '\n' + new_section + '\n\n' + text[e:].lstrip('\n')

    # Strip inline helpers that reference removed fields (sta_list_head etc.)
    s2 = text.find(SDK_HELPERS_START)
    e2 = text.find(SDK_HELPERS_END)
    if s2 != -1 and e2 != -1:
        e2 += len(SDK_HELPERS_END)
        text = text[:s2].rstrip() + '\n' + text[e2:].lstrip('\n')

    SDK_HDR.write_text(text, encoding='utf-8')
    print(f'Written: {SDK_HDR}', file=sys.stderr)

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', nargs='?', default=str(STRUCT_FILE),
                    help='Path to lmac_structure.h (default: repo root)')
    ap.add_argument('--write-sdk', action='store_true',
                    help='Rewrite sdk/include/lib/lmac/lmac_ctx.h in place')
    ap.add_argument('--dump-struct', action='store_true',
                    help='Print generated struct to stdout and exit')
    args = ap.parse_args()

    src = Path(args.source)
    if not src.exists():
        sys.exit(f'ERROR: {src} not found')

    fields = parse_file(src)

    if args.dump_struct:
        print(gen_struct(fields))
        return

    if args.write_sdk:
        rewrite_sdk_header(fields)
        return

    # Default: print macros
    print(gen_macros(fields))


if __name__ == '__main__':
    main()
