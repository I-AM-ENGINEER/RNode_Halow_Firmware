#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class PackedEntry:
    name: str
    var: str
    size_expr: str
    mtime: Optional[int]


_RE_ARRAY_DEF = re.compile(
    r"static\s+const\s+unsigned\s+char\s+(?P<var>v\d+)\s*\[\]\s*=\s*\{(?P<body>.*?)\}\s*;",
    re.S,
)

_RE_PACKED_FILES = re.compile(
    r"packed_files\s*\[\]\s*=\s*\{(?P<body>.*?)\}\s*;",
    re.S,
)

_RE_ENTRY = re.compile(
    r"\{\s*\"(?P<name>[^\"]+)\"\s*,\s*(?P<var>v\d+)\s*,\s*(?P<size>[^,]+)\s*,\s*(?P<mtime>[^}]+)\s*\}",
    re.S,
)

# C int tokens: -12, 34, 0x1f, 0123 ...
_RE_INT_TOKEN = re.compile(r"(?<![A-Za-z0-9_])(-?0x[0-9A-Fa-f]+|-?\d+)(?![A-Za-z0-9_])")


def _strip_c_comments(s: str) -> str:
    # remove /* ... */ then // ... EOL
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    s = re.sub(r"//.*?$", "", s, flags=re.M)
    return s


def _parse_c_int(tok: str) -> int:
    neg = False
    s = tok.strip()
    if s.startswith("-"):
        neg = True
        s = s[1:]

    if s.startswith(("0x", "0X")):
        v = int(s, 16)
    elif len(s) > 1 and s.startswith("0"):
        # C-style octal literals like 05, 0123
        v = int(s, 8)
    else:
        v = int(s, 10)

    return -v if neg else v


def _parse_c_arrays(no_comments_text: str) -> Dict[str, bytes]:
    arrays: Dict[str, bytes] = {}
    for m in _RE_ARRAY_DEF.finditer(no_comments_text):
        var = m.group("var")
        body = m.group("body")
        vals: List[int] = []
        for t in _RE_INT_TOKEN.findall(body):
            try:
                v = _parse_c_int(t)
            except Exception:
                continue
            vals.append(v & 0xFF)
        if vals:
            arrays[var] = bytes(vals)
    return arrays


def _parse_packed_entries(no_comments_text: str) -> List[PackedEntry]:
    m = _RE_PACKED_FILES.search(no_comments_text)
    if not m:
        raise RuntimeError("packed_files[] не найден")

    body = m.group("body")
    out: List[PackedEntry] = []
    for em in _RE_ENTRY.finditer(body):
        name = em.group("name")
        var = em.group("var")
        size_expr = em.group("size").strip()
        mtime_raw = em.group("mtime").strip()

        if mtime_raw.upper().startswith("NULL"):
            mtime = None
        else:
            nums = re.findall(r"\d+", mtime_raw)
            mtime = int(nums[0]) if nums else None

        out.append(PackedEntry(name=name, var=var, size_expr=size_expr, mtime=mtime))
    return out


def _strip_prefix_slash(p: str) -> str:
    return p[1:] if p.startswith("/") else p


def _maybe_gunzip(data: bytes, name: str) -> Tuple[bytes, str]:
    is_gz = len(data) >= 3 and data[0] == 0x1F and data[1] == 0x8B and data[2] == 0x08
    if name.endswith(".gz") or is_gz:
        try:
            return gzip.decompress(data), (name[:-3] if name.endswith(".gz") else name + ".ungz")
        except Exception:
            # если вдруг не gzip/битый - сохраним как есть
            return data, name
    return data, name


def extract(mongoose_fs_c: Path, out_dir: Path, only: Optional[str]) -> None:
    text = mongoose_fs_c.read_text(encoding="utf-8", errors="ignore")

    # КРИТИЧНО: сперва вырезаем комменты, иначе "};" внутри //... ломает парсинг массива
    nc = _strip_c_comments(text)

    arrays = _parse_c_arrays(nc)
    if not arrays:
        raise RuntimeError("Не найдено ни одного массива vN[]")

    entries = _parse_packed_entries(nc)
    if not entries:
        raise RuntimeError("packed_files[] пустой или не распарсился")

    out_dir.mkdir(parents=True, exist_ok=True)

    extracted = 0
    for e in entries:
        if only is not None and e.name != only:
            continue

        blob = arrays.get(e.var)
        if blob is None:
            raise RuntimeError(f"packed_files ссылается на {e.var}, но массива нет")

        # В mg_unpack size = p->size - 1. Обычно последний байт = 0.
        if len(blob) > 0 and blob[-1] == 0:
            blob = blob[:-1]

        data, out_name = _maybe_gunzip(blob, e.name)

        rel = Path(_strip_prefix_slash(out_name))
        dst = out_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)

        extracted += 1
        print(f"[ok] {e.name} -> {dst} ({len(data)} bytes)")

    if extracted == 0:
        if only is not None:
            raise RuntimeError(f"'{only}' не найден в packed_files[]")
        raise RuntimeError("Ничего не извлечено")


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract files from mongoose_fs.c and gunzip if needed")
    ap.add_argument("mongoose_fs", type=Path, help="Path to mongoose_fs.c")
    ap.add_argument("-o", "--out", type=Path, default=Path("out_web"), help="Output dir (default: out_web)")
    ap.add_argument("--only", type=str, default=None, help='Exact name from packed_files, e.g. "/web_root/index.html.gz"')
    args = ap.parse_args()
    extract(args.mongoose_fs, args.out, args.only)


if __name__ == "__main__":
    main()
