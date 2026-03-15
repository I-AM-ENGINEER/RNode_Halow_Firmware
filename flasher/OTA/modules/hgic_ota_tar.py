#!/usr/bin/env python3
"""OTA bundle (.tar) helpers.

An OTA bundle is a tar archive containing fw.bin at the archive root.

Rules:
- Input must be a tar archive (tarfile.is_tarfile()).
- Archive must contain ./fw.bin (root entry). We accept both 'fw.bin' and './fw.bin'
  as tar member names, but the path must be exactly at root (no subdirectories).

Implementation note:
- Some user bundles have a damaged/truncated tar trailer. For stage1 RAW flashing we only
  need fw.bin, so we parse sequentially and tolerate end-of-archive errors *after* fw.bin
  has already been seen.
"""

from __future__ import annotations

import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class OtaTarInfo:
    tar_path: Path
    fw_member_name: str
    fw_size: int
    has_www_dir: bool


def _norm_tar_name(name: str) -> str:
    s = name
    # tar often stores names like './fw.bin'
    while s.startswith("./"):
        s = s[2:]
    while s.startswith("/"):
        s = s[1:]
    return s


def inspect_ota_tar(path: Path) -> OtaTarInfo:
    p = Path(path)

    if not p.is_file():
        raise FileNotFoundError(str(p))

    if not tarfile.is_tarfile(p):
        raise ValueError("not a tar archive")

    fw_member_name: Optional[str] = None
    fw_size = 0
    has_www_dir = False
    seen_any_member = False

    try:
        with tarfile.open(p, mode="r|*") as tf:
            for m in tf:
                seen_any_member = True
                name = _norm_tar_name(m.name)

                if name == "www" and m.isdir():
                    has_www_dir = True
                elif name.startswith("www/"):
                    has_www_dir = True

                if not m.isfile():
                    continue
                if name != "fw.bin":
                    continue
                if "/" in name:
                    continue

                fw_member_name = str(m.name)
                fw_size = int(getattr(m, "size", 0) or 0)
    except (tarfile.TarError, OSError) as e:
        # Be tolerant to a broken tar tail if fw.bin has already been found.
        if fw_member_name is None:
            raise ValueError(str(e)) from e

    if not seen_any_member and fw_member_name is None:
        raise ValueError("empty tar archive")

    if fw_member_name is None:
        raise ValueError("no ./fw.bin in tar")

    if fw_size <= 0:
        raise ValueError("fw.bin is empty")

    return OtaTarInfo(
        tar_path=p,
        fw_member_name=fw_member_name,
        fw_size=fw_size,
        has_www_dir=has_www_dir,
    )


def load_fw_bin_from_ota_tar(path: Path) -> bytes:
    info = inspect_ota_tar(path)

    try:
        with tarfile.open(info.tar_path, mode="r|*") as tf:
            for m in tf:
                if str(m.name) != info.fw_member_name:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    raise ValueError("failed to read fw.bin from tar")
                data = f.read()
                if not data:
                    raise ValueError("fw.bin is empty")
                if len(data) != int(getattr(m, "size", 0) or 0):
                    raise ValueError("fw.bin is truncated")
                return data
    except (tarfile.TarError, OSError) as e:
        raise ValueError(str(e)) from e

    raise ValueError("failed to read fw.bin from tar")
