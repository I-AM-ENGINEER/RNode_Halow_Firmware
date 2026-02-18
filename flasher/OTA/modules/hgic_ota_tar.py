#!/usr/bin/env python3
"""OTA bundle (.tar) helpers.

An OTA bundle is a tar archive containing fw.bin at the archive root.

Rules:
- Input must be a tar archive (tarfile.is_tarfile()).
- Archive must contain ./fw.bin (root entry). We accept both 'fw.bin' and './fw.bin'
  as tar member names, but the path must be exactly at root (no subdirectories).
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

    with tarfile.open(p, mode="r:*") as tf:
        fw: Optional[tarfile.TarInfo] = None
        for m in tf.getmembers():
            if not m.isfile():
                continue
            if _norm_tar_name(m.name) == "fw.bin":
                # must be at root
                if "/" in _norm_tar_name(m.name):
                    continue
                fw = m
                break

        if fw is None:
            raise ValueError("no ./fw.bin in tar")

        size = int(getattr(fw, "size", 0) or 0)
        if size <= 0:
            raise ValueError("fw.bin is empty")

        return OtaTarInfo(tar_path=p, fw_member_name=str(fw.name), fw_size=size)


def load_fw_bin_from_ota_tar(path: Path) -> bytes:
    info = inspect_ota_tar(path)

    with tarfile.open(info.tar_path, mode="r:*") as tf:
        m = tf.getmember(info.fw_member_name)
        f = tf.extractfile(m)
        if f is None:
            raise ValueError("failed to read fw.bin from tar")
        data = f.read()
        if not data:
            raise ValueError("fw.bin is empty")
        return data
