#!/usr/bin/env python3
"""TFTP OTA filesystem upload helpers.

Reads a local OTA tar bundle and uploads every non-fw.bin file member directly to
an already running TFTP server on the device, preserving relative paths from the tar.
"""

from __future__ import annotations

import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import tftpy

StageCb = Callable[[str], None]
ProgressCb = Callable[[int, int, float], None]  # done, total, speed (bytes/s)


@dataclass(frozen=True)
class TftpOtaConfig:
    port: int = 69
    timeout_s: float = 1.0
    retries: int = 3


def _norm_tar_name(name: str) -> str:
    s = str(name).replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    while s.startswith("/"):
        s = s[1:]
    return s


def upload_ota_files_tftp(
    ip: str,
    ota_path: Path | str,
    *,
    cfg: TftpOtaConfig = TftpOtaConfig(),
    stage_cb: Optional[StageCb] = None,
    progress_cb: Optional[ProgressCb] = None,
) -> None:
    p = Path(ota_path)
    if not p.is_file():
        raise FileNotFoundError(str(p))

    items: list[tuple[str, int]] = []
    try:
        with tarfile.open(p, mode="r|*") as tf:
            for m in tf:
                name = _norm_tar_name(m.name)
                if not name or name == 'fw.bin' or not m.isfile():
                    continue
                items.append((name, int(getattr(m, 'size', 0) or 0)))
    except (tarfile.TarError, OSError) as e:
        raise ValueError(str(e)) from e

    if not items:
        if stage_cb:
            stage_cb('No filesystem files in ota.tar')
        return

    total = sum(sz for _, sz in items)
    done = 0
    t0 = time.time()
    client = tftpy.TftpClient(ip, int(cfg.port))

    with tempfile.TemporaryDirectory(prefix='rnode_halow_tftp_') as td_name:
        td = Path(td_name)
        try:
            with tarfile.open(p, mode='r|*') as tf:
                for m in tf:
                    remote_name = _norm_tar_name(m.name)
                    if not remote_name or remote_name == 'fw.bin' or not m.isfile():
                        continue

                    if stage_cb:
                        stage_cb(f'TFTP upload: {remote_name}')

                    src = tf.extractfile(m)
                    if src is None:
                        raise ValueError(f'failed to read tar member: {remote_name}')

                    local_tmp = td / ('payload_' + Path(remote_name).name)
                    with local_tmp.open('wb') as f:
                        shutil.copyfileobj(src, f, length=1024 * 1024)

                    with local_tmp.open('rb') as f:
                        client.upload(
                            remote_name,
                            f,
                            timeout=float(cfg.timeout_s),
                            retries=int(cfg.retries),
                        )

                    sz = int(local_tmp.stat().st_size)
                    done += sz
                    if progress_cb:
                        elapsed = time.time() - t0
                        speed = done / elapsed if elapsed > 0 else 0.0
                        progress_cb(done, total, speed)

                    try:
                        local_tmp.unlink()
                    except Exception:
                        pass
        except (tarfile.TarError, OSError) as e:
            raise ValueError(str(e)) from e
