#!/usr/bin/env python3

import sys
import shutil
import tarfile
import subprocess
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        print("Usage: build_ota.py <base_path> <firmware.bin>")
        sys.exit(1)

    base_path = Path(sys.argv[1]).resolve()
    bin_path  = Path(sys.argv[2]).resolve()

    if not bin_path.is_file():
        print(f"Firmware file not found: {bin_path}")
        sys.exit(2)

    # 0) create _filesystem directory
    fs_dir = base_path / "_filesystem"
    if fs_dir.exists():
        shutil.rmtree(fs_dir)
    fs_dir.mkdir(parents=True, exist_ok=True)

    # 1) copy .bin as fw.bin
    fw_dst = fs_dir / "fw.bin"
    shutil.copyfile(bin_path, fw_dst)

    # 2) call neighbor script
    this_script_dir = Path(__file__).resolve().parent
    neighbor_script = this_script_dir / "prepare_filesystem.py"

    if not neighbor_script.is_file():
        print(f"Neighbor script not found: {neighbor_script}")
        sys.exit(3)

    subprocess.run(
        [sys.executable, str(neighbor_script), str(fs_dir.resolve())],
        check=True
    )

    # 3) pack _filesystem into ota_firmware.tar
    tar_path = base_path / "ota_firmware.tar"
    if tar_path.exists():
        tar_path.unlink()

    with tarfile.open(tar_path, "w") as tar:
        tar.add(fs_dir, arcname="_filesystem")

    print(f"Created: {tar_path}")


if __name__ == "__main__":
    main()
