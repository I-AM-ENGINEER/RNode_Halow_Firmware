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

    script_dir = Path(__file__).resolve().parent

    # 0) create _filesystem directory
    fs_dir = base_path / "_filesystem"
    if fs_dir.exists():
        shutil.rmtree(fs_dir)
    fs_dir.mkdir(parents=True, exist_ok=True)

    # 1) copy .bin as fw.bin
    fw_dst = fs_dir / "fw.bin"
    shutil.copyfile(bin_path, fw_dst)

    # 2) pack_www: собрать ../web_configurator/www → _filesystem/_firmware/index.html
    www_src = (script_dir / "../web_configurator/www").resolve()
    firmware_www_dir = fs_dir / "www"
    firmware_www_dir.mkdir(parents=True, exist_ok=True)

    out_index = firmware_www_dir / "index.html"

    try:
        subprocess.run(
            [
                sys.executable,
                str(script_dir / "pack_www.py"),  # если pack_www лежит рядом
                "--www", str(www_src),
                "--out", str(out_index)
            ],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("pack_www failed")
        sys.exit(e.returncode)

    # 3) pack _filesystem into ota_firmware.tar
    tar_path = base_path / "ota_firmware.tar"
    if tar_path.exists():
        tar_path.unlink()

    with tarfile.open(tar_path, "w") as tar:
        for item in fs_dir.iterdir():
            tar.add(item, arcname=item.name)

    print(f"Created: {tar_path}")


if __name__ == "__main__":
    main()
