#!/usr/bin/env python3

import platform
import sys
from pathlib import Path

from modules import scan_all_parallel
from modules import HgicSession
from modules.hgic_ota_tar import inspect_ota_tar


def _ensure_pcap_available() -> bool:
    try:
        from scapy.all import conf  # type: ignore
    except Exception:
        print("[ERR] Scapy is not installed. Install it with:")
        print("      pip install scapy")
        return False

    if getattr(conf, "use_pcap", False):
        return True

    print("\n[ERR] No packet capture backend (pcap) detected.\n")

    system = platform.system()

    if system == "Windows":
        print("Npcap is required on Windows.")
        print("Download it from: https://npcap.com/dist/")

    elif system == "Linux":
        print("libpcap is required on Linux.")
        print("     debian: sudo apt install libpcap-dev")
        print("     fedora: sudo dnf install libpcap")
        print("Then run this script with sudo.\n")

    else:
        print("A libpcap-compatible backend is required on this platform.\n")

    return False


def _progress(done, total, speed):
    pct = done * 100.0 / total if total else 0.0
    print(f"\r{pct:6.2f}%  {done}/{total}  {speed/1024:.1f} KiB/s",
          end="",
          flush=True)

def _fmt_dev(d):
    mac = d.src_mac

    iface = getattr(d, "iface_name", None)
    if not iface:
        iface = getattr(d, "iface_id", "?")

    ver = d.version_str
    return mac, iface, ver

def _print_devices(devs, sel_idx):
    for i, d in enumerate(devs, 1):
        mac, iface, ver = _fmt_dev(d)
        mark = f"[{sel_idx + 1}]" if (i - 1) == sel_idx else f" {i} "
        print(f"{mark:>4}  {mac}  v{ver}  \"{iface}\"")

def _strip_quotes(s):
    s = s.strip()
    if len(s) >= 2 and (
        (s[0] == '"' and s[-1] == '"') or
        (s[0] == "'" and s[-1] == "'")
    ):
        return s[1:-1].strip()
    return s

def _ask_yes_no(prompt):
    try:
        s = input(f"{prompt} [y/N]> ").strip().lower()
    except KeyboardInterrupt:
        raise SystemExit
    except EOFError:
        return False

    return s in ("y", "yes")

def _parse_cmd(line):
    s = line.strip()
    if not s:
        return None, ""

    parts = s.split(maxsplit=1)
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) == 2 else ""
    return cmd, arg

def _resolve_path(s):
    p = Path(_strip_quotes(s)).expanduser()
    try:
        return p.resolve()
    except Exception:
        return p.absolute()

def _flash_selected(devs, sel_idx, path_str):
    d = devs[sel_idx]
    mac, iface, ver = _fmt_dev(d)
    op_iface = getattr(d, "iface_id", iface)

    if not path_str:
        path_str = input("ota.tar path> ").strip()

    p = _resolve_path(path_str)
    if not p.is_file():
        print("bad path")
        return

    try:
        info = inspect_ota_tar(p)
    except FileNotFoundError:
        print("[ERR] file not found")
        return
    except Exception as e:
        print(f"[ERR] invalid ota.tar: {e}")
        return

    print("\n--- confirm ---")
    print("device    :", mac)
    print("iface     :", iface)
    print("remote ver:", ver)
    print("chipid    :", f"0x{int(d.chipid) & 0xFFFF:04X}")
    print("ota file   :", str(p))
    print("contains  :", "./" + str(info.fw_member_name).lstrip("./"))
    print("fw size   :", info.fw_size)
    print("--------------")

    if not _ask_yes_no("flash this ota.tar?"):
        print("canceled")
        return

    sess = HgicSession(op_iface)
    sess.flash(mac, p, timeout=0.5, retries=10, progress_cb=_progress)

    print("\n[+] Done.")


def _flash_fs_selected(devs, sel_idx, path_str):
    d = devs[sel_idx]
    mac, iface, ver = _fmt_dev(d)
    op_iface = getattr(d, "iface_id", iface)

    if not path_str:
        path_str = input("ota.tar path> ").strip()

    p = _resolve_path(path_str)
    if not p.is_file():
        print("bad path")
        return

    try:
        info = inspect_ota_tar(p)
    except FileNotFoundError:
        print("[ERR] file not found")
        return
    except Exception as e:
        print(f"[ERR] invalid ota.tar: {e}")
        return

    print("\n--- confirm ---")
    print("device    :", mac)
    print("iface     :", iface)
    print("remote ver:", ver)
    print("chipid    :", f"0x{int(d.chipid) & 0xFFFF:04X}")
    print("ota file   :", str(p))
    print("contains  :", "./" + str(info.fw_member_name).lstrip("./"))
    print("fw size   :", info.fw_size)
    print("mode      :", "HTTP upload (flash_fs)")
    print("--------------")

    if not _ask_yes_no("upload ota.tar and flash via /api/ota_* ?"):
        print("canceled")
        return

    def _stage(msg: str) -> None:
        print(f"[*] {msg}")

    sess = HgicSession(op_iface)
    try:
        sess.flash_fs(mac, p, stage_cb=_stage, progress_cb=_progress)
    finally:
        print("")

    print("[+] Done.")

def _reboot_selected(devs, sel_idx, arg):
    d = devs[sel_idx]
    mac, iface, ver = _fmt_dev(d)
    op_iface = getattr(d, "iface_id", iface)

    sess = HgicSession(op_iface)
    sess.reboot(mac)

    print("[+] Reboot packet sent.")

def _get_ip_selected(devs, sel_idx, _arg):
    d = devs[sel_idx]
    mac, iface, ver = _fmt_dev(d)
    op_iface = getattr(d, "iface_id", iface)

    sess = HgicSession(op_iface)
    r = sess.get_ip(mac, tries=5, timeout=0.4)
    if r is not None:
        print(f"[+] IP   : {r.ip}")
        print(f"[+] GW   : {r.gw}")
        print(f"[+] MASK : {r.mask}")
        print(f"[+] status={r.status}  device={mac}  iface=\"{iface}\"  v{ver}")
        return

    print("[!] No GET_IP response")


class Command:
    def __init__(self, name, usage, desc, handler):
        self.name = name
        self.usage = usage
        self.desc = desc
        self.handler = handler

def _print_help(cmds):
    print("Commands:")
    for c in cmds.values():
        print(f"  {c.usage:<20} - {c.desc}")
    print("  <N>                  - select device by number")

def main():
    if not _ensure_pcap_available():
        sys.exit(1)

    devs = scan_all_parallel(packet_cnt=10,
                             period_sec=0.010,
                             sniff_time=0.5)

    if not devs:
        print("No devices discovered")
        return

    sel_idx = 0

    def cmd_help(_arg):
        _print_help(cmds)

    def cmd_devices(_arg):
        _print_devices(devs, sel_idx)

    def cmd_select(arg):
        nonlocal sel_idx
        arg = arg.strip()
        if not arg:
            _print_devices(devs, sel_idx)
            return
        try:
            n = int(arg, 10)
        except ValueError:
            print("bad index")
            return
        if not (1 <= n <= len(devs)):
            print("bad index")
            return
        sel_idx = n - 1
        _print_devices(devs, sel_idx)

    def cmd_flash(arg):
        _flash_selected(devs, sel_idx, arg)

    def cmd_flash_fs(arg):
        _flash_fs_selected(devs, sel_idx, arg)

    def cmd_reboot(arg):
        _reboot_selected(devs, sel_idx, arg)

    def cmd_getip(arg):
        _get_ip_selected(devs, sel_idx, arg)

    def cmd_quit(_arg):
        raise SystemExit

    cmds = {
        "help":   Command("help",   "help",               "show this help",             cmd_help),
        "ls":     Command("ls",     "ls",                 "list devices",               cmd_devices),
        "sel":    Command("sel",    "sel [N]",            "select device",              cmd_select),
        "flash":  Command("flash",  "flash [FILE]",       "flash selected device from ota.tar",      cmd_flash),
        "flash_fs": Command("flash_fs", "flash_fs [FILE]", "upload ota.tar via HTTP API then flash", cmd_flash_fs),
        "reboot": Command("reboot", "reboot",             "reboot selected device",     cmd_reboot),
        "ip":     Command("ip",     "ip",                 "read ip/gw/mask from device", cmd_getip),
        "q":      Command("q",      "q",                  "quit",                       cmd_quit),
    }

    _print_help(cmds)
    print()
    print("Scanned devices:")
    _print_devices(devs, sel_idx)

    while True:
        try:
            line = input(f"\n{sel_idx + 1}> ").strip()
        except KeyboardInterrupt:
            return

        cmd, arg = _parse_cmd(line)

        if str(cmd).isdigit():
            try:
                n = int(cmd, 10)
            except ValueError:
                print("bad index")
                continue
            if not (1 <= n <= len(devs)):
                print("bad index")
                continue
            sel_idx = n - 1
            mac, iface, ver = _fmt_dev(devs[sel_idx])
            print(f'Selected {mac} v{ver}  "{iface}"')
            continue

        if not cmd:
            continue

        c = cmds.get(cmd)
        if not c:
            print("unknown cmd (type: help)")
            continue

        try:
            c.handler(arg)
        except SystemExit:
            return

if __name__ == "__main__":
    main()
