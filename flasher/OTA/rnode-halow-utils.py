from pathlib import Path

from modules.discover import scan_all_parallel
from modules.flash_ota import flash_ota


def _progress(done, total, speed):
    pct = done * 100.0 / total if total else 0.0
    print(f"\r{pct:6.2f}%  {done}/{total}  {speed/1024:.1f} KiB/s", end="", flush=True)


def _fmt_dev(d):
    mac   = d["hdr"]["src"]
    iface = d["iface"]
    ver   = d.get("version_str", "?")
    return mac, iface, ver


def _print_devices(devs, sel_idx):
    for i, d in enumerate(devs, 1):
        mac, iface, ver = _fmt_dev(d)
        mark = f"[{sel_idx + 1}]" if (i - 1) == sel_idx else f" {i} "
        print(f"{mark:>4}  {mac}  v{ver}  \"{iface}\"")


def _strip_quotes(s):
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1].strip()
    return s


def _ask_yes_no(prompt):
    try:
        s = input(f"{prompt} [y/N]> ").strip().lower()
    except KeyboardInterrupt:
        quit()
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

    if not path_str:
        path_str = input("firmware path> ").strip()

    p = _resolve_path(path_str)
    if not p.is_file():
        print("bad path")
        return

    print("\n--- confirm ---")
    print("device :", mac)
    print("iface  :", iface)
    print("ver    :", ver)
    print("file   :", str(p))
    print("--------------")

    if not _ask_yes_no("flash this file?"):
        print("canceled")
        return

    flash_ota(
        iface,
        mac,
        p,
        chunk=1400,
        step=1400,
        timeout=0.5,
        retries=10,
        progress_cb=_progress,
    )
    print("\n[+] Done.")


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
    devs = scan_all_parallel(packet_cnt=10, period_sec=0.010, sniff_time=0.5)
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

    def cmd_quit(_arg):
        raise SystemExit

    cmds = {
        "help":   Command("help",   "help",             "show this help",           cmd_help),
        "ls":     Command("ls",     "ls",               "list devices",             cmd_devices),
        "flash":  Command("flash",  "flash [FILE]",     "flash selected device",    cmd_flash),
        "q":      Command("q",      "q",                "quit",                     cmd_quit),
    }

    _print_help(cmds)
    print();print("Scanned devices:")
    _print_devices(devs, sel_idx)

    while True:
        try:
            line = input(f"\n{sel_idx + 1}> ").strip()
        except KeyboardInterrupt:
            return

        cmd, arg = _parse_cmd(line)

        if cmd.isdigit():
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
