#!/usr/bin/env python3
"""
RNode-HaLow Flasher GUI (tkinter) — refactored

Fixes from user feedback:
1) Update works without pre-known IP (two-stage flow handles IP acquisition).
2) IP is always actively requested (rate-limited) and displayed for rnode-halow devices.
3) Flashing directly from GitHub releases is supported (no asset list; one asset assumed).
4) RAW flash speed: scanning never runs during flash/update (pcap lock); scan is opportunistic (non-blocking lock),
   so it won't starve GET_IP or flash operations.

Firmware sources:
- GitHub release tag (v0.4.0 etc). The tool auto-picks single asset:
  prefer .tar (modern), otherwise .bin (old, labeled RAW).
- Local file (.tar or .bin)

Actions:
- Update selected (recommended): requires OTA .tar
  * if device is NOT rnode-halow: RAW flash -> reboot -> wait IP -> HTTP OTA
  * if device IS rnode-halow: wait IP -> HTTP OTA
- Flash RAW (advanced): allows .tar or .bin (bin wrapped into minimal tar)
- Double click device with IP: open http://<ip>/

Requires "modules/" (same as rnode-halow-utils.py):
- scan_all_parallel
- HgicSession
- modules.hgic_ota_tar.inspect_ota_tar
"""

from __future__ import annotations

import json
import platform
import queue
import tarfile
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from modules import scan_all_parallel
from modules import HgicSession
from modules.hgic_ota_tar import inspect_ota_tar


# ----------------------------
# GitHub repo settings
# ----------------------------

REPO_OWNER = "I-AM-ENGINEER"
REPO_NAME  = "RNode_Halow_Firmware"
REPO_URL   = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"
RELEASES_URL = f"{REPO_URL}/releases/"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases"

# NOTE: GitHub releases are downloaded into a temporary directory per GUI run.
# This avoids accidentally flashing a stale cached file when user switches between
# "GitHub release" and "Local file" modes.


# ----------------------------
# PCAP check
# ----------------------------

def pcap_available() -> bool:
    try:
        from scapy.all import conf  # type: ignore
    except Exception:
        return False
    return bool(getattr(conf, "use_pcap", False))


def pcap_missing_message() -> str:
    system = platform.system()
    if system == "Windows":
        return (
            "No packet capture backend (pcap) detected.\n\n"
            "Npcap is required on Windows.\n"
            "Download it from:\n"
            "  https://npcap.com/dist/"
        )
    if system == "Linux":
        return (
            "No packet capture backend (pcap) detected.\n\n"
            "libpcap is required on Linux.\n"
            "  debian: sudo apt install libpcap-dev\n"
            "  fedora: sudo dnf install libpcap\n\n"
            "Then run this script with sudo (or grant needed capabilities)."
        )
    return (
        "No packet capture backend (pcap) detected.\n\n"
        "A libpcap-compatible backend is required on this platform."
    )


# ----------------------------
# Helpers
# ----------------------------

def strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1].strip()
    return s


def resolve_path(s: str) -> Path:
    p = Path(strip_quotes(s)).expanduser()
    try:
        return p.resolve()
    except Exception:
        return p.absolute()


def file_is_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except Exception:
        return False


def make_minimal_ota_tar_from_bin(bin_path: Path) -> Tuple[Path, tempfile.TemporaryDirectory]:
    td = tempfile.TemporaryDirectory(prefix="rnode_halow_tmp_")
    tar_path = Path(td.name) / "ota_from_bin.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo(name="fw.bin")
        info.size = bin_path.stat().st_size
        info.mtime = int(time.time())
        with bin_path.open("rb") as f:
            tf.addfile(info, fileobj=f)
    return tar_path, td


def http_get_json(url: str, timeout_s: float = 1.0) -> Optional[Dict[str, Any]]:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "rnode-halow-gui"})
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as r:
            data = r.read()
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


def pick_version_from_json(obj: Dict[str, Any]) -> Optional[str]:
    for k in ("version", "ver", "fw_ver", "firmware", "fw_version", "build", "sw"):
        v = obj.get(k)
        if isinstance(v, (str, int, float)):
            return str(v)
    for k in ("info", "device", "sys", "system"):
        sub = obj.get(k)
        if isinstance(sub, dict):
            v = pick_version_from_json(sub)
            if v:
                return v
    return None


def is_rnode_halow_by_scan(ver: str) -> bool:
    return (ver or "").strip() == "0.0.0.0"


def fmt_iface(d: Any) -> str:
    iface = getattr(d, "iface_name", None)
    if not iface:
        iface = getattr(d, "iface_id", None)
    if not iface:
        iface = getattr(d, "iface", None)
    return str(iface) if iface is not None else "?"


def fmt_iface_id(d: Any) -> str:
    iface = getattr(d, "iface_id", None)
    if iface:
        return str(iface)
    return fmt_iface(d)


def fmt_mac(d: Any) -> str:
    return str(getattr(d, "src_mac", "")).lower()


def fmt_scan_ver(d: Any) -> str:
    return str(getattr(d, "version_str", "")).strip()


# ----------------------------
# GitHub API (single asset)
# ----------------------------

@dataclass
class GhAsset:
    name: str
    size: int
    url: str

    @property
    def ext(self) -> str:
        return Path(self.name).suffix.lower()

    @property
    def is_tar(self) -> bool:
        return self.ext == ".tar"

    @property
    def is_bin(self) -> bool:
        return self.ext == ".bin"


@dataclass
class GhRelease:
    tag: str
    assets: List[GhAsset]


def github_list_release_tags(timeout_s: float = 8.0) -> List[GhRelease]:
    import urllib.request
    req = urllib.request.Request(GITHUB_API_RELEASES, headers={"User-Agent": "rnode-halow-gui"})
    with urllib.request.urlopen(req, timeout=float(timeout_s)) as r:
        data = r.read()
    obj = json.loads(data.decode("utf-8", errors="replace"))
    if not isinstance(obj, list):
        return []

    rels: List[GhRelease] = []
    for rr in obj:
        if not isinstance(rr, dict):
            continue
        tag = str(rr.get("tag_name") or "").strip()
        if not tag:
            continue

        assets: List[GhAsset] = []
        a_raw = rr.get("assets")
        if isinstance(a_raw, list):
            for a in a_raw:
                if not isinstance(a, dict):
                    continue
                nm = str(a.get("name") or "").strip()
                url = str(a.get("browser_download_url") or "").strip()
                sz = int(a.get("size") or 0)
                if not nm or not url:
                    continue
                ext = Path(nm).suffix.lower()
                if ext not in (".tar", ".bin"):
                    continue
                assets.append(GhAsset(name=nm, size=sz, url=url))

        rels.append(GhRelease(tag=tag, assets=assets))

    return rels


def github_pick_asset(rel: GhRelease) -> Optional[GhAsset]:
    # Prefer modern OTA tar
    for a in rel.assets:
        if a.is_tar:
            return a
    for a in rel.assets:
        if a.is_bin:
            return a
    return None


def github_download(url: str, out_path: Path, progress_cb=None, timeout_s: float = 30.0) -> None:
    import urllib.request

    out_path.parent.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "rnode-halow-gui",
            "Accept": "application/octet-stream",
        },
    )

    with urllib.request.urlopen(req, timeout=float(timeout_s)) as r:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        t0 = time.time()

        with out_path.open("wb") as f:
            while True:
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)

                if progress_cb:
                    dt = max(0.001, time.time() - t0)
                    speed = done / dt
                    progress_cb(done, total, speed)


# ----------------------------
# Device rows
# ----------------------------

@dataclass
class DevRow:
    mac: str
    iface: str
    iface_id: str
    kind: str = ""      # "rnode-halow" | "hgic"
    ip: str = ""
    ver: str = ""       # rnode-halow HTTP version (best-effort)
    last_seen_ts: float = field(default_factory=time.time)

    def key(self) -> Tuple[str, str]:
        return (self.mac, self.iface_id)


# ----------------------------
# App
# ----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("RNode-HaLow Flasher")
        self.geometry("950x620")
        self.minsize(880, 560)

        self._q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._stop = threading.Event()

        # pcap/network serialization
        self._pcap_lock = threading.RLock()
        self._iface_locks: Dict[str, threading.Lock] = {}

        # device state
        self._rows: Dict[Tuple[str, str], DevRow] = {}
        self._tree_items: Dict[Tuple[str, str], str] = {}
        self._selected_key: Optional[Tuple[str, str]] = None

        # IP polling rate-limit
        self._ip_poll_last: Dict[Tuple[str, str], float] = {}
        self._ip_jobs_inflight: set[Tuple[str, str]] = set()

        # firmware state
        self._fw_source = tk.StringVar(value="github")  # "github"|"local"
        self._fw_path = tk.StringVar(value="")
        self._fw_mode = tk.StringVar(value="")          # "ota"|"bin"|""
        self._fw_info = tk.StringVar(value="")

        # keep both selections; switching radiobuttons must immediately switch mode/info/buttons
        self._fw_local_path: Optional[Path] = None
        self._fw_local_mode: str = ""
        self._fw_local_info: str = ""

        self._fw_gh_path: Optional[Path] = None
        self._fw_gh_mode: str = ""
        self._fw_gh_info: str = ""
        self._fw_gh_tag: str = ""

        # github download temp dir (per GUI run)
        self._gh_tmp = tempfile.TemporaryDirectory(prefix="rnode_halow_gh_")
        self._gh_tmp_dir = Path(self._gh_tmp.name)

        # github
        self._gh_status = tk.StringVar(value="GitHub: …")
        self._gh_tags: List[str] = []
        self._gh_rels: Dict[str, GhRelease] = {}
        self._gh_tag = tk.StringVar(value="")

        # scanning
        self._auto_refresh = tk.BooleanVar(value=True)
        self._scan_interval_s = tk.DoubleVar(value=2.0)

        # busy (UI only)
        self._busy = threading.Event()

        # startup pcap check
        self.withdraw()
        if not pcap_available():
            try:
                messagebox.showerror("pcap backend missing", pcap_missing_message())
            except Exception:
                pass
            self.destroy()
            return

        self._build_ui()
        self.deiconify()

        # timers/threads
        self.after(60, self._poll_queue)
        threading.Thread(target=self._scan_loop, daemon=True).start()

        # fetch releases
        self._gh_refresh_async()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------

    def _build_ui(self) -> None:
        fw = ttk.LabelFrame(self, text="Firmware")
        fw.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)

        fw_top = ttk.Frame(fw)
        fw_top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(6, 2))

        ttk.Button(fw_top, text="GitHub", command=lambda: webbrowser.open(REPO_URL)).pack(side=tk.RIGHT)
        ttk.Button(fw_top, text="Releases", command=lambda: webbrowser.open(RELEASES_URL)).pack(side=tk.RIGHT, padx=(6, 6))

        ttk.Radiobutton(
            fw_top, text="GitHub release:", value="github", variable=self._fw_source,
            command=self._fw_source_changed
        ).pack(side=tk.LEFT)

        self._gh_combo = ttk.Combobox(fw_top, textvariable=self._gh_tag, state="readonly", width=22)
        self._gh_combo.pack(side=tk.LEFT, padx=(6, 6))
        self._gh_combo.bind("<<ComboboxSelected>>", self._gh_tag_selected)

        ttk.Button(fw_top, text="Refresh", command=self._gh_refresh_async).pack(side=tk.LEFT)

        fw_mid = ttk.Frame(fw)
        fw_mid.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(2, 6))

        ttk.Radiobutton(
            fw_mid, text="Local file:", value="local", variable=self._fw_source,
            command=self._fw_source_changed
        ).pack(side=tk.LEFT)

        self._fw_entry = ttk.Entry(fw_mid, textvariable=self._fw_path)
        self._fw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        self._btn_browse = ttk.Button(fw_mid, text="Browse…", command=self._browse_fw)
        self._btn_browse.pack(side=tk.LEFT)

        ttk.Label(fw_mid, textvariable=self._fw_info, foreground="#888").pack(side=tk.LEFT, padx=(10, 0))
        ttk.Label(fw, textvariable=self._gh_status, foreground="#888").pack(side=tk.TOP, anchor=tk.W, padx=10, pady=(0, 6))

        dev = ttk.LabelFrame(self, text="Devices")
        dev.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

        ctrl = ttk.Frame(dev)
        ctrl.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 6))

        ttk.Checkbutton(ctrl, text="Auto refresh", variable=self._auto_refresh).pack(side=tk.LEFT)
        ttk.Label(ctrl, text="Interval (s):").pack(side=tk.LEFT, padx=(10, 4))
        ttk.Spinbox(ctrl, from_=0.5, to=10.0, increment=0.5, textvariable=self._scan_interval_s, width=5).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="Refresh now", command=self._scan_once_async).pack(side=tk.LEFT, padx=(10, 0))

        self._btn_open_cfg = ttk.Button(ctrl, text="Open configurator", command=self._open_configurator_selected)
        self._btn_open_cfg.pack(side=tk.LEFT, padx=(6, 0))

        self._btn_reboot = ttk.Button(ctrl, text="Reboot", command=self._reboot_selected)
        self._btn_reboot.pack(side=tk.LEFT, padx=(6, 0))

        self._btn_flash = ttk.Button(ctrl, text="Flash", command=self._flash_selected)
        self._btn_flash.pack(side=tk.RIGHT)

        cols = ("mac", "iface", "type", "ip", "version")
        self._tree = ttk.Treeview(dev, columns=cols, show="headings", selectmode="browse")
        for c, txt, w in [
            ("mac", "MAC", 170),
            ("iface", "Interface", 170),
            ("type", "Type", 120),
            ("ip", "IP", 140),
            ("version", "Version", 140),
        ]:
            self._tree.heading(c, text=txt)
            self._tree.column(c, width=w, anchor=tk.W)
        self._tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _e: self._open_configurator_selected())

        bot = ttk.Frame(self)
        bot.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=False, padx=10, pady=(0, 10))

        pbar = ttk.Frame(bot)
        pbar.pack(side=tk.TOP, fill=tk.X)

        self._p = ttk.Progressbar(pbar, orient=tk.HORIZONTAL, mode="determinate")
        self._p.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._p_lbl = ttk.Label(pbar, text="")
        self._p_lbl.pack(side=tk.LEFT, padx=(10, 0))

        self._log = tk.Text(bot, height=9, wrap=tk.WORD)
        self._log.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(8, 0))
        self._log.tag_configure("err", foreground="#ff6666")
        self._log.tag_configure("ok", foreground="#66ff99")
        self._log.tag_configure("stage", foreground="#66aaff")

        self._fw_source_changed()
        self._refresh_buttons()

    # ---------- UI state ----------

    def _log_line(self, s: str, tag: str = "") -> None:
        self._log.insert(tk.END, s + "\n", tag)
        self._log.see(tk.END)

    def _set_progress(self, pct: float, done: int = 0, total: int = 0, speed: float = 0.0) -> None:
        pct = max(0.0, min(100.0, float(pct)))
        self._p["value"] = pct
        if total > 0:
            self._p_lbl.config(text=f"{pct:6.2f}%  {done}/{total}  {speed/1024:.1f} KiB/s")
        else:
            self._p_lbl.config(text=f"{pct:6.2f}%")

    def _set_busy(self, b: bool) -> None:
        if b:
            self._busy.set()
        else:
            self._busy.clear()
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        mode = self._fw_mode.get().strip()
        busy = self._busy.is_set()

        has_sel = bool(self._selected_key and (self._selected_key in self._rows))
        if hasattr(self, "_btn_open_cfg"):
            self._btn_open_cfg.config(state=("normal" if (has_sel and not busy) else "disabled"))

        if hasattr(self, "_btn_reboot"):
            self._btn_reboot.config(state=("normal" if (has_sel and not busy) else "disabled"))

        if hasattr(self, "_btn_flash"):
            self._btn_flash.config(state=("normal" if (has_sel and (mode in ("ota", "bin")) and not busy) else "disabled"))

    def _apply_fw_view(self) -> None:
        src = self._fw_source.get().strip()
        if src == "github":
            p = self._fw_gh_path
            m = (self._fw_gh_mode or "").strip()
            info = self._fw_gh_info
            if p and p.is_file() and m in ("ota", "bin"):
                self._fw_path.set(str(p))
                self._fw_mode.set(m)
                self._fw_info.set(info)
            else:
                self._fw_path.set("")
                self._fw_mode.set("")
                self._fw_info.set("")
        else:
            p = self._fw_local_path
            m = (self._fw_local_mode or "").strip()
            info = self._fw_local_info
            if p and p.is_file() and m in ("ota", "bin"):
                self._fw_path.set(str(p))
                self._fw_mode.set(m)
                self._fw_info.set(info)
            else:
                # keep the entry text for convenience, but disable actions
                self._fw_mode.set("")
                self._fw_info.set("")
        self._refresh_buttons()

    def _fw_source_changed(self) -> None:
        src = self._fw_source.get().strip()
        if src == "github":
            self._gh_combo.configure(state="readonly")
            self._fw_entry.configure(state="disabled")
            self._btn_browse.configure(state="disabled")
        else:
            self._gh_combo.configure(state="disabled")
            self._fw_entry.configure(state="normal")
            self._btn_browse.configure(state="normal")

        # switching radiobuttons must immediately switch mode/info/buttons
        self._apply_fw_view()

    # ---------- Firmware: local ----------

    def _browse_fw(self) -> None:
        p = filedialog.askopenfilename(
            title="Select firmware file",
            filetypes=[("OTA tar (.tar)", "*.tar"), ("Firmware bin (.bin)", "*.bin"), ("All files", "*.*")],
        )
        if not p:
            return
        self._set_fw_local(resolve_path(p))

    def _set_fw_local(self, path: Path) -> None:
        ext = path.suffix.lower()
        mode = ""
        if ext == ".tar":
            mode = "ota"
        elif ext == ".bin":
            mode = "bin"

        if mode == "bin":
            if file_is_tar(path):
                messagebox.showerror("Looks like a TAR", "This file looks like a TAR archive but has .bin extension.")
                return
            if not messagebox.askyesno("Confirm BIN", "This is a RAW .bin firmware (NOT an OTA .tar). Proceed?"):
                return

        info_s = ""
        if mode == "ota":
            try:
                info = inspect_ota_tar(path)
                name = "./" + str(info.fw_member_name).lstrip("./")
                info_s = f"Local OTA: {name}"
            except Exception as e:
                info_s = f"Local OTA invalid: {e}"
        elif mode == "bin":
            info_s = "Local BIN (raw)"

        self._fw_local_path = path
        self._fw_local_mode = mode
        self._fw_local_info = info_s
        if self._fw_source.get().strip() == "local":
            self._apply_fw_view()

    # ---------- Firmware: GitHub ----------

    def _gh_refresh_async(self) -> None:
        self._gh_status.set("GitHub: fetching…")
        threading.Thread(target=self._gh_refresh_worker, daemon=True).start()

    def _gh_refresh_worker(self) -> None:
        try:
            rels = github_list_release_tags(timeout_s=8.0)
            self._q.put(("gh_rels", rels))
        except Exception as e:
            self._q.put(("gh_err", str(e)))

    def _gh_tag_selected(self, _evt=None) -> None:
        if self._fw_source.get().strip() != "github":
            return
        tag = self._gh_tag.get().strip()
        if not tag:
            return
        threading.Thread(target=self._gh_use_tag_worker, args=(tag,), daemon=True).start()

    def _gh_use_tag_worker(self, tag: str) -> None:
        rel = self._gh_rels.get(tag)
        if not rel:
            self._q.put(("log", (f"[ERR] GitHub: tag not found: {tag}", "err")))
            return
        asset = github_pick_asset(rel)
        if not asset:
            self._q.put(("log", (f"[ERR] GitHub: no .tar/.bin asset in {tag}", "err")))
            return

        # download into a per-run temp directory (requested)
        if self._gh_tmp is None:
            self._gh_tmp = tempfile.TemporaryDirectory(prefix="rnode_halow_github_")
        out_dir = Path(self._gh_tmp.name) / tag
        out_path = out_dir / asset.name

        if asset.is_bin:
            # confirmation in UI thread
            self._q.put(("gh_confirm_bin", (tag, asset.name)))

        # download (NO pcap lock; should not block scanning)
        self._q.put(("log", (f"[*] GitHub: downloading {tag}", "stage")))

        def cb(done: int, total: int, speed: float) -> None:
            pct = (done * 100.0 / total) if total else 0.0
            self._q.put(("progress", (pct, done, total, speed)))

        try:
            github_download(asset.url, out_path, progress_cb=cb, timeout_s=30.0)
            self._q.put(("fw_set", (str(out_path), "ota" if asset.is_tar else "bin", tag)))
            self._q.put(("log", (f"[OK] GitHub ready: {tag}", "ok")))
        except Exception as e:
            self._q.put(("log", (f"[ERR] GitHub download failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))

    def _set_fw_github(self, path: Path, mode: str, tag: str) -> None:
        # store github selection; apply only if github radiobutton is active
        self._fw_gh_path = path
        self._fw_gh_mode = str(mode or "").strip()
        self._fw_gh_tag = str(tag or "").strip()
        if self._fw_gh_mode == "bin":
            self._fw_gh_info = f"GitHub {self._fw_gh_tag} (raw)"
        elif self._fw_gh_mode == "ota":
            self._fw_gh_info = f"GitHub {self._fw_gh_tag}"
        else:
            self._fw_gh_info = ""

        if self._fw_source.get().strip() == "github":
            self._apply_fw_view()

    # ---------- Devices selection ----------

    def _on_select(self, _evt=None) -> None:
        sel = self._tree.selection()
        if not sel:
            self._selected_key = None
            return
        item = sel[0]
        for k, iid in self._tree_items.items():
            if iid == item:
                self._selected_key = k
                break
        self._refresh_buttons()

    def _open_configurator_selected(self) -> None:
        if not self._selected_key:
            return
        row = self._rows.get(self._selected_key)
        if not row:
            return
        ip = (row.ip or "").strip()
        if not ip:
            self._log_line("[!] no IP for selected device", "err")
            return
        webbrowser.open(f"http://{ip}/")

    # ---------- Scanning / IP polling ----------

    def _iface_lock(self, iface_id: str) -> threading.Lock:
        if iface_id not in self._iface_locks:
            self._iface_locks[iface_id] = threading.Lock()
        return self._iface_locks[iface_id]

    def _scan_loop(self) -> None:
        while not self._stop.is_set():
            if self._auto_refresh.get():
                self._scan_worker()
            delay = float(self._scan_interval_s.get() or 2.0)
            for _ in range(int(max(1, delay * 10))):
                if self._stop.is_set():
                    break
                time.sleep(0.1)

    def _scan_once_async(self) -> None:
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        # Opportunistic scan: if pcap is in use (flash/get_ip), do not scan.
        if not self._pcap_lock.acquire(blocking=False):
            return
        try:
            devs = scan_all_parallel(packet_cnt=10, period_sec=0.010, sniff_time=0.5)
        except Exception as e:
            self._q.put(("log", (f"[ERR] scan failed: {e}", "err")))
            return
        finally:
            try:
                self._pcap_lock.release()
            except Exception:
                pass

        now = time.time()
        seen: set[Tuple[str, str]] = set()
        rows: List[DevRow] = []

        for d in devs or []:
            mac = fmt_mac(d)
            iface = fmt_iface(d)
            iface_id = fmt_iface_id(d)
            ver = fmt_scan_ver(d)
            kind = "rnode-halow" if is_rnode_halow_by_scan(ver) else "hgic"

            key = (mac, iface_id)
            seen.add(key)

            r = self._rows.get(key, DevRow(mac=mac, iface=iface, iface_id=iface_id))
            r.iface = iface
            r.kind = kind
            r.last_seen_ts = now
            rows.append(r)

        self._q.put(("scan", (rows, seen)))

    def _maybe_poll_ip(self, r: DevRow) -> None:
        key = r.key()
        if r.kind != "rnode-halow":
            return
        if key in self._ip_jobs_inflight:
            return
        now = time.time()
        last = float(self._ip_poll_last.get(key, 0.0))
        # rate limit: 2 seconds
        if (now - last) < 2.0:
            return
        self._ip_poll_last[key] = now
        self._ip_jobs_inflight.add(key)
        threading.Thread(target=self._ip_poll_worker, args=(r,), daemon=True).start()

    def _ip_poll_worker(self, r: DevRow) -> None:
        key = r.key()
        try:
            ip_s = ""
            ver_s = ""
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)
                    ans = sess.get_ip(r.mac, tries=1, timeout=0.35)
            if ans is not None:
                ip_s = str(getattr(ans, "ip", "") or "")
                if ip_s == "0.0.0.0":
                    ip_s = ""
                ver_s = str(getattr(ans, "version", "") or "")

            if ip_s and not ver_s:
                for path in ("/api/heartbeat", "/api/version", "/api/info", "/api/get_all"):
                    obj = http_get_json(f"http://{ip_s}{path}", timeout_s=1.0)
                    if isinstance(obj, dict):
                        v = pick_version_from_json(obj)
                        if v:
                            ver_s = v
                            break

            self._q.put(("devinfo", (key, ip_s, ver_s)))
        finally:
            self._ip_jobs_inflight.discard(key)

    # ---------- Actions ----------

    def _ensure_fw_path(self) -> Optional[Tuple[Path, str]]:
        src = self._fw_source.get().strip()
        if src == "github":
            tag = self._gh_tag.get().strip()
            if not tag:
                return None
            if (self._fw_gh_tag or "").strip() != tag:
                return None
            if not self._fw_gh_path or not self._fw_gh_path.is_file():
                return None
        else:
            if not self._fw_local_path or not self._fw_local_path.is_file():
                return None

        p = resolve_path(self._fw_path.get()) if self._fw_path.get().strip() else None
        mode = self._fw_mode.get().strip()
        if not p or not p.is_file():
            return None
        if mode not in ("ota", "bin"):
            return None
        return (p, mode)

    def _ensure_selected(self) -> Optional[DevRow]:
        if not self._selected_key:
            messagebox.showinfo("Select device", "Select a device first.")
            return None
        r = self._rows.get(self._selected_key)
        if not r:
            messagebox.showerror("Not found", "Selected device is not available (maybe went offline).")
            return None
        return r

    def _flash_selected(self) -> None:
        r = self._ensure_selected()
        if not r:
            return

        fw = self._ensure_fw_path()
        if not fw:
            messagebox.showerror("No firmware", "Select a firmware first.")
            return

        fw_path, mode = fw
        have_ip = bool((r.ip or "").strip())

        fw_name = ""
        if mode == "ota":
            try:
                info = inspect_ota_tar(fw_path)
                fw_name = "./" + str(info.fw_member_name).lstrip("./")
            except Exception as e:
                messagebox.showerror("Invalid OTA", f"Invalid ota.tar: {e}")
                return

        if mode == "bin":
            plan = "RAW flash (bin) -> reboot"
        else:
            if have_ip:
                plan = "OTA via HTTP"
            else:
                plan = "RAW flash -> reboot -> wait IP -> OTA via HTTP"

        if not messagebox.askyesno(
            "Confirm flash",
            f"Device: {r.mac}\n"
            f"Type: {r.kind}\n"
            f"IP: {(r.ip or '(none)')}\n\n"
            f"Firmware: {fw_name or fw_path.name}\n"
            f"Mode: {mode}\n\n"
            f"Plan: {plan}\n\n"
            f"Proceed?",
        ):
            return

        if self._busy.is_set():
            return
        self._set_busy(True)
        self._set_progress(0.0, 0, 0, 0.0)
        threading.Thread(target=self._flash_worker, args=(r, fw_path, mode, have_ip), daemon=True).start()

    def _flash_worker(self, r: DevRow, fw_path: Path, mode: str, have_ip: bool) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    def cb_stage(msg: str) -> None:
                        self._q.put(("log", ("[*] " + msg, "stage")))

                    if mode == "bin":
                        self._q.put(("log", ("[*] RAW flash (bin)", "stage")))
                        tar_p, td = make_minimal_ota_tar_from_bin(fw_path)
                        try:
                            sess.flash(r.mac, tar_p, timeout=3.0, retries=10, progress_cb=cb_progress)
                            self._q.put(("log", ("[OK] RAW flash done", "ok")))
                        finally:
                            try:
                                td.cleanup()
                            except Exception:
                                pass

                        self._q.put(("log", ("[*] reboot", "stage")))
                        sess.reboot(r.mac, flags=0, count=3, period_sec=0.05)
                        self._q.put(("log", ("[OK] reboot sent", "ok")))
                        return

                    # mode == "ota"
                    if not have_ip:
                        self._q.put(("log", ("[*] stage1: RAW flash (ota.tar)", "stage")))
                        sess.flash(r.mac, fw_path, timeout=0.45, retries=6, progress_cb=cb_progress)
                        self._q.put(("log", ("[OK] stage1 done", "ok")))

                        self._q.put(("log", ("[*] reboot", "stage")))
                        sess.reboot(r.mac, flags=0, count=3, period_sec=0.05)

                        self._q.put(("log", ("[*] waiting IP…", "stage")))
                        ip_s = self._wait_ip(sess, r.mac, overall_timeout_s=80.0)
                        if not ip_s:
                            self._q.put(("log", ("[ERR] IP not acquired (timeout).", "err")))
                            return
                        self._q.put(("devinfo", (r.key(), ip_s, "")))

                    self._q.put(("log", ("[*] stage2: OTA via HTTP", "stage")))
                    sess.flash_fs(r.mac, fw_path, stage_cb=cb_stage, progress_cb=cb_progress)
                    self._q.put(("log", ("[OK] flash done", "ok")))

            self._maybe_poll_ip(self._rows.get(r.key(), r))
        except Exception as e:
            self._q.put(("log", (f"[ERR] flash failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    def _reboot_selected(self) -> None:
        r = self._ensure_selected()
        if not r:
            return

        if not messagebox.askyesno(
            "Confirm reboot",
            f"Reboot device via HGIC?\n\nMAC: {r.mac}\nInterface: {r.iface}\n",
        ):
            return

        if self._busy.is_set():
            return
        self._set_busy(True)
        threading.Thread(target=self._reboot_worker, args=(r,), daemon=True).start()

    def _reboot_worker(self, r: DevRow) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)
                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(r.mac, flags=0, count=3, period_sec=0.05)
                    self._q.put(("log", ("[OK] reboot sent", "ok")))
        except Exception as e:
            self._q.put(("log", (f"[ERR] reboot failed: {e}", "err")))
        finally:
            self._q.put(("busy", False))

    def _wait_ip(self, sess: HgicSession, mac: str, *, overall_timeout_s: float = 60.0) -> Optional[str]:
        t0 = time.time()
        while time.time() - t0 < overall_timeout_s:
            try:
                ans = sess.get_ip(mac, tries=1, timeout=0.5)
            except Exception:
                ans = None
            if ans is not None:
                ip_s = str(getattr(ans, "ip", "") or "")
                if ip_s and ip_s != "0.0.0.0":
                    return ip_s
            time.sleep(0.4)
        return None

    def _update_worker(self, r: DevRow, tar_path: Path) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    def cb_stage(msg: str) -> None:
                        self._q.put(("log", ("[*] " + msg, "stage")))

                    # Stage 1 (only for non-rnode-halow)
                    if r.kind != "rnode-halow":
                        self._q.put(("log", ("[*] stage1: RAW flash", "stage")))
                        # slightly lower retries vs old GUI to avoid "unnecessary retries"
                        sess.flash(r.mac, tar_path, timeout=0.45, retries=6, progress_cb=cb_progress)
                        self._q.put(("log", ("[OK] stage1 done", "ok")))

                        self._q.put(("log", ("[*] reboot", "stage")))
                        sess.reboot(r.mac)

                        self._q.put(("log", ("[*] waiting IP…", "stage")))
                        ip_s = self._wait_ip(sess, r.mac, overall_timeout_s=80.0)
                        if not ip_s:
                            self._q.put(("log", ("[ERR] IP not acquired (timeout).", "err")))
                            return
                        self._q.put(("devinfo", (r.key(), ip_s, "")))
                    else:
                        # Stage 0: ensure IP even if not displayed yet
                        if not (r.ip or "").strip():
                            self._q.put(("log", ("[*] waiting IP…", "stage")))
                            ip_s = self._wait_ip(sess, r.mac, overall_timeout_s=35.0)
                            if not ip_s:
                                self._q.put(("log", ("[ERR] No IP (timeout).", "err")))
                                return
                            self._q.put(("devinfo", (r.key(), ip_s, r.ver)))

                    # Stage 2 (HTTP OTA): uses flash_fs
                    self._q.put(("log", ("[*] stage2: OTA via HTTP", "stage")))
                    sess.flash_fs(r.mac, tar_path, stage_cb=cb_stage, progress_cb=cb_progress)
                    self._q.put(("log", ("[OK] update done", "ok")))

            # refresh ip/version (best-effort)
            self._maybe_poll_ip(self._rows.get(r.key(), r))
        except Exception as e:
            self._q.put(("log", (f"[ERR] update failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    def _raw_worker(self, r: DevRow, fw_path: Path, mode: str) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    if mode == "ota":
                        self._q.put(("log", ("[*] RAW flash (ota.tar)", "stage")))
                        sess.flash(r.mac, fw_path, timeout=2.0, retries=3, progress_cb=cb_progress)
                        self._q.put(("log", ("[OK] RAW flash done", "ok")))
                    else:
                        self._q.put(("log", ("[*] RAW flash (bin)", "stage")))
                        tar_p, td = make_minimal_ota_tar_from_bin(fw_path)
                        try:
                            sess.flash(r.mac, tar_p, timeout=3.0, retries=10, progress_cb=cb_progress)
                            self._q.put(("log", ("[OK] RAW flash done", "ok")))
                        finally:
                            try:
                                td.cleanup()
                            except Exception:
                                pass


                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(r.mac, flags=0, count=3, period_sec=0.05)
                    self._q.put(("log", ("[OK] reboot sent", "ok")))
        except Exception as e:
            self._q.put(("log", (f"[ERR] RAW flash failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    # ---------- Tree update helpers ----------

    def _row_values(self, r: DevRow) -> Tuple[str, str, str, str, str]:
        return (r.mac, r.iface, r.kind, r.ip, r.ver if r.kind == "rnode-halow" else "")

    def _upsert_row(self, r: DevRow) -> None:
        key = r.key()
        self._rows[key] = r
        vals = self._row_values(r)
        if key in self._tree_items:
            self._tree.item(self._tree_items[key], values=vals)
        else:
            self._tree_items[key] = self._tree.insert("", tk.END, values=vals)

    def _remove_row(self, key: Tuple[str, str]) -> None:
        iid = self._tree_items.pop(key, None)
        if iid:
            try:
                self._tree.delete(iid)
            except Exception:
                pass
        self._rows.pop(key, None)
        self._ip_poll_last.pop(key, None)
        self._ip_jobs_inflight.discard(key)
        if self._selected_key == key:
            self._selected_key = None

    # ---------- Queue polling ----------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()

                if kind == "scan":
                    rows, seen = payload
                    for r in rows:
                        self._upsert_row(r)
                        self._maybe_poll_ip(r)
                    # remove offline
                    for k in list(self._rows.keys()):
                        if k not in seen:
                            self._remove_row(k)

                    self._refresh_buttons()

                elif kind == "devinfo":
                    key, ip_s, ver_s = payload
                    r = self._rows.get(key)
                    if r:
                        if isinstance(ip_s, str):
                            r.ip = ip_s
                        if isinstance(ver_s, str) and ver_s:
                            r.ver = ver_s
                        self._upsert_row(r)
                        self._refresh_buttons()

                elif kind == "log":
                    s, tag = payload
                    self._log_line(str(s), tag or "")

                elif kind == "progress":
                    pct, done, total, speed = payload
                    self._set_progress(float(pct), int(done), int(total), float(speed))

                elif kind == "busy":
                    self._set_busy(bool(payload))

                elif kind == "gh_rels":
                    rels: List[GhRelease] = payload
                    self._gh_rels = {r.tag: r for r in rels}
                    self._gh_tags = [r.tag for r in rels]
                    self._gh_combo["values"] = self._gh_tags
                    if self._gh_tags and not self._gh_tag.get().strip():
                        self._gh_tag.set(self._gh_tags[0])
                        # auto download/activate first tag
                        self._gh_tag_selected()
                    self._gh_status.set(f"GitHub: {len(self._gh_tags)} release(s)")

                elif kind == "gh_err":
                    self._gh_status.set("GitHub: error")
                    self._log_line(f"[ERR] GitHub: {payload}", "err")

                elif kind == "gh_confirm_bin":
                    tag, name = payload
                    ok = True
                    if not ok:
                        self._log_line("[*] GitHub download cancelled", "stage")
                        # clear selection
                        self._gh_tag.set("")
                        self._fw_mode.set("")
                        self._fw_info.set("")
                        self._refresh_buttons()

                elif kind == "fw_set":
                    p_str, mode, tag = payload
                    self._set_fw_github(resolve_path(p_str), mode, tag)

        except queue.Empty:
            pass

        self.after(80, self._poll_queue)

    # ---------- Close ----------

    def _on_close(self) -> None:
        self._stop.set()
        try:
            if hasattr(self, "_gh_tmp") and self._gh_tmp is not None:
                self._gh_tmp.cleanup()
        except Exception:
            pass

        try:
            self.destroy()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


def main() -> None:
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
