#!/usr/bin/env python3
"""
Scanning helpers (device discovery) built on hgic_device + hgic_ota protocol.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from scapy.all import Ether, Raw  # type: ignore

from .hgic_device import HgicDevice, iter_ifaces
from .hgic_ota import ETH_P_OTA, pack_scan_req, parse_scan_report_payload


@dataclass(frozen=True)
class ScanReport:
    iface_id: str
    iface_name: str
    src_mac: str
    dst_mac: str
    status: int
    version_u32: int
    chipid: int
    mode: int
    rev: int
    svn_version: int
    app_version: int

    @property
    def version_str(self) -> str:
        v0 = (self.version_u32 >> 24) & 0xFF
        v1 = (self.version_u32 >> 16) & 0xFF
        v2 = (self.version_u32 >> 8) & 0xFF
        v3 = (self.version_u32 >> 0) & 0xFF
        return f"{v0}.{v1}.{v2}.{v3}"


def scan_iface(iface: str, *, packet_cnt: int = 10, period_sec: float = 0.010, sniff_time: float = 0.5) -> list[ScanReport]:
    dev = HgicDevice(iface)
    info = dev.iface_info()

    found: list[ScanReport] = []
    seen: set[str] = set()

    def on_packet(p):
        if not p.haslayer(Ether) or not p.haslayer(Raw):
            return
        eth = p[Ether]
        if eth.type != ETH_P_OTA:
            return
        if eth.dst.lower() != info.host_mac:
            return

        src = eth.src.lower()
        if src == info.host_mac or src in seen:
            return

        rep = parse_scan_report_payload(bytes(p[Raw].load))
        if not rep:
            return

        (status, version, chipid, mode, rev, svn_version, app_version) = rep
        seen.add(src)
        found.append(
            ScanReport(
                iface_id=info.iface_id,
                iface_name=info.iface_name,
                src_mac=src,
                dst_mac=eth.dst.lower(),
                status=int(status),
                version_u32=int(version),
                chipid=int(chipid),
                mode=int(mode),
                rev=int(rev),
                svn_version=int(svn_version),
                app_version=int(app_version),
            )
        )

    dev.send_periodic_broadcast(pack_scan_req(), count=packet_cnt, period_sec=period_sec)
    dev.sniff(timeout=sniff_time, prn=on_packet, store=False)
    return found


def scan_all_parallel(packet_cnt: int = 10, period_sec: float = 0.010, sniff_time: float = 0.5) -> list[ScanReport]:
    out: list[ScanReport] = []
    lock = threading.Lock()
    thrs: list[threading.Thread] = []

    def worker(iface: str):
        try:
            res = scan_iface(iface, packet_cnt=packet_cnt, period_sec=period_sec, sniff_time=sniff_time)
        except Exception:
            return
        if not res:
            return
        with lock:
            out.extend(res)

    for iface in iter_ifaces():
        t = threading.Thread(target=worker, args=(iface,), daemon=True)
        thrs.append(t)
        t.start()

    for t in thrs:
        t.join()

    return out
