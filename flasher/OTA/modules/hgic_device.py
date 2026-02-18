#!/usr/bin/env python3
"""
Low-level Ethernet transport for HGIC OTA.

This module is responsible for scapy send/sniff and interface helpers.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from scapy.all import Ether, Raw, conf, get_if_hwaddr, get_if_list, sendp, sniff  # type: ignore

from .hgic_ota import ETH_P_OTA
from .hgic_ota import parse_mac


def _sniff_safe(
    *,
    iface: str,
    timeout: float,
    prn=None,
    lfilter=None,
    store: bool = False,
    promisc: bool = True,
    bpf: str | None = None,
):
    try:
        return sniff(
            iface=iface,
            timeout=timeout,
            prn=prn,
            lfilter=lfilter,
            store=store,
            promisc=promisc,
            filter=bpf,
        )
    except Exception:
        return sniff(
            iface=iface,
            timeout=timeout,
            prn=prn,
            lfilter=lfilter,
            store=store,
            promisc=promisc,
        )


def _iface_title_windows(iface: str) -> str:
    try:
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:
        return iface

    lname = iface.lower()
    for i in get_windows_if_list():
        guid = i.get("guid")
        if not guid:
            continue
        npf = f"\\device\\npf_{guid}".lower()
        if npf == lname:
            return i.get("name") or iface
    return iface


@dataclass(frozen=True)
class IfaceInfo:
    iface_id: str
    iface_name: str
    host_mac: str


def iter_ifaces() -> list[str]:
    out: list[str] = []
    for iface in get_if_list():
        lname = iface.lower()
        if "loopback" in lname or lname == "lo":
            continue
        out.append(iface)
    return out


class HgicDevice:
    def __init__(self, iface: str):
        self.iface = iface
        conf.iface = iface
        self.host_mac = parse_mac(get_if_hwaddr(iface))
        self.iface_name = _iface_title_windows(iface)

    def iface_info(self) -> IfaceInfo:
        return IfaceInfo(iface_id=self.iface, iface_name=self.iface_name, host_mac=self.host_mac)

    def send(self, *, dst_mac: str, payload: bytes) -> None:
        dst = parse_mac(dst_mac)
        frame = Ether(dst=dst, src=self.host_mac, type=ETH_P_OTA) / Raw(load=payload)
        sendp(frame, iface=self.iface, verbose=False)

    def send_broadcast(self, payload: bytes) -> None:
        frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.host_mac, type=ETH_P_OTA) / Raw(load=payload)
        sendp(frame, iface=self.iface, verbose=False)

    def sniff(
        self,
        *,
        timeout: float,
        prn=None,
        lfilter=None,
        store: bool = False,
    ):
        return _sniff_safe(
            iface=self.iface,
            timeout=timeout,
            prn=prn,
            lfilter=lfilter,
            store=store,
            promisc=True,
            bpf=f"ether proto 0x{ETH_P_OTA:04x}",
        )

    def send_periodic_broadcast(self, payload: bytes, *, count: int, period_sec: float, start_delay: float = 0.1) -> None:
        def sender():
            time.sleep(start_delay)
            for _ in range(count):
                self.send_broadcast(payload)
                time.sleep(period_sec)

        threading.Thread(target=sender, daemon=True).start()
