#!/usr/bin/env python3
"""
Firmware flashing helpers (write + reboot) built on hgic_device + hgic_ota protocol.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from scapy.all import Ether, Raw  # type: ignore

from .hgic_device import HgicDevice
from .hgic_ota import (
    ETH_P_OTA,
    FwAck,
    OtaErr,
    pack_fw_data_req,
    pack_reboot_req,
    parse_fw_ack_payload,
    parse_mac,
)


class HgicFlasher:
    def __init__(self, iface: str):
        self.dev = HgicDevice(iface)

    def reboot(self, device_mac: str, *, flags: int = 0) -> None:
        self.dev.send(dst_mac=device_mac, payload=pack_reboot_req(flags))

    def _wait_fw_ack(self, *, dev_mac: str, timeout_s: float) -> Optional[FwAck]:
        dev_mac  = parse_mac(dev_mac)
        host_mac = (self.dev.host_mac or "").lower()
        got: Optional[FwAck] = None

        def want_pkt(p) -> bool:
            nonlocal got
            if not p.haslayer(Ether) or not p.haslayer(Raw):
                return False

            eth = p[Ether]
            if eth.type != ETH_P_OTA:
                return False
            if (eth.src or "").lower() != dev_mac:
                return False
            if (eth.dst or "").lower() != host_mac:
                return False

            ack = parse_fw_ack_payload(bytes(p[Raw].load))
            if not ack:
                return False

            got = ack
            return True  # стопаем sniff сразу

        # BPF сильно ускоряет (меньше пакетов попадёт в python)
        # На некоторых конфигурациях filter может падать — тогда просто без него.
        bpf = f"ether proto {ETH_P_OTA:#x} and ether src {dev_mac} and ether dst {host_mac}"
        try:
            from scapy.all import sniff  # type: ignore
            sniff(
                iface=self.dev.iface,      # если у тебя иначе называется — подставь нужное поле
                filter=bpf,
                timeout=float(timeout_s),
                store=False,
                stop_filter=want_pkt,
            )
        except Exception:
            from scapy.all import sniff  # type: ignore
            sniff(
                iface=self.dev.iface,
                timeout=float(timeout_s),
                store=False,
                stop_filter=want_pkt,
            )

        return got



    def flash_firmware(
        self,
        device_mac: str,
        firmware: bytes | Path | str,
        *,
        timeout: float = 0.5,
        retries: int = 10,
        progress_cb: Optional[Callable[[int, int, float], None]] = None,
    ) -> None:
        chipid: int = 0x4002
        version: int = 0x01020503
        chunk: int = 1400
        
        if chunk < 1:
            raise ValueError("chunk must be >= 1")
        if retries < 1:
            raise ValueError("retries must be >= 1")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")

        dev_mac = parse_mac(device_mac)

        if isinstance(firmware, (str, Path)):
            fw = Path(firmware).read_bytes()
        else:
            fw = bytes(firmware)

        total = len(fw)
        if total == 0:
            raise ValueError("firmware is empty")

        off = 0
        t0 = time.time()

        while off < total:
            chunk_bytes = fw[off : off + chunk]
            payload, expect = pack_fw_data_req(
                chunk_bytes,
                version=version,
                off=off,
                tot_len=total,
                chipid=chipid,
            )

            last_ack: Optional[FwAck] = None
            ok = False

            for _ in range(retries):
                self.dev.send(dst_mac=dev_mac, payload=payload)
                ack = self._wait_fw_ack(dev_mac=dev_mac, timeout_s=timeout)
                if not ack:
                    continue

                last_ack = ack
                if ack.status == 0:
                    ok = True
                    break

            if not ok:
                if last_ack:
                    raise RuntimeError(f"FW ACK error at off={off} status={last_ack.status}")
                raise RuntimeError(f"No FW ACK for off={off} after {retries} retries")

            off += len(chunk_bytes)

            done = min(off, total)
            elapsed = time.time() - t0
            speed = done / elapsed if elapsed > 0 else 0.0
            if progress_cb:
                progress_cb(done, total, speed)
