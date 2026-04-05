#!/usr/bin/env python3
"""
Firmware flashing helpers (write + reboot) built on hgic_device + hgic_ota protocol.
"""

from __future__ import annotations

import queue
import time
from pathlib import Path
from typing import Callable, Optional

from scapy.all import AsyncSniffer, Ether, Raw  # type: ignore

from .hgic_device import HgicDevice
from .hgic_ota import (
    ETH_P_OTA,
    FwAck,
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

    def flash_firmware(
        self,
        device_mac: str,
        firmware: bytes | Path | str,
        *,
        timeout: float = 2.5,
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
        host_mac = (self.dev.host_mac or "").lower()

        if isinstance(firmware, (str, Path)):
            fw = Path(firmware).read_bytes()
        else:
            fw = bytes(firmware)

        total = len(fw)
        if total == 0:
            raise ValueError("firmware is empty")

        ack_queue: queue.Queue = queue.Queue()

        def on_packet(p) -> None:
            if not p.haslayer(Ether) or not p.haslayer(Raw):
                return
            eth = p[Ether]
            # print(f"[DBG] pkt: type=0x{eth.type:04x} src={eth.src} dst={eth.dst}", flush=True)
            if eth.type != ETH_P_OTA:
                return
            if (eth.src or "").lower() != dev_mac:
                # print(f"[DBG] src mismatch: got={eth.src.lower()} want={dev_mac}", flush=True)
                return
            if (eth.dst or "").lower() != host_mac:
                # print(f"[DBG] dst mismatch: got={eth.dst.lower()} want={host_mac}", flush=True)
                return
            ack = parse_fw_ack_payload(bytes(p[Raw].load))
            if ack:
                # print(f"[DBG] ACK queued: off={ack.off} status={ack.status}", flush=True)
                ack_queue.put(ack)
            # else:
            #     print(f"[DBG] parse_fw_ack_payload=None raw={bytes(p[Raw].load)[:4].hex()}", flush=True)

        # print(f"[DBG] sniffer starting on iface={self.dev.iface} dev_mac={dev_mac} host_mac={host_mac}", flush=True)
        sniffer = AsyncSniffer(iface=self.dev.iface, store=False, prn=on_packet)
        sniffer.start()
        # print(f"[DBG] sniffer started", flush=True)

        off = 0
        t0 = time.time()

        try:
            while off < total:
                chunk_bytes = fw[off : off + chunk]
                payload, _ = pack_fw_data_req(
                    chunk_bytes,
                    version=version,
                    off=off,
                    tot_len=total,
                    chipid=chipid,
                )

                last_ack: Optional[FwAck] = None
                ok = False

                for _ in range(retries):
                    # print(f"[DBG] sending off={off}", flush=True)
                    self.dev.send(dst_mac=dev_mac, payload=payload)
                    try:
                        ack = ack_queue.get(timeout=float(timeout))
                    except queue.Empty:
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
        finally:
            if sniffer.running:
                sniffer.stop(join=False)
