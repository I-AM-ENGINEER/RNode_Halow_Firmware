#!/usr/bin/env python3
"""High-level HGIC OTA API.

UI (CLI/GUI) should call only this module (and hgic_scan models), without
importing scapy or touching protocol packing/parsing directly.

All network I/O is handled by hgic_device + other modules.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from scapy.all import Ether, Raw, srp1  # type: ignore
from scapy.all import Ether, Raw, sendp, AsyncSniffer, srp1

from .hgic_device import HgicDevice
from .hgic_flash import HgicFlasher
from .hgic_ota_tar import load_fw_bin_from_ota_tar
from .hgic_tftp_ota import TftpOtaConfig, upload_ota_files_tftp
from .hgic_ota import (
    ETH_P_OTA,
    pack_get_ip_req,
    pack_reboot_req,
    parse_get_ip_resp_payload,
    parse_mac,
)


@dataclass(frozen=True)
class IpInfo:
    status: int
    ip: ipaddress.IPv4Address
    gw: ipaddress.IPv4Address
    mask: ipaddress.IPv4Address
    version: str


class HgicSession:
    """Bound to a specific host interface (Npcap/Scapy iface id)."""

    def __init__(self, iface: str):
        self.iface = iface
        self._dev = HgicDevice(iface)
        self._flasher = HgicFlasher(iface)

    @property
    def iface_name(self) -> str:
        return self._dev.iface_name

    @property
    def host_mac(self) -> str:
        return self._dev.host_mac

    def reboot(self, dst_mac: str, *, flags: int = 0, count: int = 3, period_sec: float = 0.05) -> None:
        dst = parse_mac(dst_mac)
        payload = pack_reboot_req(flags)
        for _ in range(int(count)):
            self._dev.send(dst_mac=dst, payload=payload)
            time.sleep(float(period_sec))
            
    def get_ip(self, dst_mac: str, *, tries: int = 5, timeout: float = 0.4) -> Optional[IpInfo]:
        dst_mac_s  = str(dst_mac).lower()
        host_mac_s = str(self._dev.host_mac).lower()
        payload = pack_get_ip_req()

        def is_my_resp(p) -> bool:
            if not p.haslayer(Ether) or not p.haslayer(Raw):
                return False
            eth = p[Ether]
            if int(eth.type) != int(ETH_P_OTA):
                return False
            return (eth.src or "").lower() == dst_mac_s and (eth.dst or "").lower() == host_mac_s

        for _ in range(int(tries)):
            frame = Ether(src=host_mac_s, dst=dst_mac_s, type=ETH_P_OTA) / Raw(load=payload)

            sn = AsyncSniffer(iface=self._dev.iface, store=True, lfilter=is_my_resp)
            sn.start()
            try:
                sendp(frame, iface=self._dev.iface, verbose=False)
                sn.join(timeout=float(timeout))
            finally:
                pkts = sn.stop() or []

            for p in pkts:
                r = parse_get_ip_resp_payload(bytes(p[Raw].load))
                if r is None:
                    continue
                status, ip, gw, mask, ver = r
                return IpInfo(
                    status=int(status),
                    ip=ipaddress.IPv4Address(int(ip)),
                    gw=ipaddress.IPv4Address(int(gw)),
                    mask=ipaddress.IPv4Address(int(mask)),
                    version=str(ver),
                )

        return None

    def flash(
        self,
        dst_mac: str,
        ota_tar: bytes | Path | str,
        *,
        timeout: float = 3.0,
        retries: int = 3,
        retry_delay: float = 3.0,
        progress_cb: Optional[Callable[[int, int, float], None]] = None,
        retry_cb: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        """Flash device firmware from an OTA tar bundle.

        ota_tar:
          - Path/str to ota.tar containing ./fw.bin (preferred), OR
          - bytes (already extracted fw.bin), for higher-level UIs.
        """

        payload: bytes
        if isinstance(ota_tar, (str, Path)):
            payload = load_fw_bin_from_ota_tar(Path(ota_tar))
        else:
            payload = bytes(ota_tar)

        attempts = int(retries)
        if attempts < 1:
            raise ValueError("retries must be >= 1")

        last_err: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                self._flasher.flash_firmware(
                    dst_mac,
                    payload,
                    timeout=float(timeout),
                    retries=1,
                    progress_cb=progress_cb,
                )
                return
            except Exception as e:
                last_err = e
                if attempt >= attempts:
                    break
                if retry_cb:
                    retry_cb(attempt, attempts, str(e))
                time.sleep(float(retry_delay))

        assert last_err is not None
        raise RuntimeError(f"flash failed after {attempts} attempts: {last_err}") from last_err

    def flash_fs(
        self,
        dst_mac: str,
        ota_tar: Path | str,
        *,
        getip_tries: int = 8,
        getip_timeout: float = 0.5,
        tftp_cfg: TftpOtaConfig = TftpOtaConfig(),
        stage_cb: Optional[Callable[[str], None]] = None,
        progress_cb: Optional[Callable[[int, int, float], None]] = None,
    ) -> IpInfo:
        """Upload filesystem files from ota.tar directly over TFTP.

        Steps:
          1) GET_IP over Ethernet (custom OTA ethertype)
          2) Upload every non-fw.bin file from ota.tar to the device TFTP server

        Returns resolved IpInfo.
        """

        info = self.get_ip(dst_mac, tries=int(getip_tries), timeout=float(getip_timeout))
        if info is None:
            raise RuntimeError("GET_IP failed")

        ip_s = str(info.ip)
        if ip_s == "0.0.0.0":
            raise RuntimeError("device reported 0.0.0.0")

        if stage_cb:
            stage_cb(f"Device IP: {ip_s}")

        upload_ota_files_tftp(
            ip_s,
            Path(ota_tar),
            cfg=tftp_cfg,
            stage_cb=stage_cb,
            progress_cb=progress_cb,
        )

        return info
