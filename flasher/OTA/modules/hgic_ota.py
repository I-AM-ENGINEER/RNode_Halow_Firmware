#!/usr/bin/env python3
"""
HGIC OTA (Ethertype 0x4847) protocol packing/parsing only.

This module must NOT touch scapy/sniffing/sending. Only bytes <-> structs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


ETH_P_OTA = 0x4847


class OtaStype(IntEnum):
    REBOOT = 1
    SCAN = 2
    SCAN_REPORT = 3
    FW_DATA = 4
    FW_DATA_RESP = 5
    FW_GET_PARAM = 6
    FW_GET_PARAM_RESP = 7
    FW_SET_PARAM = 8
    FW_SET_PARAM_RESP = 9


    FW_CUSTOM_GET_IP = 0xF0
    FW_CUSTOM_GET_IP_RESP = 0xF1
class OtaErr(IntEnum):
    OK = 0
    CHECKSUM = 1
    WRITE = 2


class RebootFlags(IntEnum):
    LOADDEF = 1 << 0


@dataclass
class FwAck:
    status: int
    off: int
    tot_len: int
    length: int
    checksum: int
    chipid: int
    first_word: int = 0


def parse_mac(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"Bad MAC: {mac}")
    for p in parts:
        if len(p) != 2:
            raise ValueError(f"Bad MAC: {mac}")
        int(p, 16)
    return mac.lower()

def inet_checksum_16( data: bytes ) -> int:
    s = 0
    if len(data) & 1:
        data += b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]   # BE words (как у тебя в старом)
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF
    
def pack_scan_req() -> bytes:
    return struct.pack("BB", int(OtaStype.SCAN), 0)

def parse_scan_report_payload(b: bytes) -> Optional[tuple[int, int, int, int, int, int, int]]:
    if len(b) < 18:
        return None
    if b[0] != int(OtaStype.SCAN_REPORT):
        return None
    status = b[1]
    version = struct.unpack(">I", b[2:6])[0]
    chipid = struct.unpack(">H", b[6:8])[0]
    mode = b[8]
    rev = b[9]
    svn_version = struct.unpack(">I", b[10:14])[0]
    app_version = struct.unpack(">I", b[14:18])[0]
    return (int(status), int(version), int(chipid), int(mode), int(rev), int(svn_version), int(app_version))


def pack_get_ip_req() -> bytes:
    return struct.pack("BB", int(OtaStype.FW_CUSTOM_GET_IP), 0)

def parse_get_ip_resp_payload(b: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(b) < 14:
        return None
    if b[0] != int(OtaStype.FW_CUSTOM_GET_IP_RESP):
        return None
    status = b[1]
    ip = struct.unpack(">I", b[2:6])[0]
    gw = struct.unpack(">I", b[6:10])[0]
    mask = struct.unpack(">I", b[10:14])[0]
    return (int(status), int(ip), int(gw), int(mask))

def pack_reboot_req(flags: int = 0) -> bytes:
    return struct.pack(">BBI", int(OtaStype.REBOOT), 0, int(flags) & 0xFFFFFFFF)

def pack_fw_data_req(
    fw_chunk: bytes,
    *,
    version: int,
    off: int,
    tot_len: int,
    chipid: int,
):
    if not fw_chunk:
        raise ValueError("fw_chunk is empty")
    if len(fw_chunk) < 2:
        raise ValueError("fw_chunk must be >= 2")

    stype  = int(OtaStype.FW_DATA)  # 0x04
    status = 0

    first_word = struct.unpack(">H", fw_chunk[0:2])[0]   # 0x0269 -> "02 69"
    checksum   = inet_checksum_16(fw_chunk) & 0xFFFF     # 0xC778 -> "<H" даст "78 c7"
    fw_len     = len(fw_chunk) & 0xFFFF                  # 0x0510 -> "<H" даст "10 05"

    payload = b"".join([
        struct.pack("BB", 0x04, 0x00),
        struct.pack(">I", version & 0xFFFFFFFF),
        struct.pack(">I", off & 0xFFFFFFFF),
        struct.pack(">I", tot_len & 0xFFFFFFFF),
        struct.pack(">H", fw_len),
        struct.pack("<H", checksum),
        struct.pack(">H", chipid),
        struct.pack(">H", first_word),
        fw_chunk[2:],
        b"\x00\x00",
    ])


    expect = {
        "version": version & 0xFFFFFFFF,
        "off": off & 0xFFFFFFFF,
        "tot_len": tot_len & 0xFFFFFFFF,
        "length": fw_len,
        "checksum": checksum,
        "chipid": chipid & 0xFFFF,
        "first_word": first_word & 0xFFFF,
    }
    return payload, expect


def parse_fw_ack_payload(b: bytes) -> Optional[FwAck]:
    if len(b) < 22:
        return None
    if b[0] != 0x05:  # FW_DATA_RESP
        return None

    status = b[1]

    off      = struct.unpack(">I", b[6:10])[0]
    tot_len  = struct.unpack(">I", b[10:14])[0]
    length   = struct.unpack(">H", b[14:16])[0]   # ACK: BE
    checksum = struct.unpack("<H", b[16:18])[0]   # ACK: LE
    chipid   = struct.unpack(">H", b[18:20])[0]   # ACK: BE (image_id)
    first    = struct.unpack(">H", b[20:22])[0]   # ACK: BE

    return FwAck(
        status=int(status),
        off=int(off),
        tot_len=int(tot_len),
        length=int(length),
        checksum=int(checksum),
        chipid=int(chipid),
        first_word=int(first),
    )