import struct
import time
from pathlib import Path
from scapy.all import Ether, sendp, sniff, conf, get_if_hwaddr

ETHERTYPE_HG  = 0x4847
FIXED_HDR     = b"\x00\x01\x02\x05\x03"
IMAGE_ID      = 0x4002
DEFAULT_CHUNK = 1400


def _parse_mac(s: str) -> str:
    parts = s.split(":")
    if len(parts) != 6:
        raise ValueError(f"Bad MAC: {s}")
    for p in parts:
        if len(p) != 2:
            raise ValueError(f"Bad MAC: {s}")
        int(p, 16)
    return s.lower()


def _inet_checksum_16(data: bytes) -> int:
    s = 0
    if len(data) & 1:
        data += b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _build_data_payload(fw: bytes, offset: int, chunk_len: int) -> tuple[bytes, dict]:
    total = len(fw)
    chunk = fw[offset:offset + chunk_len]
    if len(chunk) != chunk_len:
        raise ValueError("chunk slicing error")
    if chunk_len < 2:
        raise ValueError("chunk_len must be >= 2")

    first_word = struct.unpack(">H", chunk[0:2])[0]
    cksum = _inet_checksum_16(chunk)

    payload = bytearray()
    payload += b"\x04"
    payload += FIXED_HDR
    payload += struct.pack(">I", offset)
    payload += struct.pack(">I", total)
    payload += struct.pack(">H", chunk_len)
    payload += struct.pack("<H", cksum)
    payload += struct.pack(">H", IMAGE_ID)
    payload += struct.pack(">H", first_word)
    payload += chunk[2:] + b"\x00\x00"

    expect = {
        "offset": offset,
        "total": total,
        "chunk_len": chunk_len,
        "cksum": cksum,
        "image_id": IMAGE_ID,
        "first_word": first_word,
    }

    return bytes(payload), expect


def _parse_ack_payload(p: bytes):
    if len(p) < 22:
        return None
    if p[0] != 0x05:
        return None
    if p[1:6] != FIXED_HDR:
        return None

    offset     = struct.unpack(">I", p[6:10])[0]
    total      = struct.unpack(">I", p[10:14])[0]
    chunk_len  = struct.unpack(">H", p[14:16])[0]
    cksum      = struct.unpack("<H", p[16:18])[0]
    image_id   = struct.unpack(">H", p[18:20])[0]
    first_word = struct.unpack(">H", p[20:22])[0]

    return {
        "offset": offset,
        "total": total,
        "chunk_len": chunk_len,
        "cksum": cksum,
        "image_id": image_id,
        "first_word": first_word,
    }


def _wait_for_ack(iface: str, dev_mac: str, host_mac: str, expect: dict, timeout_s: float) -> bool:
    dev_mac = dev_mac.lower()
    host_mac = host_mac.lower()

    def lfilter(pkt):
        if not pkt.haslayer(Ether):
            return False
        eth = pkt[Ether]
        if eth.type != ETHERTYPE_HG:
            return False
        if eth.src.lower() != dev_mac:
            return False
        if eth.dst.lower() != host_mac:
            return False

        ack = _parse_ack_payload(bytes(eth.payload))
        if not ack:
            return False

        for k in ("offset", "total", "chunk_len", "cksum", "image_id", "first_word"):
            if ack[k] != expect[k]:
                return False
        return True

    return len(sniff(iface=iface, timeout=timeout_s, lfilter=lfilter, store=True)) > 0


def flash_ota(
    iface: str,
    device_mac: str,
    firmware: bytes | Path | str,
    *,
    chunk: int = DEFAULT_CHUNK,
    timeout: float = 0.5,
    retries: int = 10,
    step: int | None = None,
    progress_cb=None,
) -> None:
    if chunk < 2:
        raise ValueError("chunk must be >= 2")
    if retries < 1:
        raise ValueError("retries must be >= 1")
    if timeout <= 0:
        raise ValueError("timeout must be > 0")

    dev_mac = _parse_mac(device_mac)
    if isinstance(firmware, (str, Path)):
        fw = Path(firmware).read_bytes()
    else:
        fw = bytes(firmware)

    if step is None:
        step = chunk

    conf.iface = iface
    host_mac = get_if_hwaddr(iface).lower()

    total = len(fw)
    offset = 0
    t0 = time.time()

    while offset < total:
        chunk_len = min(chunk, total - offset)
        payload, expect = _build_data_payload(fw, offset, chunk_len)
        frame = Ether(dst=dev_mac, src=host_mac, type=ETHERTYPE_HG) / payload

        ok = False
        for _ in range(retries):
            sendp(frame, iface=iface, verbose=False)
            if _wait_for_ack(iface, dev_mac, host_mac, expect, timeout):
                ok = True
                break

        if not ok:
            raise RuntimeError(f"No valid ACK for offset={offset} after {retries} retries")

        offset += step

        done = min(offset, total)
        elapsed = time.time() - t0
        speed = done / elapsed if elapsed > 0 else 0.0

        if progress_cb:
            progress_cb(done, total, speed)

