#!/usr/bin/env python3
"""
Connection test: sends 500-byte framed packets between two RNode HaLow nodes
and measures round-trip echo.

Framing (rns_stream / stream_parser.c):
  FLAG  0x7E  — frame delimiter (start and end)
  ESC   0x7D  — escape next byte XOR 0x20 (escapes 0x7E and 0x7D in payload)

  Wire format:  0x7E  <escaped-payload>  0x7E

Usage:
  python connection_test.py                          # defaults
  python connection_test.py --a-host 192.168.1.42 --b-host 192.168.1.43
  python connection_test.py --count 20 --interval 0.5
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time

# ── framing constants (stream_parser.c) ──────────────────────────────────────
FLAG = 0x7E
ESC  = 0x7D
ESC_MASK = 0x20

MAGIC  = b"CT01"
_HDR   = struct.Struct(">4sHH")   # magic(4), seq(2), payload_len(2)
PKT_SIZE = 500                     # total payload bytes (including header)


# ── framing helpers ───────────────────────────────────────────────────────────

def _escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FLAG or b == ESC:
            out.append(ESC)
            out.append(b ^ ESC_MASK)
        else:
            out.append(b)
    return bytes(out)


def _unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == ESC:
            i += 1
            if i < len(data):
                out.append(data[i] ^ ESC_MASK)
        else:
            out.append(b)
        i += 1
    return bytes(out)


def encode_frame(payload: bytes) -> bytes:
    return bytes([FLAG]) + _escape(payload) + bytes([FLAG])


def decode_frames(buf: bytearray) -> tuple[list[bytes], bytearray]:
    """Extract all complete frames from buf; return (frames, remaining)."""
    frames: list[bytes] = []
    while True:
        try:
            start = buf.index(FLAG)
        except ValueError:
            break
        try:
            end = buf.index(FLAG, start + 1)
        except ValueError:
            break
        raw = bytes(buf[start + 1 : end])
        buf = buf[end + 1 :]  # consume up to and including end FLAG
        if raw:
            frames.append(_unescape(raw))
    return frames, buf


def make_payload(seq: int) -> bytes:
    hdr = _HDR.pack(MAGIC, seq, PKT_SIZE)
    pad = PKT_SIZE - len(hdr)
    # fill with incrementing bytes so corruption is obvious
    fill = bytes(i & 0xFF for i in range(pad))
    return hdr + fill


# ── connection worker ─────────────────────────────────────────────────────────

class NodeConn:
    def __init__(self, host: str, port: int, name: str):
        self.host = host
        self.port = port
        self.name = name
        self._sock: socket.socket | None = None
        self._rx_buf: bytearray = bytearray()
        self._rx_frames: list[bytes] = []
        self._lock = threading.Lock()
        self._rx_thread: threading.Thread | None = None
        self._running = False

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=5.0)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock.settimeout(0.1)
        self._running = True
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()
        print(f"[{self.name}] connected {self.host}:{self.port}")

    def close(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def send(self, payload: bytes) -> None:
        frame = encode_frame(payload)
        if self._sock:
            self._sock.sendall(frame)

    def recv_frames(self, timeout: float = 2.0) -> list[tuple[bytes, float]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._rx_frames:
                    frames = self._rx_frames[:]
                    self._rx_frames.clear()
                    return frames
            time.sleep(0.005)
        return []

    def _rx_loop(self) -> None:
        while self._running:
            try:
                chunk = self._sock.recv(4096)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            t = time.monotonic()
            self._rx_buf.extend(chunk)
            frames, self._rx_buf = decode_frames(self._rx_buf)
            if frames:
                with self._lock:
                    self._rx_frames.extend((f, t) for f in frames)


# ── test logic ────────────────────────────────────────────────────────────────

def run_test(
    a_host: str, a_port: int,
    b_host: str, b_port: int,
    count: int, interval: float,
) -> int:
    node_a = NodeConn(a_host, a_port, "A")
    node_b = NodeConn(b_host, b_port, "B")

    try:
        node_a.connect()
    except OSError as e:
        print(f"[A] connect failed: {e}")
        return 1

    try:
        node_b.connect()
    except OSError as e:
        print(f"[B] connect failed: {e}")
        node_a.close()
        return 1

    print(f"\nSending {count} packets of {PKT_SIZE} bytes each, interval={interval}s")

    # ── A → B ─────────────────────────────────────────────────────────────────
    print(f"\nDirection: A ({a_host}:{a_port})  →  B ({b_host}:{b_port})")
    print("-" * 60)

    sent_ab = 0
    recv_ab = 0
    latencies_ab: list[float] = []

    for seq in range(1, count + 1):
        payload = make_payload(seq)
        t_send = time.monotonic()
        node_a.send(payload)
        sent_ab += 1

        frames = node_b.recv_frames(timeout=2.0)
        ok = False
        for f, t_recv in frames:
            if len(f) >= _HDR.size:
                magic, rx_seq, _ = _HDR.unpack(f[:_HDR.size])
                if magic == MAGIC and rx_seq == seq:
                    ok = True
                    recv_ab += 1
                    lat_ms = (t_recv - t_send) * 1000.0
                    latencies_ab.append(lat_ms)
                    print(f"  seq={seq:4d}  B received  len={len(f)}  lat={lat_ms:7.1f} ms")
                    break
        if not ok:
            print(f"  seq={seq:4d}  B TIMEOUT")
        time.sleep(interval)

    # ── B → A ─────────────────────────────────────────────────────────────────
    print(f"\nDirection: B ({b_host}:{b_port})  →  A ({a_host}:{a_port})")
    print("-" * 60)

    sent_ba = 0
    recv_ba = 0
    latencies_ba: list[float] = []

    for seq in range(1, count + 1):
        payload = make_payload(seq)
        t_send = time.monotonic()
        node_b.send(payload)
        sent_ba += 1

        frames = node_a.recv_frames(timeout=2.0)
        ok = False
        for f, t_recv in frames:
            if len(f) >= _HDR.size:
                magic, rx_seq, _ = _HDR.unpack(f[:_HDR.size])
                if magic == MAGIC and rx_seq == seq:
                    ok = True
                    recv_ba += 1
                    lat_ms = (t_recv - t_send) * 1000.0
                    latencies_ba.append(lat_ms)
                    print(f"  seq={seq:4d}  A received  len={len(f)}  lat={lat_ms:7.1f} ms")
                    break
        if not ok:
            print(f"  seq={seq:4d}  A TIMEOUT")
        time.sleep(interval)

    node_a.close()
    node_b.close()

    # ── summary ───────────────────────────────────────────────────────────────
    def stats(lats: list[float], sent: int, recv: int) -> str:
        lost = sent - recv
        s = f"sent={sent} recv={recv} lost={lost}"
        if lats:
            s += f"  avg={sum(lats)/len(lats):.1f} min={min(lats):.1f} max={max(lats):.1f} ms"
        return s

    print(f"\n  A→B: {stats(latencies_ab, sent_ab, recv_ab)}")
    print(f"  B→A: {stats(latencies_ba, sent_ba, recv_ba)}")

    total_lost = (sent_ab - recv_ab) + (sent_ba - recv_ba)
    return 0 if total_lost == 0 else 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="RNode HaLow TCP connection test (rns_stream framing)")
    ap.add_argument("--a-host",   default="192.168.1.42")
    ap.add_argument("--a-port",   type=int, default=4242)
    ap.add_argument("--b-host",   default="192.168.1.43")
    ap.add_argument("--b-port",   type=int, default=4242)
    ap.add_argument("--count",    type=int, default=10,  help="packets per direction (default: 10)")
    ap.add_argument("--interval", type=float, default=0.2, help="seconds between packets (default: 0.2)")
    args = ap.parse_args()

    return run_test(
        a_host=args.a_host, a_port=args.a_port,
        b_host=args.b_host, b_port=args.b_port,
        count=args.count,
        interval=args.interval,
    )


if __name__ == "__main__":
    raise SystemExit(main())
