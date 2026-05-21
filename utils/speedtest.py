#!/usr/bin/env python3
"""
Throughput test using rns_stream framing (FLAG=0x7E / ESC=0x7D).

Sends as fast as possible (saturate) or at a fixed bitrate.
Tests A→B then B→A sequentially, or both simultaneously (--bidir).

Example
-------
  python speedtest.py                                   # defaults, saturate
  python speedtest.py --pkt-size 1000 --duration 10
  python speedtest.py --bidir
  python speedtest.py --bitrate 500000 --duration 15
"""
from __future__ import annotations

import argparse
import select
import signal
import socket
import struct
import threading
import time

FLAG = 0x7E
ESC  = 0x7D

MAGIC = b"SPD1"
_HDR  = struct.Struct(">4sII")   # magic(4), stream_id(4), seq(4)
HDR_SIZE = _HDR.size             # 12 bytes


def _escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FLAG or b == ESC:
            out.append(ESC)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def _unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == ESC and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


def encode_frame(payload: bytes) -> bytes:
    return bytes([FLAG]) + _escape(payload) + bytes([FLAG])


def decode_frames(buf: bytearray) -> tuple[list[bytes], bytearray]:
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
        raw = bytes(buf[start + 1:end])
        buf = buf[end + 1:]
        if raw:
            frames.append(_unescape(raw))
    return frames, buf


class NodeConn:
    def __init__(self, host: str, port: int, name: str):
        self.name = name
        self._host = host
        self._port = port
        self._sock: socket.socket | None = None
        self._rx_buf = bytearray()
        self._rx_bytes = 0
        self._rx_pkts = 0
        self._last_seq: dict[int, int] = {}   # stream_id → last seq
        self._lost: dict[int, int] = {}
        self._lock = threading.Lock()
        self._running = False

    def connect(self) -> None:
        self._sock = socket.create_connection((self._host, self._port), timeout=5.0)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock.settimeout(None)          # blocking — sendall() must not time out
        self._running = True
        threading.Thread(target=self._rx_loop, daemon=True, name=f"rx-{self.name}").start()

    def close(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def send(self, payload: bytes) -> None:
        if self._sock:
            self._sock.sendall(encode_frame(payload))

    def rx_stats(self, stream_id: int) -> tuple[int, int, int]:
        """Return (pkts, bytes, lost) for a given stream_id."""
        with self._lock:
            return self._rx_pkts, self._rx_bytes, self._lost.get(stream_id, 0)

    def reset_rx(self) -> None:
        with self._lock:
            self._rx_bytes = 0
            self._rx_pkts = 0
            self._last_seq.clear()
            self._lost.clear()

    def _rx_loop(self) -> None:
        while self._running:
            readable, _, _ = select.select([self._sock], [], [], 0.1)
            if not readable:
                continue
            try:
                chunk = self._sock.recv(65536)  # type: ignore[union-attr]
            except OSError:
                break
            if not chunk:
                break
            self._rx_buf.extend(chunk)
            frames, self._rx_buf = decode_frames(self._rx_buf)
            for f in frames:
                if len(f) < HDR_SIZE:
                    continue
                magic, sid, seq = _HDR.unpack(f[:HDR_SIZE])
                if magic != MAGIC:
                    continue
                with self._lock:
                    self._rx_pkts += 1
                    self._rx_bytes += len(f)
                    prev = self._last_seq.get(sid, seq - 1)
                    if seq > prev + 1:
                        self._lost[sid] = self._lost.get(sid, 0) + (seq - prev - 1)
                    if seq > prev:
                        self._last_seq[sid] = seq


def _make_payload(stream_id: int, seq: int, pkt_size: int) -> bytes:
    hdr = _HDR.pack(MAGIC, stream_id, seq)
    pad = max(0, pkt_size - len(hdr))
    return hdr + b"\x00" * pad


class OneWayTest:
    def __init__(self, sender: NodeConn, receiver: NodeConn,
                 name: str, stream_id: int,
                 pkt_size: int, duration_s: float, bitrate_bps: int):
        self.sender = sender
        self.receiver = receiver
        self.name = name
        self.stream_id = stream_id
        self.pkt_size = max(pkt_size, HDR_SIZE)
        self.duration_s = duration_s
        self.bitrate_bps = bitrate_bps  # 0 = saturate

        self._stop = threading.Event()
        self._sent_pkts = 0
        self._sent_bytes = 0

    def stop(self) -> None:
        self._stop.set()

    def _tx_loop(self) -> None:
        t_end = time.monotonic() + self.duration_s
        seq = 0

        if self.bitrate_bps == 0:
            while not self._stop.is_set() and time.monotonic() < t_end:
                seq += 1
                payload = _make_payload(self.stream_id, seq, self.pkt_size)
                try:
                    self.sender.send(payload)
                    self._sent_pkts += 1
                    self._sent_bytes += len(payload)
                except OSError:
                    break
        else:
            period = (self.pkt_size * 8) / self.bitrate_bps
            next_t = time.monotonic()
            while not self._stop.is_set() and time.monotonic() < t_end:
                now = time.monotonic()
                if now < next_t:
                    time.sleep(next_t - now)
                next_t += period
                seq += 1
                payload = _make_payload(self.stream_id, seq, self.pkt_size)
                try:
                    self.sender.send(payload)
                    self._sent_pkts += 1
                    self._sent_bytes += len(payload)
                except OSError:
                    break

        self._stop.set()

    def _report_loop(self) -> None:
        last_tx_b = 0
        last_rx_b = 0
        t0 = time.monotonic()
        while not self._stop.is_set():
            time.sleep(1.0)
            t1 = time.monotonic()
            dt = max(t1 - t0, 1e-9)
            t0 = t1

            tx_b = self._sent_bytes
            _, rx_b, lost = self.receiver.rx_stats(self.stream_id)

            tx_kbps = (tx_b - last_tx_b) * 8 / dt / 1e3
            rx_kbps = (rx_b - last_rx_b) * 8 / dt / 1e3
            last_tx_b, last_rx_b = tx_b, rx_b

            rx_pkts, _, _ = self.receiver.rx_stats(self.stream_id)
            total = rx_pkts + lost
            loss = lost * 100.0 / total if total else 0.0

            print(f"[{self.name}]  tx={tx_kbps:8.1f} kbps  rx={rx_kbps:8.1f} kbps  "
                  f"sent={self._sent_pkts}  recv={rx_pkts}  loss≈{loss:.1f}%")

    def run(self) -> dict:
        self.receiver.reset_rx()
        t_start = time.monotonic()

        threading.Thread(target=self._tx_loop, daemon=True).start()
        threading.Thread(target=self._report_loop, daemon=True).start()

        while not self._stop.is_set():
            time.sleep(0.05)

        time.sleep(0.5)  # drain in-flight

        dur = time.monotonic() - t_start
        rx_pkts, rx_bytes, lost = self.receiver.rx_stats(self.stream_id)
        total = rx_pkts + lost
        loss_pct = lost * 100.0 / total if total else 0.0

        return {
            "name": self.name,
            "tx_kbps": self._sent_bytes * 8 / dur / 1e3,
            "rx_kbps": rx_bytes * 8 / dur / 1e3,
            "sent": self._sent_pkts,
            "recv": rx_pkts,
            "lost": lost,
            "loss_pct": loss_pct,
        }


_global_stop = threading.Event()


def _sighandler(_sig, _frame):
    print("\nInterrupted.")
    _global_stop.set()


def main() -> int:
    signal.signal(signal.SIGINT,  _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    ap = argparse.ArgumentParser(
        description="rns_stream throughput test",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--a-host",   default="192.168.1.42")
    ap.add_argument("--a-port",   type=int, default=4242)
    ap.add_argument("--b-host",   default="192.168.1.43")
    ap.add_argument("--b-port",   type=int, default=4242)
    ap.add_argument("--pkt-size", type=int, default=1000,  help="payload bytes per packet")
    ap.add_argument("--duration", type=float, default=10.0, help="seconds per direction")
    ap.add_argument("--bitrate",  type=int, default=0,     help="bps limit (0 = saturate)")
    ap.add_argument("--gap",      type=float, default=1.0, help="pause between directions (s)")
    ap.add_argument("--bidir",    action="store_true",     help="run both directions simultaneously")
    args = ap.parse_args()

    a = NodeConn(args.a_host, args.a_port, "A")
    b = NodeConn(args.b_host, args.b_port, "B")

    try:
        a.connect()
        print(f"[A] connected {args.a_host}:{args.a_port}")
    except OSError as e:
        print(f"[A] connect failed: {e}")
        return 1
    try:
        b.connect()
        print(f"[B] connected {args.b_host}:{args.b_port}")
    except OSError as e:
        print(f"[B] connect failed: {e}")
        a.close()
        return 1

    mode = "saturate" if args.bitrate == 0 else f"{args.bitrate/1e3:.0f} kbps"
    print(f"pkt_size={args.pkt_size} B  duration={args.duration}s  bitrate={mode}  bidir={args.bidir}\n")

    results = []

    def make(name, stream_id, sender, receiver):
        t = OneWayTest(sender, receiver, name, stream_id,
                       args.pkt_size, args.duration, args.bitrate)
        return t

    if args.bidir:
        print("=== Bidirectional (simultaneous) ===")
        t_ab = make("A→B", 1, a, b)
        t_ba = make("B→A", 2, b, a)
        th_ab = threading.Thread(target=lambda: results.append(t_ab.run()), daemon=True)
        th_ba = threading.Thread(target=lambda: results.append(t_ba.run()), daemon=True)
        th_ab.start(); th_ba.start()
        while (th_ab.is_alive() or th_ba.is_alive()) and not _global_stop.is_set():
            time.sleep(0.1)
        t_ab.stop(); t_ba.stop()
        th_ab.join(); th_ba.join()
    else:
        print("=== A → B ===")
        t_ab = make("A→B", 1, a, b)
        th = threading.Thread(target=lambda: results.append(t_ab.run()), daemon=True)
        th.start()
        while th.is_alive() and not _global_stop.is_set():
            time.sleep(0.1)
        t_ab.stop(); th.join()

        if not _global_stop.is_set():
            time.sleep(args.gap)
            print("\n=== B → A ===")
            t_ba = make("B→A", 2, b, a)
            th = threading.Thread(target=lambda: results.append(t_ba.run()), daemon=True)
            th.start()
            while th.is_alive() and not _global_stop.is_set():
                time.sleep(0.1)
            t_ba.stop(); th.join()

    a.close()
    b.close()

    print("\n--- summary ---")
    for r in results:
        print(f"{r['name']}:  tx={r['tx_kbps']:.1f} kbps  rx={r['rx_kbps']:.1f} kbps  "
              f"sent={r['sent']}  recv={r['recv']}  lost={r['lost']}  loss≈{r['loss_pct']:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
