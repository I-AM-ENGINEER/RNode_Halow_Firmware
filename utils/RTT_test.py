#!/usr/bin/env python3
from __future__ import annotations

import argparse
import queue
import signal
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import kiss  # pip install pyham_kiss  (PyHam KISS)

MAGIC_REQ = b"RTT0"   # request
MAGIC_RSP = b"RTT1"   # response

# wire format:
#  4s magic
#  I  seq
#  Q  t0_ns (sender timestamp)
#  ... padding bytes (optional)
_HDR = struct.Struct(">4sIQ")


def _now_ns() -> int:
    return time.monotonic_ns()


def _percentile_sorted(xs_sorted: List[float], p: float) -> float:
    if not xs_sorted:
        return 0.0
    if p <= 0:
        return xs_sorted[0]
    if p >= 100:
        return xs_sorted[-1]
    k = (len(xs_sorted) - 1) * (p / 100.0)
    i = int(k)
    frac = k - i
    if i + 1 >= len(xs_sorted):
        return xs_sorted[i]
    return xs_sorted[i] * (1.0 - frac) + xs_sorted[i + 1] * frac


@dataclass
class Stats:
    sent: int = 0
    recv: int = 0
    echoed: int = 0
    bad: int = 0
    timeouts: int = 0

    rtts_ms: List[float] = None

    def __post_init__(self):
        if self.rtts_ms is None:
            self.rtts_ms = []


class RTTRunner:
    def __init__(self, a_host: str, a_port: int, b_host: str, b_port: int,
                 rate: float, count: int, size: int, timeout_s: float, kiss_port: int):
        self.a_host = a_host
        self.a_port = a_port
        self.b_host = b_host
        self.b_port = b_port
        self.rate = rate
        self.count = count
        self.size = max(size, _HDR.size)
        self.timeout_s = timeout_s
        self.kiss_port = kiss_port

        self._stop = threading.Event()

        self._a_rxq: "queue.Queue[bytes]" = queue.Queue()
        self._b_rxq: "queue.Queue[bytes]" = queue.Queue()

        self._a = kiss.Connection(self._a_rx_cb)
        self._b = kiss.Connection(self._b_rx_cb)

        self._pending: Dict[int, int] = {}  # seq -> t_send_ns
        self._pending_lock = threading.Lock()

        self.stats = Stats()

    def _a_rx_cb(self, kport: int, data: bytearray):
        # data is raw payload (already KISS-decoded)
        self._a_rxq.put(bytes(data))

    def _b_rx_cb(self, kport: int, data: bytearray):
        self._b_rxq.put(bytes(data))

    def connect(self):
        self._a.connect_to_server(self.a_host, int(self.a_port))
        self._b.connect_to_server(self.b_host, int(self.b_port))

    def close(self):
        try:
            self._a.disconnect_from_server()
        except Exception:
            pass
        try:
            self._b.disconnect_from_server()
        except Exception:
            pass

    def stop(self):
        self._stop.set()

    def _mk_frame(self, magic: bytes, seq: int, t0_ns: int) -> bytes:
        base = _HDR.pack(magic, seq, t0_ns)
        if len(base) < self.size:
            base += b"\x00" * (self.size - len(base))
        return base

    def _parse(self, payload: bytes):
        if len(payload) < _HDR.size:
            return None
        magic, seq, t0_ns = _HDR.unpack(payload[:_HDR.size])
        return magic, seq, t0_ns

    def _thread_b_echo(self):
        # B side: on request, immediately respond from B -> A with same seq
        while not self._stop.is_set():
            try:
                p = self._b_rxq.get(timeout=0.2)
            except queue.Empty:
                continue

            parsed = self._parse(p)
            if not parsed:
                self.stats.bad += 1
                continue

            magic, seq, t0_ns = parsed
            if magic != MAGIC_REQ:
                # ignore чужие пакеты
                continue

            rsp = self._mk_frame(MAGIC_RSP, seq, t0_ns)
            try:
                self._b.send_data(rsp, port=self.kiss_port)
                self.stats.echoed += 1
            except Exception:
                self.stats.bad += 1

    def _thread_a_rx(self):
        # A side: accept responses, compute RTT
        while not self._stop.is_set():
            try:
                p = self._a_rxq.get(timeout=0.2)
            except queue.Empty:
                continue

            parsed = self._parse(p)
            if not parsed:
                self.stats.bad += 1
                continue

            magic, seq, _t0_ns = parsed
            if magic != MAGIC_RSP:
                continue

            t1_ns = _now_ns()
            with self._pending_lock:
                t0 = self._pending.pop(seq, None)

            if t0 is None:
                # ответ на неизвестный/просроченный seq
                self.stats.bad += 1
                continue

            rtt_ms = (t1_ns - t0) / 1e6
            self.stats.rtts_ms.append(rtt_ms)
            self.stats.recv += 1

    def _thread_a_send(self):
        period = 1.0 / self.rate if self.rate > 0 else 0.0
        next_t = time.monotonic()

        for seq in range(1, self.count + 1):
            if self._stop.is_set():
                break

            now = time.monotonic()
            if now < next_t:
                time.sleep(next_t - now)
            next_t += period

            t0 = _now_ns()
            frame = self._mk_frame(MAGIC_REQ, seq, t0)

            with self._pending_lock:
                self._pending[seq] = t0

            try:
                self._a.send_data(frame, port=self.kiss_port)
                self.stats.sent += 1
            except Exception:
                self.stats.bad += 1
                with self._pending_lock:
                    self._pending.pop(seq, None)

        # wait for late responses up to timeout
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline and not self._stop.is_set():
            with self._pending_lock:
                if not self._pending:
                    break
            time.sleep(0.05)

        # mark remaining as timeouts
        with self._pending_lock:
            self.stats.timeouts += len(self._pending)
            self._pending.clear()

        self._stop.set()

    def _thread_report(self):
        last_sent = last_recv = last_time = None

        while not self._stop.is_set():
            time.sleep(1.0)

            sent = self.stats.sent
            recv = self.stats.recv
            bad = self.stats.bad
            echoed = self.stats.echoed
            to = self.stats.timeouts

            rtts = self.stats.rtts_ms
            rtts_sorted = sorted(rtts)
            avg = (sum(rtts) / len(rtts)) if rtts else 0.0
            p50 = _percentile_sorted(rtts_sorted, 50.0)
            p95 = _percentile_sorted(rtts_sorted, 95.0)
            mn = rtts_sorted[0] if rtts_sorted else 0.0
            mx = rtts_sorted[-1] if rtts_sorted else 0.0

            loss = 0.0
            if sent > 0:
                loss = (sent - recv) * 100.0 / sent

            # simple rate estimate (optional)
            if last_time is None:
                last_time = time.monotonic()
                last_sent, last_recv = sent, recv
                rate_s = rate_r = 0.0
            else:
                now = time.monotonic()
                dt = max(now - last_time, 1e-9)
                rate_s = (sent - last_sent) / dt
                rate_r = (recv - last_recv) / dt
                last_time = now
                last_sent, last_recv = sent, recv

            print(
                f"A→B→A sent={sent} recv={recv} loss={loss:6.2f}% "
                f"rtt_ms avg={avg:7.3f} p50={p50:7.3f} p95={p95:7.3f} min={mn:7.3f} max={mx:7.3f} "
                f"echoed={echoed} timeouts={to} bad={bad} "
                f"| rate tx={rate_s:6.1f}/s rx={rate_r:6.1f}/s"
            )

    def run(self) -> int:
        self.connect()

        th_echo = threading.Thread(target=self._thread_b_echo, daemon=True)
        th_rx = threading.Thread(target=self._thread_a_rx, daemon=True)
        th_tx = threading.Thread(target=self._thread_a_send, daemon=True)
        th_rep = threading.Thread(target=self._thread_report, daemon=True)

        th_echo.start()
        th_rx.start()
        th_rep.start()
        th_tx.start()

        while not self._stop.is_set():
            time.sleep(0.1)

        self.close()

        # final summary
        sent = self.stats.sent
        recv = self.stats.recv
        loss = (sent - recv) * 100.0 / sent if sent else 0.0
        rtts = self.stats.rtts_ms
        rtts_sorted = sorted(rtts)
        avg = (sum(rtts) / len(rtts)) if rtts else 0.0
        p50 = _percentile_sorted(rtts_sorted, 50.0)
        p95 = _percentile_sorted(rtts_sorted, 95.0)

        print("\n--- final ---")
        print(f"sent={sent} recv={recv} loss={loss:.2f}% timeouts={self.stats.timeouts} bad={self.stats.bad}")
        print(f"rtt_ms avg={avg:.3f} p50={p50:.3f} p95={p95:.3f}")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="KISS RTT tester (A->B echo->A), port 0 data frames")
    ap.add_argument("--a-host", required=True)
    ap.add_argument("--a-port", required=True, type=int)
    ap.add_argument("--b-host", required=True)
    ap.add_argument("--b-port", required=True, type=int)

    ap.add_argument("--rate", type=float, default=100.0, help="packets per second (default: 100)")
    ap.add_argument("--count", type=int, default=2000, help="how many requests to send (default: 2000)")
    ap.add_argument("--size", type=int, default=64, help="payload size in bytes incl header (default: 64)")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for late replies (default: 2.0)")
    ap.add_argument("--kiss-port", type=int, default=0, help="KISS TNC port number (default: 0)")

    args = ap.parse_args()

    runner = RTTRunner(
        a_host=args.a_host, a_port=args.a_port,
        b_host=args.b_host, b_port=args.b_port,
        rate=args.rate, count=args.count,
        size=args.size, timeout_s=args.timeout,
        kiss_port=args.kiss_port,
    )

    def _sig(_signo, _frame):
        runner.stop()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
