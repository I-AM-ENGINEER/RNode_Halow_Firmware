#!/usr/bin/env python3
from __future__ import annotations

import argparse
import queue
import signal
import struct
import threading
import time
from dataclasses import dataclass

import kiss  # pip install pyham_kiss

MAGIC = b"SPD1"
_HDR = struct.Struct(">4sIIQ")  # magic, stream_id, seq, t0_ns


def _now_ns() -> int:
    return time.monotonic_ns()


@dataclass
class OneWayStats:
    sent_pkts: int = 0
    sent_bytes: int = 0
    recv_pkts: int = 0
    recv_bytes: int = 0
    lost_gap: int = 0
    bad: int = 0
    last_seq: int = 0


class OneWaySpeed:
    def __init__(self, sender: kiss.Connection, receiver: kiss.Connection,
                 sender_rxq: "queue.Queue[bytes]", receiver_rxq: "queue.Queue[bytes]",
                 direction_name: str,
                 stream_id: int,
                 bitrate_bps: int, pkt_size: int, duration_s: float, kiss_port: int):
        self.sender = sender
        self.receiver = receiver
        self.sender_rxq = sender_rxq
        self.receiver_rxq = receiver_rxq

        self.direction_name = direction_name
        self.stream_id = int(stream_id)
        self.bitrate_bps = int(bitrate_bps)
        self.pkt_size = max(int(pkt_size), _HDR.size)
        self.duration_s = float(duration_s)
        self.kiss_port = int(kiss_port)

        self.stats = OneWayStats()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _mk_frame(self, seq: int) -> bytes:
        t0 = _now_ns()
        p = _HDR.pack(MAGIC, self.stream_id, seq, t0)
        if len(p) < self.pkt_size:
            p += b"\x00" * (self.pkt_size - len(p))
        return p

    def _parse(self, p: bytes):
        if len(p) < _HDR.size:
            return None
        magic, stream_id, seq, _t0 = _HDR.unpack(p[:_HDR.size])
        if magic != MAGIC or stream_id != self.stream_id:
            return None
        return seq

    def _rx_worker(self) -> None:
        # receiver consumes its rxq and counts only our stream_id
        while not self._stop.is_set():
            try:
                p = self.receiver_rxq.get(timeout=0.2)
            except queue.Empty:
                continue

            seq = self._parse(p)
            if seq is None:
                self.stats.bad += 1
                continue

            self.stats.recv_pkts += 1
            self.stats.recv_bytes += len(p)

            if self.stats.last_seq == 0:
                self.stats.last_seq = seq
            else:
                if seq > self.stats.last_seq + 1:
                    self.stats.lost_gap += (seq - self.stats.last_seq - 1)
                if seq > self.stats.last_seq:
                    self.stats.last_seq = seq

    def _tx_worker(self) -> None:
        bits_per_pkt = self.pkt_size * 8
        pps = self.bitrate_bps / bits_per_pkt if bits_per_pkt > 0 else 0.0
        if pps <= 0.0:
            self._stop.set()
            return

        period = 1.0 / pps
        t_end = time.monotonic() + self.duration_s
        next_t = time.monotonic()

        seq = 0
        while not self._stop.is_set() and time.monotonic() < t_end:
            now = time.monotonic()
            if now < next_t:
                time.sleep(next_t - now)
            next_t += period

            seq += 1
            frame = self._mk_frame(seq)
            try:
                self.sender.send_data(frame, port=self.kiss_port)
                self.stats.sent_pkts += 1
                self.stats.sent_bytes += len(frame)
            except Exception:
                # ignore send errors, just don't count
                pass

        self._stop.set()

    def _reporter(self) -> None:
        last_sent_b = 0
        last_recv_b = 0
        t0 = time.monotonic()

        while not self._stop.is_set():
            time.sleep(1.0)
            t1 = time.monotonic()
            dt = max(t1 - t0, 1e-9)
            t0 = t1

            sent_b = self.stats.sent_bytes
            recv_b = self.stats.recv_bytes

            tx_mbps = (sent_b - last_sent_b) * 8.0 / dt / 1e6
            rx_mbps = (recv_b - last_recv_b) * 8.0 / dt / 1e6

            last_sent_b, last_recv_b = sent_b, recv_b

            est_total = self.stats.recv_pkts + self.stats.lost_gap
            loss = (self.stats.lost_gap * 100.0 / est_total) if est_total else 0.0

            print(
                f"{self.direction_name}  tx={tx_mbps:6.2f} Mb/s rx={rx_mbps:6.2f} Mb/s "
                f"sent={self.stats.sent_pkts} recv={self.stats.recv_pkts} loss≈{loss:5.2f}% bad={self.stats.bad}"
            )

    def run(self) -> OneWayStats:
        th_rx = threading.Thread(target=self._rx_worker, daemon=True)
        th_tx = threading.Thread(target=self._tx_worker, daemon=True)
        th_rp = threading.Thread(target=self._reporter, daemon=True)

        # flush old frames in receiver queue to reduce cross-talk
        try:
            while True:
                self.receiver_rxq.get_nowait()
        except queue.Empty:
            pass

        th_rx.start()
        th_rp.start()
        th_tx.start()

        while not self._stop.is_set():
            time.sleep(0.05)

        # small tail for last packets in buffers
        time.sleep(0.2)
        self._stop.set()
        return self.stats


class SpeedTest:
    def __init__(self, a_host: str, a_port: int, b_host: str, b_port: int,
                 bitrate_bps: int, pkt_size: int, duration_s: float, kiss_port: int,
                 gap_s: float):
        self.a_host = a_host
        self.a_port = a_port
        self.b_host = b_host
        self.b_port = b_port
        self.bitrate_bps = int(bitrate_bps)
        self.pkt_size = int(pkt_size)
        self.duration_s = float(duration_s)
        self.kiss_port = int(kiss_port)
        self.gap_s = float(gap_s)

        self._stop = threading.Event()

        self._a_rxq: "queue.Queue[bytes]" = queue.Queue()
        self._b_rxq: "queue.Queue[bytes]" = queue.Queue()

        self._a = kiss.Connection(self._a_rx_cb)
        self._b = kiss.Connection(self._b_rx_cb)

    def _a_rx_cb(self, kport: int, data: bytearray) -> None:
        self._a_rxq.put(bytes(data))

    def _b_rx_cb(self, kport: int, data: bytearray) -> None:
        self._b_rxq.put(bytes(data))

    def stop(self) -> None:
        self._stop.set()

    def connect(self) -> None:
        self._a.connect_to_server(self.a_host, int(self.a_port))
        self._b.connect_to_server(self.b_host, int(self.b_port))

    def close(self) -> None:
        try:
            self._a.disconnect_from_server()
        except Exception:
            pass
        try:
            self._b.disconnect_from_server()
        except Exception:
            pass

    def run(self) -> int:
        self.connect()

        # Direction 1: A -> B (stream_id=1)
        print("\n=== Direction 1: A → B ===")
        ow1 = OneWaySpeed(
            sender=self._a, receiver=self._b,
            sender_rxq=self._a_rxq, receiver_rxq=self._b_rxq,
            direction_name="A→B",
            stream_id=1,
            bitrate_bps=self.bitrate_bps,
            pkt_size=self.pkt_size,
            duration_s=self.duration_s,
            kiss_port=self.kiss_port,
        )
        st1 = ow1.run()

        if self._stop.is_set():
            self.close()
            return 0

        if self.gap_s > 0:
            time.sleep(self.gap_s)

        # Direction 2: B -> A (stream_id=2)
        print("\n=== Direction 2: B → A ===")
        ow2 = OneWaySpeed(
            sender=self._b, receiver=self._a,
            sender_rxq=self._b_rxq, receiver_rxq=self._a_rxq,
            direction_name="B→A",
            stream_id=2,
            bitrate_bps=self.bitrate_bps,
            pkt_size=self.pkt_size,
            duration_s=self.duration_s,
            kiss_port=self.kiss_port,
        )
        st2 = ow2.run()

        self.close()

        def _summary(name: str, st: OneWayStats) -> str:
            dur = self.duration_s
            tx_mbps = (st.sent_bytes * 8.0) / max(dur, 1e-9) / 1e6
            rx_mbps = (st.recv_bytes * 8.0) / max(dur, 1e-9) / 1e6
            est_total = st.recv_pkts + st.lost_gap
            loss = (st.lost_gap * 100.0 / est_total) if est_total else 0.0
            return (
                f"{name}: tx={tx_mbps:.3f} Mb/s rx={rx_mbps:.3f} Mb/s "
                f"sent={st.sent_pkts} recv={st.recv_pkts} lost_gap={st.lost_gap} loss≈{loss:.2f}% bad={st.bad}"
            )

        print("\n--- final ---")
        print(_summary("A→B", st1))
        print(_summary("B→A", st2))
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="KISS speedtest one-way then reverse, port 0 data frames")
    ap.add_argument("--a-host", required=True)
    ap.add_argument("--a-port", required=True, type=int)
    ap.add_argument("--b-host", required=True)
    ap.add_argument("--b-port", required=True, type=int)

    ap.add_argument("--bitrate", required=True, type=int, help="target bitrate in bps (per direction)")
    ap.add_argument("--pkt-size", type=int, default=200, help="payload size in bytes (default: 200)")
    ap.add_argument("--duration", type=float, default=10.0, help="seconds per direction (default: 10)")
    ap.add_argument("--kiss-port", type=int, default=0, help="KISS TNC port (default: 0)")
    ap.add_argument("--gap", type=float, default=0.5, help="pause between directions in seconds (default: 0.5)")

    args = ap.parse_args()

    st = SpeedTest(
        a_host=args.a_host, a_port=args.a_port,
        b_host=args.b_host, b_port=args.b_port,
        bitrate_bps=args.bitrate,
        pkt_size=args.pkt_size,
        duration_s=args.duration,
        kiss_port=args.kiss_port,
        gap_s=args.gap,
    )

    def _sig(_signo, _frame):
        st.stop()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    return st.run()


if __name__ == "__main__":
    raise SystemExit(main())
