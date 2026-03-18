import socket
import time
import argparse
import threading
from pathlib import Path


PATTERN_TAG = b"RHALOW_PACKET_"


def set_keepalive_5s(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 5000))


def make_ascii_packet(size: int, counter: int) -> bytes:
    header = f"RHALOW_PACKET_{counter:08d}_".encode()
    buf = bytearray()

    while len(buf) < size:
        buf.extend(header)

    return bytes(buf[:size])


def sender_loop(sock: socket.socket,
                stop_evt: threading.Event,
                payload: bytes | None,
                chunk: int,
                tx_stats: dict) -> None:
    packet_counter = 0

    while not stop_evt.is_set():
        if payload is None:
            pkt = make_ascii_packet(chunk, packet_counter)
        else:
            pkt = payload

        packet_counter += 1
        view = memoryview(pkt)

        while len(view) > 0 and not stop_evt.is_set():
            try:
                n = sock.send(view)
            except (BrokenPipeError, ConnectionResetError, OSError):
                stop_evt.set()
                break

            if n <= 0:
                stop_evt.set()
                break

            tx_stats["bytes"] += n
            view = view[n:]


def receiver_loop(sock: socket.socket,
                  stop_evt: threading.Event,
                  rx_stats: dict) -> None:
    while not stop_evt.is_set():
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        except (ConnectionResetError, OSError):
            stop_evt.set()
            break

        if not data:
            stop_evt.set()
            break

        rx_stats["bytes"] += len(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("--chunk", type=int, default=500, help="Packet size for generated data")
    parser.add_argument("--file", type=Path, help="Optional payload file")
    parser.add_argument("--recv", action="store_true", default=True,
                        help="Drain echoed/response data from server (default: enabled)")
    parser.add_argument("--no-recv", dest="recv", action="store_false",
                        help="Do not read from socket")
    parser.add_argument("--sndbuf", type=int, default=256 * 1024, help="SO_SNDBUF")
    parser.add_argument("--rcvbuf", type=int, default=256 * 1024, help="SO_RCVBUF")
    args = parser.parse_args()

    payload = None
    if args.file is not None:
        if not args.file.exists():
            raise FileNotFoundError(args.file)

        payload = args.file.read_bytes()
        if not payload:
            raise ValueError("File empty")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, args.sndbuf)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    set_keepalive_5s(sock)
    sock.settimeout(0.5)
    sock.connect((args.ip, args.port))
    sock.settimeout(0.5)

    stop_evt = threading.Event()
    tx_stats = {"bytes": 0}
    rx_stats = {"bytes": 0}

    tx_thr = threading.Thread(target=sender_loop, args=(sock, stop_evt, payload, args.chunk, tx_stats), daemon=True)
    tx_thr.start()

    rx_thr = None
    if args.recv:
        rx_thr = threading.Thread(target=receiver_loop, args=(sock, stop_evt, rx_stats), daemon=True)
        rx_thr.start()

    last_tx = 0
    last_rx = 0
    last_time = time.monotonic()

    try:
        while not stop_evt.is_set():
            time.sleep(1.0)

            now = time.monotonic()
            dt = now - last_time
            if dt <= 0:
                continue

            tx = tx_stats["bytes"]
            rx = rx_stats["bytes"]

            tx_speed = (tx - last_tx) / dt
            rx_speed = (rx - last_rx) / dt

            print(
                f"TX {tx_speed / 1024 / 1024:8.2f} MiB/s  "
                f"{tx_speed * 8 / 1_000_000:8.2f} Mbit/s  "
                f"total={tx / 1024 / 1024:10.2f} MiB"
            )

            if args.recv:
                print(
                    f"RX {rx_speed / 1024 / 1024:8.2f} MiB/s  "
                    f"{rx_speed * 8 / 1_000_000:8.2f} Mbit/s  "
                    f"total={rx / 1024 / 1024:10.2f} MiB"
                )

            last_time = now
            last_tx = tx
            last_rx = rx

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        stop_evt.set()

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        sock.close()

        tx_thr.join(timeout=1.0)
        if rx_thr is not None:
            rx_thr.join(timeout=1.0)


if __name__ == "__main__":
    main()
