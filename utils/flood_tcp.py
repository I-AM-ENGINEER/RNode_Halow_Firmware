import socket
import time
import argparse
from pathlib import Path


def set_keepalive_5s(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Windows: тонкая настройка keepalive (idle, interval) в мс
    # count на Windows не задаётся так же прямо, но обычно ок.
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 5000))


def send_all(sock: socket.socket, data: bytes) -> int:
    view = memoryview(data)
    total = 0
    while total < len(view):
        n = sock.send(view[total:])
        if n <= 0:
            raise ConnectionError("send returned 0")
        total += n
    return total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("port", type=int, help="Target port")
    parser.add_argument("--chunk", type=int, default=1500, help="Chunk size per send")
    parser.add_argument("--file", type=Path, help="Optional file to use as payload (looped)")
    args = parser.parse_args()

    if args.file:
        if not args.file.exists():
            raise FileNotFoundError(args.file)
        payload = args.file.read_bytes()
        if not payload:
            raise ValueError("File is empty")
    else:
        payload = b"\x55" * args.chunk

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    set_keepalive_5s(sock)

    sock.connect((args.ip, args.port))

    total_bytes = 0
    last_bytes = 0
    last_time = time.time()

    try:
        while True:
            total_bytes += send_all(sock, payload)

            now = time.time()
            if now - last_time >= 1.0:
                delta_bytes = total_bytes - last_bytes
                speed = delta_bytes / (now - last_time)

                print(
                    f"{speed / 1024 / 1024:8.2f} MiB/s  "
                    f"{speed * 8 / 1_000_000:8.2f} Mbit/s  "
                    f"total={total_bytes / 1024 / 1024:10.2f} MiB"
                )

                last_time = now
                last_bytes = total_bytes

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
