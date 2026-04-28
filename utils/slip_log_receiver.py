#!/usr/bin/env python3
"""SLIP UDP Log Receiver - displays logs from COM port"""

import serial
import serial.tools.list_ports
import threading
import sys
import os
from struct import unpack
import argparse

try:
    from colorama import init
    init(autoreset=False)
except ImportError:
    pass

# SLIP protocol
SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD


class SLIPDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.in_frame = False

    def decode(self, byte):
        if byte == SLIP_END:
            if self.in_frame and len(self.buffer) > 0:
                frame = bytes(self.buffer)
                self.buffer.clear()
                self.in_frame = False
                return frame
            self.in_frame = True
            return None

        if byte == SLIP_ESC:
            self.esc_next = True
            return None

        if hasattr(self, 'esc_next') and self.esc_next:
            if byte == SLIP_ESC_END:
                self.buffer.append(SLIP_END)
            elif byte == SLIP_ESC_ESC:
                self.buffer.append(SLIP_ESC)
            self.esc_next = False
            return None

        if self.in_frame:
            self.buffer.append(byte)
        return None


class LogReceiver:
    def __init__(self, port='COM16', baudrate=2000000):
        self.port = port
        self.baudrate = baudrate
        self.running = True
        self.decoder = SLIPDecoder()
        self.serial_port = None

    def start(self):
        try:
            self.serial_port = serial.Serial(port=self.port, baudrate=self.baudrate, timeout=1)
            print(f"[*] Connected to {self.port} at {self.baudrate} baud")
        except Exception as e:
            print(f"[!] Failed to open {self.port}: {e}", file=sys.stderr)
            self.running = False
            return

        try:
            while self.running:
                if self.serial_port.in_waiting:
                    byte = self.serial_port.read(1)[0]
                    frame = self.decoder.decode(byte)
                    if frame:
                        self._process_frame(frame)
        except KeyboardInterrupt:
            pass
        finally:
            if self.serial_port:
                self.serial_port.close()

    def _process_frame(self, frame):
        if len(frame) < 28:  # min IP + UDP header
            return

        try:
            version_ihl = frame[0]
            ip_version = version_ihl >> 4
            ihl = (version_ihl & 0x0F) * 4

            if ip_version != 4 or ihl < 20:
                return

            protocol = frame[9]
            if protocol != 17:  # UDP
                return

            # Check destination IP (192.168.7.1)
            dst_ip = frame[16:20]
            if dst_ip != b'\xc0\xa8\x07\x01':  # 192.168.7.1
                return

            payload = frame[ihl:]
            if len(payload) < 8:
                return

            dst_port = unpack('!HH', payload[2:6])[0]
            udp_data = payload[8:]

            if dst_port == 5000:  # Log port
                message = udp_data.decode('utf-8', errors='replace').rstrip('\x00\r\n')
                if message:
                    print(message)
                    sys.stdout.flush()
        except:
            pass

    def stop(self):
        self.running = False


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def list_ports():
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("[!] No serial ports found")
        return []
    print("[*] Available serial ports:")
    for i, port in enumerate(ports):
        print(f"  {i}: {port.device} - {port.description}")
    return [p.device for p in ports]


def main():
    parser = argparse.ArgumentParser(description='SLIP UDP Log Receiver')
    parser.add_argument('--port', help='Serial port')
    parser.add_argument('--list-ports', action='store_true', help='List ports')
    args = parser.parse_args()

    if args.list_ports:
        list_ports()
        return

    port = args.port
    if not port:
        ports = list_ports()
        if not ports:
            return
        if len(ports) == 1:
            port = ports[0]
            print(f"[*] Using {port}")
        else:
            try:
                idx = int(input("[?] Select port (number): "))
                port = ports[idx]
            except (ValueError, IndexError):
                print("[!] Invalid selection")
                return

    print("SLIP UDP Log Receiver")
    print("Ctrl+X = clear screen, Ctrl+C = exit")
    print("-" * 50)

    receiver = LogReceiver(port=port, baudrate=2000000)
    thread = threading.Thread(target=receiver.start, daemon=True)
    thread.start()

    def input_handler():
        try:
            if os.name == 'nt':
                import msvcrt
                while receiver.running:
                    if msvcrt.kbhit():
                        key = msvcrt.getch()
                        if key == b'\x18':
                            clear_screen()
                        elif key == b'\x03':
                            receiver.running = False
                    else:
                        import time
                        time.sleep(0.01)
            else:
                import tty, termios, time
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                tty.setraw(fd)
                try:
                    while receiver.running:
                        ch = sys.stdin.read(1)
                        if ch == '\x18':
                            clear_screen()
                        elif ch == '\x03':
                            receiver.running = False
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except:
            pass

    input_thread = threading.Thread(target=input_handler, daemon=True)
    input_thread.start()

    try:
        while receiver.running:
            import time
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        receiver.stop()
        print("\n[*] Stopped")


if __name__ == '__main__':
    main()
