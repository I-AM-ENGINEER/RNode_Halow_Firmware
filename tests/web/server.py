"""
Mock HTTP server for web configurator testing.

Run: python server.py [--port 8080]
Then open http://localhost:8080 in browser.
"""

import argparse
import copy
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WWW_DIR = Path(__file__).parent.parent.parent / "web_configurator" / "www"

# ---------------------------------------------------------------------------
# In-memory device state (mirrors C firmware defaults)
# ---------------------------------------------------------------------------

_state = {
    "change_version": 0,

    "halow": {
        "bandwidth": "4 MHz",
        "central_freq": 864.5,
        "power_dbm": 20,
        "mcs_index": "MCS5",
    },

    "lbt": {
        "en": True,
        "sw": 100,
        "lw": 500,
        "lp": 10,
        "roff": -5,
        "abusy": -80,
        "txgr": 1000,
        "txmax": 5000,
        "bmin": 500,
        "bmax": 5000,
        "uen": False,
        "umax": 50,
        "uwin": 10000,
        "uburst": 1000,
    },

    "net": {
        "dhcp": True,
        "ip_address": "192.168.1.100",
        "gw_address": "192.168.1.1",
        "netmask": "255.255.255.0",
    },

    "slip": {
        "enable": False,
        "baud": 115200,
        "ip": "10.0.0.1",
        "mask": "255.255.255.252",
        "gw": "10.0.0.2",
    },

    "log": {
        "udp_enable": False,
        "enable": False,
        "host": "192.168.1.200",
        "ip_address": "192.168.1.200",
        "port": 514,
    },

    "tcp": {
        "enable": False,
        "port": 9000,
        "whitelist": "0.0.0.0/0",
        "connected": "no connection",
    },

    "telemetry": {
        "en": False,
        "ext": False,
        "prd": 60,
        "host": "mqtt.example.com",
        "port": 1883,
        "lat": 0.0,
        "lon": 0.0,
        "dir_en": False,
        "dir": 0,
        "usr": "",
        "pwd": "",
        "top": "rnode/telemetry",
        "name": "rnode-halow",
        "lxmf": "00000000000000000000000000000000",
    },

    "dev_stat": {
        "uptime": "0d 0h 1m 0s",
        "hostname": "rnode-halow",
        "ip": "192.168.1.100",
        "ver": "0.6.0-dev",
        "mac": "AA:BB:CC:DD:EE:FF",
        "flashs": "128 Mbit",
        "cpu": "12.5%",
        "heap": "210.3 KiB / 256 KiB",
    },

    "radio_stat": {
        "rx_bytes": "0.00 KiB",
        "tx_bytes": "0.00 KiB",
        "rx_packets": 0,
        "tx_packets": 0,
        "rx_speed": "0.00 kbit/s",
        "tx_speed": "0.00 kbit/s",
        "airtime": "0.0 %",
        "ch_util": "0.0 %",
        "bg_pwr_dbm": "-95.0 dBm",
        "bg_pwr_now_dbm": "-95.0 dBm",
    },

    "nearby_modems": [
        ["AABBCCDDEEFF", -72, 5, 1234, 56789, 3],
        ["112233445566", -85, 3, 420,  12345, 11],
    ],

    "reticulum_links": [],

    "ota": {
        "fw_version": None,
        "progress": 0,
        "state": "idle",   # idle | uploading | done | error
    },
}


def _bump_version():
    _state["change_version"] += 1


# ---------------------------------------------------------------------------
# API handler functions (one per endpoint)
# ---------------------------------------------------------------------------

def api_heartbeat_get(_body):
    return {"version": _state["change_version"]}


def api_ok_get(_body):
    return {"ok": True}


def api_get_all_get(_body):
    s = _state
    return {
        "ver": s["change_version"],
        "halow": copy.deepcopy(s["halow"]),
        "net":   copy.deepcopy(s["net"]),
        "tcp":   copy.deepcopy(s["tcp"]),
        "lbt":   copy.deepcopy(s["lbt"]),
        "ota":   {},
        "slip":  copy.deepcopy(s["slip"]),
        "log":   copy.deepcopy(s["log"]),
        "telemetry": copy.deepcopy(s["telemetry"]),
        "stat": {
            "device": copy.deepcopy(s["dev_stat"]),
            "radio":  copy.deepcopy(s["radio_stat"]),
        },
    }


def api_get_stat_get(_body):
    return {
        "device": copy.deepcopy(_state["dev_stat"]),
        "radio":  copy.deepcopy(_state["radio_stat"]),
    }


def api_halow_cfg_get(_body):
    return copy.deepcopy(_state["halow"])


def api_halow_cfg_post(body):
    cfg = _state["halow"]
    for key in ("bandwidth", "mcs_index"):
        if key in body:
            cfg[key] = body[key]
    for key in ("central_freq", "power_dbm"):
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    return copy.deepcopy(cfg)


def api_lbt_cfg_get(_body):
    return copy.deepcopy(_state["lbt"])


def api_lbt_cfg_post(body):
    cfg = _state["lbt"]
    for key in cfg:
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    # C firmware returns halow_cfg after lbt POST (see config_api_calls.c:703)
    return copy.deepcopy(_state["halow"])


def api_net_cfg_get(_body):
    return copy.deepcopy(_state["net"])


def api_net_cfg_post(body):
    cfg = _state["net"]
    for key in ("dhcp", "ip_address", "gw_address", "netmask"):
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    return copy.deepcopy(cfg)


def api_slip_cfg_get(_body):
    return copy.deepcopy(_state["slip"])


def api_slip_cfg_post(body):
    cfg = _state["slip"]
    for key in cfg:
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    return copy.deepcopy(cfg)


def api_log_cfg_get(_body):
    return copy.deepcopy(_state["log"])


def api_log_cfg_post(body):
    cfg = _state["log"]
    for key in cfg:
        if key in body:
            cfg[key] = body[key]
    # mirror both field names like the C code does
    if "udp_enable" in body:
        cfg["enable"] = body["udp_enable"]
    if "enable" in body:
        cfg["udp_enable"] = body["enable"]
    if "host" in body:
        cfg["ip_address"] = body["host"]
    if "ip_address" in body:
        cfg["host"] = body["ip_address"]
    _bump_version()
    return copy.deepcopy(cfg)


def api_tcp_server_cfg_get(_body):
    return copy.deepcopy(_state["tcp"])


def api_tcp_server_cfg_post(body):
    cfg = _state["tcp"]
    for key in ("enable", "port", "whitelist"):
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    return copy.deepcopy(cfg)


def api_telemetry_cfg_get(_body):
    return copy.deepcopy(_state["telemetry"])


def api_telemetry_cfg_post(body):
    cfg = _state["telemetry"]
    for key in cfg:
        if key in body:
            cfg[key] = body[key]
    _bump_version()
    return copy.deepcopy(cfg)


def api_telemetry_send_post(_body):
    print("[stub] telemetry_send triggered")
    return {}


def api_reset_stat_post(_body):
    r = _state["radio_stat"]
    for k in r:
        r[k] = "0.00 KiB" if "bytes" in k else (
            "0.00 kbit/s" if "speed" in k else (
                "0.0 %" if "%" in str(r[k]) else (
                    "-95.0 dBm" if "dBm" in str(r[k]) else 0
                )
            )
        )
    _bump_version()
    return copy.deepcopy(_state["lbt"])


def api_reboot_post(_body):
    print("[stub] reboot requested")
    _bump_version()
    return {}


def api_default_rst_post(_body):
    print("[stub] factory reset requested")
    _bump_version()
    return {}


def api_get_nearby_modems_get(_body):
    rows = [
        [mac, rssi, mcs, rxp, rxb, age]
        for mac, rssi, mcs, rxp, rxb, age in _state["nearby_modems"]
    ]
    return {"d": rows}


def api_get_reticulum_links_get(_body):
    return {"d": list(_state["reticulum_links"])}


# --- OTA stubs ---

def api_ota_wipe_lfs_post(_body):
    print("[stub] ota_wipe_lfs")
    return {}


def api_ota_file_begin_post(body):
    print(f"[stub] ota_file_begin: {body}")
    return {}


def api_ota_file_chunk_post(body):
    return {}


def api_ota_file_end_post(body):
    print(f"[stub] ota_file_end: {body}")
    return {}


def api_ota_fw_begin_post(body):
    print(f"[stub] ota_fw_begin size={body.get('size')}")
    _state["ota"]["state"] = "uploading"
    _state["ota"]["progress"] = 0
    return {}


def api_ota_fw_chunk_post(body):
    return {}


def api_ota_fw_end_post(body):
    print(f"[stub] ota_fw_end crc={body.get('crc')}")
    _state["ota"]["state"] = "done"
    _state["ota"]["progress"] = 100
    return {}


# ---------------------------------------------------------------------------
# Route table  { "endpoint": (GET_fn | None, POST_fn | None) }
# ---------------------------------------------------------------------------

ROUTES = {
    "heartbeat":          (api_heartbeat_get,          None),
    "ok":                 (api_ok_get,                 None),
    "get_all":            (api_get_all_get,             None),
    "get_stat":           (api_get_stat_get,            None),
    "halow_cfg":          (api_halow_cfg_get,           api_halow_cfg_post),
    "lbt_cfg":            (api_lbt_cfg_get,             api_lbt_cfg_post),
    "net_cfg":            (api_net_cfg_get,             api_net_cfg_post),
    "slip_cfg":           (api_slip_cfg_get,            api_slip_cfg_post),
    "log_cfg":            (api_log_cfg_get,             api_log_cfg_post),
    "tcp_server_cfg":     (api_tcp_server_cfg_get,      api_tcp_server_cfg_post),
    "telemetry_cfg":      (api_telemetry_cfg_get,       api_telemetry_cfg_post),
    "telemetry_send":     (None,                        api_telemetry_send_post),
    "reset_stat":         (None,                        api_reset_stat_post),
    "reboot":             (None,                        api_reboot_post),
    "default_rst":        (None,                        api_default_rst_post),
    "get_nearby_modems":  (api_get_nearby_modems_get,   None),
    "get_reticulum_links":(api_get_reticulum_links_get, None),
    "ota_wipe_lfs":       (None,                        api_ota_wipe_lfs_post),
    "ota_file_begin":     (None,                        api_ota_file_begin_post),
    "ota_file_chunk":     (None,                        api_ota_file_chunk_post),
    "ota_file_end":       (None,                        api_ota_file_end_post),
    "ota_fw_begin":       (None,                        api_ota_fw_begin_post),
    "ota_fw_chunk":       (None,                        api_ota_fw_chunk_post),
    "ota_fw_end":         (None,                        api_ota_fw_end_post),
}


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress default noisy access log; print our own condensed version
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

    # ---- static file serving -----------------------------------------------

    def _serve_static(self):
        rel = self.path.lstrip("/") or "index.html"
        # strip query string
        rel = rel.split("?")[0]
        target = WWW_DIR / rel
        if not target.exists() or not target.is_file():
            self.send_error(404, f"Not found: {rel}")
            return
        mime = {
            ".html": "text/html",
            ".js":   "application/javascript",
            ".css":  "text/css",
        }.get(target.suffix, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- API dispatch -------------------------------------------------------

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _send_json(self, code, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch_api(self, method):
        # path: /api/<endpoint>
        endpoint = self.path.lstrip("/api/").split("?")[0]
        if endpoint.startswith("api/"):
            endpoint = endpoint[len("api/"):]

        entry = ROUTES.get(endpoint)
        if entry is None:
            self._send_json(404, {"err": f"unknown endpoint: {endpoint}"})
            return

        get_fn, post_fn = entry

        if method == "GET":
            if get_fn is None:
                self._send_json(405, {"err": "method not allowed"})
                return
            result = get_fn(None)
        else:  # POST
            if post_fn is None:
                self._send_json(405, {"err": "method not allowed"})
                return
            body = self._read_json_body()
            result = post_fn(body)

        self._send_json(200, result)

    # ---- entry points -------------------------------------------------------

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._dispatch_api("GET")
        else:
            self._serve_static()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._dispatch_api("POST")
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Mock web configurator server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    if not WWW_DIR.exists():
        print(f"ERROR: www directory not found at {WWW_DIR}", file=sys.stderr)
        sys.exit(1)

    server = HTTPServer((args.host, args.port), Handler)
    print(f"Mock server running at http://{args.host}:{args.port}/")
    print(f"Serving static files from: {WWW_DIR}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
