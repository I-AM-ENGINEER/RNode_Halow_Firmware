"""
API smoke-tests for the mock web configurator server.

Run while the server is up:
    python server.py &
    python test_api.py

Or run with pytest (no server needed — uses the in-process fixture):
    pytest test_api.py -v
"""

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer

# Import the mock server module
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import server as srv


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

BASE = "http://127.0.0.1:18080"


def get(path):
    with urllib.request.urlopen(f"{BASE}{path}") as r:
        return json.loads(r.read())


def post(path, payload=None):
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


# ---------------------------------------------------------------------------
# pytest / unittest fixture — spins up the in-process mock server once
# ---------------------------------------------------------------------------

_server_instance = None
_server_thread = None


def setup_module(_module):
    """Start mock server on port 18080 before the test module runs."""
    global _server_instance, _server_thread

    # Reset shared state to defaults before each test run
    srv._state["change_version"] = 0
    srv._state["halow"] = {
        "bandwidth": "4 MHz",
        "central_freq": 864.5,
        "power_dbm": 20,
        "mcs_index": "MCS5",
    }

    _server_instance = HTTPServer(("127.0.0.1", 18080), srv.Handler)
    _server_thread = threading.Thread(target=_server_instance.serve_forever, daemon=True)
    _server_thread.start()
    time.sleep(0.1)  # let the socket bind


def teardown_module(_module):
    if _server_instance:
        _server_instance.shutdown()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHeartbeat(unittest.TestCase):
    def test_returns_version(self):
        r = get("/api/heartbeat")
        self.assertIn("version", r)
        self.assertIsInstance(r["version"], int)


class TestGetAll(unittest.TestCase):
    def test_structure(self):
        r = get("/api/get_all")
        for key in ("ver", "halow", "net", "tcp", "lbt", "slip", "log", "telemetry", "stat"):
            self.assertIn(key, r, f"missing key: {key}")

    def test_stat_has_device_and_radio(self):
        r = get("/api/get_all")
        self.assertIn("device", r["stat"])
        self.assertIn("radio",  r["stat"])


class TestGetStat(unittest.TestCase):
    def test_structure(self):
        r = get("/api/get_stat")
        self.assertIn("device", r)
        self.assertIn("radio",  r)

    def test_device_fields(self):
        dev = get("/api/get_stat")["device"]
        for f in ("uptime", "hostname", "ip", "ver", "mac", "wmac", "flashs", "cpu", "heap", "chip_temp"):
            self.assertIn(f, dev, f"missing device field: {f}")

    def test_radio_fields(self):
        radio = get("/api/get_stat")["radio"]
        for f in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                  "rx_speed", "tx_speed", "airtime", "ch_util",
                  "bg_pwr_dbm", "bg_pwr_now_dbm"):
            self.assertIn(f, radio, f"missing radio field: {f}")


class TestHalowCfg(unittest.TestCase):
    def test_get(self):
        r = get("/api/halow_cfg")
        for f in ("bandwidth", "central_freq", "power_dbm", "mcs_index"):
            self.assertIn(f, r)

    def test_post_updates_fields(self):
        r = post("/api/halow_cfg", {"power_dbm": 15, "mcs_index": "MCS3"})
        self.assertEqual(r["power_dbm"], 15)
        self.assertEqual(r["mcs_index"], "MCS3")

    def test_get_reflects_post(self):
        post("/api/halow_cfg", {"central_freq": 868.0})
        r = get("/api/halow_cfg")
        self.assertAlmostEqual(r["central_freq"], 868.0)

    def test_post_bumps_version(self):
        v0 = get("/api/heartbeat")["version"]
        post("/api/halow_cfg", {"power_dbm": 10})
        v1 = get("/api/heartbeat")["version"]
        self.assertGreater(v1, v0)


class TestLbtCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/lbt_cfg")
        for f in ("en", "sw", "lw", "lp", "roff", "abusy",
                  "txgr", "txmax", "bmin", "bmax",
                  "uen", "umax", "uwin", "uburst"):
            self.assertIn(f, r)

    def test_post_returns_halow(self):
        # C firmware: lbt POST returns halow_cfg response (config_api_calls.c:703)
        r = post("/api/lbt_cfg", {"en": False})
        self.assertIn("bandwidth", r)

    def test_post_updates_state(self):
        post("/api/lbt_cfg", {"sw": 200})
        r = get("/api/lbt_cfg")
        self.assertEqual(r["sw"], 200)


class TestNetCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/net_cfg")
        for f in ("dhcp", "ip_address", "gw_address", "netmask"):
            self.assertIn(f, r)

    def test_post_static(self):
        r = post("/api/net_cfg", {
            "dhcp": False,
            "ip_address": "10.0.0.5",
            "gw_address": "10.0.0.1",
            "netmask": "255.255.255.0",
        })
        self.assertFalse(r["dhcp"])
        self.assertEqual(r["ip_address"], "10.0.0.5")

    def test_post_dhcp(self):
        r = post("/api/net_cfg", {"dhcp": True})
        self.assertTrue(r["dhcp"])


class TestSlipCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/slip_cfg")
        for f in ("enable", "baud", "ip", "mask", "gw"):
            self.assertIn(f, r)

    def test_post_updates(self):
        r = post("/api/slip_cfg", {"enable": True, "baud": 9600})
        self.assertTrue(r["enable"])
        self.assertEqual(r["baud"], 9600)


class TestLogCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/log_cfg")
        for f in ("enable", "udp_enable", "host", "ip_address", "port"):
            self.assertIn(f, r)

    def test_post_updates(self):
        r = post("/api/log_cfg", {"enable": True, "port": 5140})
        self.assertTrue(r["enable"])
        self.assertEqual(r["port"], 5140)


class TestTcpServerCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/tcp_server_cfg")
        for f in ("enable", "port", "whitelist", "connected"):
            self.assertIn(f, r)

    def test_post_updates(self):
        r = post("/api/tcp_server_cfg", {"enable": True, "port": 4242})
        self.assertTrue(r["enable"])
        self.assertEqual(r["port"], 4242)


class TestTelemetryCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/telemetry_cfg")
        for f in ("en", "ext", "prd", "host", "port", "lat", "lon",
                  "dir_en", "dir", "usr", "pwd", "top", "name", "lxmf"):
            self.assertIn(f, r)

    def test_post_updates(self):
        r = post("/api/telemetry_cfg", {
            "en": True,
            "host": "test.mqtt.local",
            "port": 8883,
            "lat": 55.75,
            "lon": 37.62,
        })
        self.assertTrue(r["en"])
        self.assertEqual(r["host"], "test.mqtt.local")
        self.assertEqual(r["port"], 8883)


class TestTelemetrySend(unittest.TestCase):
    def test_post_ok(self):
        r = post("/api/telemetry_send")
        self.assertIsInstance(r, dict)


class TestResetStat(unittest.TestCase):
    def test_post_ok(self):
        r = post("/api/reset_stat")
        self.assertIsInstance(r, dict)


class TestNearbyModems(unittest.TestCase):
    def test_get_structure(self):
        r = get("/api/get_nearby_modems")
        self.assertIn("d", r)
        self.assertIsInstance(r["d"], list)

    def test_each_row_has_7_fields(self):
        rows = get("/api/get_nearby_modems")["d"]
        for row in rows:
            self.assertEqual(len(row), 7, f"bad row length: {row}")

    def test_rssi_is_negative(self):
        rows = get("/api/get_nearby_modems")["d"]
        for row in rows:
            # row[1] is RSSI in dBm — should be negative for real signals
            self.assertLess(row[1], 0)

    def test_snr_is_positive(self):
        rows = get("/api/get_nearby_modems")["d"]
        for row in rows:
            # row[2] is SNR in dB — should be positive for real signals
            self.assertGreater(row[2], 0)


class TestReticulumLinks(unittest.TestCase):
    def test_get_structure(self):
        r = get("/api/get_reticulum_links")
        self.assertIn("d", r)
        self.assertIsInstance(r["d"], list)


class TestReboot(unittest.TestCase):
    def test_post_ok(self):
        r = post("/api/reboot")
        self.assertIsInstance(r, dict)


class TestDefaultReset(unittest.TestCase):
    def test_post_ok(self):
        r = post("/api/default_rst")
        self.assertIsInstance(r, dict)


class TestOtaStubs(unittest.TestCase):
    def test_wipe_lfs(self):
        r = post("/api/ota_wipe_lfs")
        self.assertIsInstance(r, dict)

    def test_fw_begin(self):
        r = post("/api/ota_fw_begin", {"size": 524288})
        self.assertIsInstance(r, dict)

    def test_fw_chunk(self):
        r = post("/api/ota_fw_chunk", {"offset": 0, "data": "AABBCCDD"})
        self.assertIsInstance(r, dict)

    def test_fw_end(self):
        r = post("/api/ota_fw_end", {"crc": "12345678"})
        self.assertIsInstance(r, dict)


class TestPrivacyCfg(unittest.TestCase):
    def test_get_fields(self):
        r = get("/api/privacy_cfg")
        self.assertIn("rotation", r)
        self.assertIn("broadcast", r)

    def test_post_updates(self):
        r = post("/api/privacy_cfg", {"rotation": 60, "broadcast": False})
        self.assertEqual(r["rotation"], 60)
        self.assertFalse(r["broadcast"])

    def test_post_broadcast(self):
        r = post("/api/privacy_cfg", {"broadcast": True})
        self.assertTrue(r["broadcast"])


class TestUnknownEndpoint(unittest.TestCase):
    def test_404(self):
        try:
            get("/api/nonexistent_endpoint")
            self.fail("expected HTTPError 404")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


class TestMethodNotAllowed(unittest.TestCase):
    def test_get_on_post_only(self):
        """reboot is POST-only; GET should return 405."""
        try:
            get("/api/reboot")
            self.fail("expected HTTPError 405")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 405)

    def test_post_on_get_only(self):
        """get_stat is GET-only; POST should return 405."""
        try:
            post("/api/get_stat")
            self.fail("expected HTTPError 405")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 405)


if __name__ == "__main__":
    setup_module(None)
    try:
        unittest.main(verbosity=2, exit=False)
    finally:
        teardown_module(None)
