import time
import threading
import struct
from scapy.all import Ether, Raw, sendp, sniff, get_if_hwaddr, get_if_list
from scapy.arch.windows import get_windows_if_list

ETHERTYPE = 0x4847
PAYLOAD   = b"\x02\x00"


def _build_iface_map():
    m = {}
    for i in get_windows_if_list():
        guid = i.get("guid")
        if not guid:
            continue
        npf = f"\\device\\npf_{guid}".lower()
        m[npf] = {
            "name": i.get("name"),
            "mac": (i.get("mac") or "").lower(),
        }
    return m


def _iface_title(iface, iface_map):
    info = iface_map.get(iface.lower())
    if info and info.get("name"):
        return info["name"]
    return iface


def _parse_scan_report(eth, iface_title):
    if eth.type != ETHERTYPE:
        return None
    if not eth.haslayer(Raw):
        return None

    b = bytes(eth[Raw].load)
    if len(b) < 18:
        return None

    stype  = b[0]
    status = b[1]

    ver_u32 = struct.unpack(">I", b[2:6])[0]
    v0, v1, v2, v3 = b[2], b[3], b[4], b[5]

    chipid = struct.unpack(">H", b[6:8])[0]
    mode   = b[8]
    rev    = b[9]

    svn_version = struct.unpack(">I", b[10:14])[0]
    app_version = struct.unpack(">I", b[14:18])[0]

    return {
        "iface": iface_title,

        "hdr": {
            "dest": eth.dst.lower(),
            "src": eth.src.lower(),
            "proto": eth.type,
            "stype": stype,
            "status": status,
        },

        "version": ver_u32,
        "chipid": chipid,
        "mode": mode,
        "rev": rev,
        "svn_version": svn_version,
        "app_version": app_version,

        "version_str": f"{v0}.{v1}.{v2}.{v3}",
        "raw": b,
        "tail": b[18:],
    }


def _scan_iface(iface, iface_map, packet_cnt, period_sec, sniff_time):
    try:
        my_mac = get_if_hwaddr(iface).lower()
    except Exception:
        return []

    if my_mac == "00:00:00:00:00:00":
        return []

    found = []
    seen  = set()
    title = _iface_title(iface, iface_map)

    def on_packet(p):
        if not p.haslayer(Ether):
            return
        eth = p[Ether]

        if eth.type != ETHERTYPE:
            return
        if eth.dst.lower() != my_mac:
            return

        src = eth.src.lower()
        if src == my_mac or src in seen:
            return

        rep = _parse_scan_report(eth, title)
        if not rep:
            return

        seen.add(src)
        found.append(rep)

    def sender():
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac, type=ETHERTYPE) / PAYLOAD
        time.sleep(0.1)
        for _ in range(packet_cnt):
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(period_sec)

    threading.Thread(target=sender, daemon=True).start()

    sniff(
        iface=iface,
        timeout=sniff_time,
        prn=on_packet,
        store=False,
        promisc=True,
        filter=f"ether proto 0x{ETHERTYPE:04x}",
    )

    return found


def scan_all_parallel(packet_cnt=10, period_sec=0.010, sniff_time=0.5):
    iface_map = _build_iface_map()
    ifaces = []

    for iface in get_if_list():
        lname = iface.lower()
        if "loopback" in lname or lname == "lo":
            continue
        ifaces.append(iface)

    out  = []
    lock = threading.Lock()
    thrs = []

    def worker(iface):
        res = _scan_iface(iface, iface_map, packet_cnt, period_sec, sniff_time)
        if not res:
            return
        with lock:
            out.extend(res)

    for iface in ifaces:
        t = threading.Thread(target=worker, args=(iface,), daemon=True)
        thrs.append(t)
        t.start()

    for t in thrs:
        t.join()

    return out

if __name__ == "__main__":
    res = scan_all_parallel(
        packet_cnt=10,
        period_sec=0.010,
        sniff_time=0.5,
    )

    for r in res:
        print("IFACE:", r["iface"])
        print("SRC:", r["hdr"]["src"])
        print("DST:", r["hdr"]["dest"])
        print("PROTO: 0x%04x" % r["hdr"]["proto"])
        print("STYPE:", r["hdr"]["stype"], "STATUS:", r["hdr"]["status"])
        print("VERSION:", r["version_str"])
        print("CHIPID:", r["chipid"])
        print("MODE:", r["mode"], "REV:", r["rev"])
        print("SVN:", r["svn_version"])
        print("APP:", r["app_version"])
        print("-" * 40)