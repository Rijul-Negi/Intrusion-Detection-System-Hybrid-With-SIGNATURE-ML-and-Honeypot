from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, get_if_list
from queue import Queue
from threading import Lock
import numpy as np
import time

from sign import check_signatures, sig_flagged_flows

EPS = 1e-6

check_queue = Queue()
flow_queue  = Queue()
alert_queue = Queue()
flow_table  = {}
flow_lock   = Lock()

class Flow:
    def __init__(self, now):
        self.start = now
        self.last  = now

        self.PROTOCOL  = 0
        self.L7_PROTO  = 0

        self.IN_BYTES  = 0
        self.IN_PKTS   = 0

        self.TCP_FLAGS      = 0
        self.TCP_WIN_MAX_IN = 0

        self.s2d      = []
        self.last_s2d = now

    def update(self, pkt_len, flags, win, now):
        self.IN_BYTES  += pkt_len
        self.IN_PKTS   += 1
        self.TCP_FLAGS |= flags

        self.s2d.append((now - self.last_s2d) * 1000)
        self.last_s2d = now
        self.last     = now


def process_packet(pack):
    if IP not in pack:
        return

    print("PACKET DETECTED")  

    now     = time.time()
    pkt_len = len(pack)

    ip    = pack[IP]
    proto = ip.proto

    sport = pack[TCP].sport if TCP in pack else (pack[UDP].sport if UDP in pack else 0)
    dport = pack[TCP].dport if TCP in pack else (pack[UDP].dport if UDP in pack else 0)
    flags = int(pack[TCP].flags) if TCP in pack else 0
    win   = pack[TCP].window    if TCP in pack else 0

    key = (ip.src, ip.dst, sport, dport, proto)

    check_signatures(pack, key)

    with flow_lock:
        flow = flow_table.get(key)

        if flow is None:
            flow = Flow(now)
            flow.PROTOCOL = proto
            flow.L7_PROTO = dport
            flow_table[key] = flow

        flow.update(pkt_len, flags, win, now)


def flow_exporter():
    while True:
        time.sleep(0.5)
        now = time.time()

        with flow_lock:
            keys = list(flow_table.keys())

        for key in keys:
            with flow_lock:
                flow = flow_table.get(key)
                if flow is None:
                    continue

                if (now - flow.last > 0.5) or flow.IN_PKTS >= 3:
                    check_queue.put((key, flow_table.pop(key)))


def check_flow():
    while True:
        key, flow = check_queue.get()

        dur     = max((flow.last - flow.start) * 1000, 1)
        dur_sec = dur / 1000.0

        s2d = flow.s2d
        stats = [
            min(s2d) if s2d else 0.0,
            max(s2d) if s2d else 0.0,
            float(np.mean(s2d)) if s2d else 0.0,
            float(np.std(s2d)) if s2d else 0.0
        ]

        sig_flagged = key in sig_flagged_flows
        sig_flagged_flows.discard(key)

        flow_queue.put({
            "features": {
                "PROTOCOL": flow.PROTOCOL,
                "L7_PROTO": flow.L7_PROTO,
                "IN_BYTES": flow.IN_BYTES,
                "IN_PKTS": flow.IN_PKTS,
                "FLOW_DURATION_MILLISECONDS": dur,
                "SRC_TO_DST_IAT_MIN": stats[0],
                "SRC_TO_DST_IAT_MAX": stats[1],
                "SRC_TO_DST_IAT_AVG": stats[2],
                "SRC_TO_DST_IAT_STDDEV": stats[3],
                "IN_BYTES_PER_SEC": flow.IN_BYTES / (dur_sec + EPS),
                "IN_PKTS_PER_SEC": flow.IN_PKTS / (dur_sec + EPS),
                "OUT_IN_BYTES_RATIO": 1.0,
                "PKT_SIZE_AVG": flow.IN_BYTES / (flow.IN_PKTS + 1),
            },
            "sig_flagged": sig_flagged,
            "src": key[0],
            "dport": key[3],
        })


def pack_info_extract():
    sniff(
        iface=get_if_list(),
        prn=process_packet,
        store=False
    )
