from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from queue import Queue
import pandas as pd
import xgboost as xgb
import numpy as np
import time

EPS         = 1e-6
check_queue = Queue()
flow_queue  = Queue()
flow_table  = {}

detector   = xgb.XGBClassifier()
detector.load_model("v3_model.json")
trained_on = detector.get_booster().feature_names

def pack_info_extract():
    def handle(pack):
        if not IP in pack: return
        now, pkt  = time.time(), len(pack)
        proto, ttl = pack[IP].proto, pack[IP].ttl
        sport = pack[TCP].sport if TCP in pack else (pack[UDP].sport if UDP in pack else 0)
        dport = pack[TCP].dport if TCP in pack else (pack[UDP].dport if UDP in pack else 0)
        flags = int(pack[TCP].flags) if TCP in pack else 0
        win   = pack[TCP].window if TCP in pack else 0
        key   = (pack[IP].src, pack[IP].dst, sport, dport, proto)

        if key not in flow_table:
            flow_table[key] = {
                "start": now, "last": now, "PROTOCOL": proto, "L7_PROTO": dport,
                "IN_BYTES": pkt, "IN_PKTS": 1, "OUT_BYTES": 0, "OUT_PKTS": 0,
                "TCP_FLAGS": flags, "CLIENT_TCP_FLAGS": flags, "SERVER_TCP_FLAGS": 0,
                "MIN_TTL": ttl, "MAX_TTL": ttl,
                "LONGEST_FLOW_PKT": pkt, "SHORTEST_FLOW_PKT": pkt,
                "MIN_IP_PKT_LEN": pkt, "MAX_IP_PKT_LEN": pkt,
                "RETRANSMITTED_IN_BYTES": 0, "RETRANSMITTED_IN_PKTS": 0,
                "RETRANSMITTED_OUT_BYTES": 0, "RETRANSMITTED_OUT_PKTS": 0,
                "TCP_WIN_MAX_IN": win, "TCP_WIN_MAX_OUT": 0,
                "ICMP_IPV4_TYPE": pack[ICMP].type if ICMP in pack else 0,
                "DNS_QUERY_TYPE": pack[DNS].qd.qtype if (DNS in pack and pack[DNS].qd) else 0,
                "DNS_TTL_ANSWER": pack[DNS].an.ttl if (DNS in pack and pack[DNS].an) else 0,
                "NUM_PKTS_UP_TO_128_BYTES": 0, "NUM_PKTS_128_TO_256_BYTES": 0,
                "NUM_PKTS_256_TO_512_BYTES": 0, "NUM_PKTS_512_TO_1024_BYTES": 0,
                "NUM_PKTS_1024_TO_1514_BYTES": 0,
                "s2d": [], "last_s2d": now,
            }
        else:
            f = flow_table[key]
            f["IN_BYTES"] += pkt; f["IN_PKTS"] += 1
            f["TCP_FLAGS"] |= flags; f["CLIENT_TCP_FLAGS"] |= flags
            f["TCP_WIN_MAX_IN"] = max(f["TCP_WIN_MAX_IN"], win)
            f["MIN_TTL"] = min(f["MIN_TTL"], ttl); f["MAX_TTL"] = max(f["MAX_TTL"], ttl)
            f["LONGEST_FLOW_PKT"] = max(f["LONGEST_FLOW_PKT"], pkt)
            f["SHORTEST_FLOW_PKT"] = min(f["SHORTEST_FLOW_PKT"], pkt)
            f["MIN_IP_PKT_LEN"] = min(f["MIN_IP_PKT_LEN"], pkt)
            f["MAX_IP_PKT_LEN"] = max(f["MAX_IP_PKT_LEN"], pkt)
            f["s2d"].append((now - f["last_s2d"]) * 1000)
            f["last_s2d"] = now; f["last"] = now
            b = ["NUM_PKTS_UP_TO_128_BYTES","NUM_PKTS_128_TO_256_BYTES","NUM_PKTS_256_TO_512_BYTES","NUM_PKTS_512_TO_1024_BYTES","NUM_PKTS_1024_TO_1514_BYTES"]
            f[b[0 if pkt<=128 else 1 if pkt<=256 else 2 if pkt<=512 else 3 if pkt<=1024 else 4]] += 1
            if now - f["last"] > 60: check_queue.put(flow_table.pop(key))

    sniff(prn=handle, store=False)

def check_flow():
    while True:
        f   = check_queue.get()
        dur = max((f["last"] - f["start"]) * 1000, 1)
        s2d = f["s2d"]
        iat = lambda x: [min(x),max(x),float(np.mean(x)),float(np.std(x))] if x else [0,0,0,0]
        s   = iat(s2d)
        flow_queue.put({**{k: f[k] for k in ["PROTOCOL","L7_PROTO","IN_BYTES","IN_PKTS","OUT_BYTES","OUT_PKTS","TCP_FLAGS","CLIENT_TCP_FLAGS","SERVER_TCP_FLAGS","MIN_TTL","MAX_TTL","LONGEST_FLOW_PKT","SHORTEST_FLOW_PKT","MIN_IP_PKT_LEN","MAX_IP_PKT_LEN","RETRANSMITTED_IN_BYTES","RETRANSMITTED_IN_PKTS","RETRANSMITTED_OUT_BYTES","RETRANSMITTED_OUT_PKTS","NUM_PKTS_UP_TO_128_BYTES","NUM_PKTS_128_TO_256_BYTES","NUM_PKTS_256_TO_512_BYTES","NUM_PKTS_512_TO_1024_BYTES","NUM_PKTS_1024_TO_1514_BYTES","TCP_WIN_MAX_IN","TCP_WIN_MAX_OUT","ICMP_IPV4_TYPE","DNS_QUERY_TYPE","DNS_TTL_ANSWER"]},
            "FLOW_DURATION_MILLISECONDS": dur, "DURATION_IN": dur, "DURATION_OUT": dur,
            "SRC_TO_DST_SECOND_BYTES": f["IN_BYTES"]/(dur/1000+EPS), "DST_TO_SRC_SECOND_BYTES": 0,
            "SRC_TO_DST_AVG_THROUGHPUT": f["IN_BYTES"]/(dur/1000+EPS), "DST_TO_SRC_AVG_THROUGHPUT": 0,
            "SRC_TO_DST_IAT_MIN": s[0], "SRC_TO_DST_IAT_MAX": s[1], "SRC_TO_DST_IAT_AVG": s[2], "SRC_TO_DST_IAT_STDDEV": s[3],
            "DST_TO_SRC_IAT_MIN": 0, "DST_TO_SRC_IAT_MAX": 0, "DST_TO_SRC_IAT_AVG": 0, "DST_TO_SRC_IAT_STDDEV": 0,
            "IN_BYTES_PER_SEC": f["IN_BYTES"]/(dur+EPS), "IN_PKTS_PER_SEC": f["IN_PKTS"]/(dur+EPS),
            "OUT_IN_BYTES_RATIO": 1.0, "PKT_SIZE_AVG": f["IN_BYTES"]/(f["IN_PKTS"]+EPS),
        })

def ml_inference():
    while True:
        features   = flow_queue.get()
        df         = pd.DataFrame([features]).reindex(columns=trained_on, fill_value=0)
        confidence = detector.predict_proba(df)[0][1]
        if confidence >= 0.5:
            print(f"[ALERT] confidence={confidence:.2f}")