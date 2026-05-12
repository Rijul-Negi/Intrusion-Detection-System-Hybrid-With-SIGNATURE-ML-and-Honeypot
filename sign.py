import re
from scapy.all import IP, TCP, UDP, Raw

sig_flagged_flows = set()

_TCP_APP_PROTOS = {"http", "ftp", "smtp", "imap", "pop3", "ssl", "tls", "telnet"}
_UDP_APP_PROTOS = {"dns", "tftp", "snmp", "ntp", "sip"}
_KNOWN_PROTOS   = _TCP_APP_PROTOS | _UDP_APP_PROTOS | {"tcp", "udp", "icmp", "ip"}


_PORT_VARS = {
    "$HTTP_PORTS":     {80, 8080, 8000, 8008, 8888, 443, 8443},
    "$HTTP_SERVERS":   None,   
    "$SQL_PORTS":      {1433, 3306, 5432, 1521},
    "$FTP_PORTS":      {21, 2121},
    "$SMTP_PORTS":     {25, 465, 587},
    "$SSH_PORTS":      {22},
    "$TELNET_PORTS":   {23},
    "$DNS_PORTS":      {53},
    "$HOME_NET":       None,   
    "$EXTERNAL_NET":   None,   
    "$AIM_SERVERS":    None,
    "$FILE_DATA_PORTS": {80, 8080, 21, 110, 143},
}


def parse_snort_rules(filepath):
    rules = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m = re.match(
                r'(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.+)\)',
                line,
            )
            if not m:
                continue

            action, proto, src_ip, src_port, dst_ip, dst_port, options = m.groups()
            proto = proto.lower()

            if proto not in _KNOWN_PROTOS:
                continue

            msg     = re.search(r'msg:"([^"]+)"',    options)
            sid     = re.search(r'sid:(\d+)',         options)
            content = re.findall(r'content:"([^"]+)"', options)

            if not content and src_port == "any" and dst_port == "any":
                continue

            rules.append({
                "name":      msg.group(1) if msg else "Unknown",
                "sid":       int(sid.group(1)) if sid else 0,
                "proto":     proto,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "content":   content,
            })

    print(f"[sign] Loaded {len(rules)} usable rules")
    return rules


RULES = parse_snort_rules("snort3-community.rules")

def _port_match(rule_port: str, actual_port: int) -> bool:
    if rule_port == "any":
        return True

    # negation  e.g. !80
    if rule_port.startswith("!"):
        return not _port_match(rule_port[1:], actual_port)

    if rule_port in _PORT_VARS:
        port_set = _PORT_VARS[rule_port]
        if port_set is None:
            return True
        return actual_port in port_set

    if rule_port.startswith("$"):
        return False

    if ":" in rule_port:
        parts = rule_port.split(":", 1)
        lo = int(parts[0]) if parts[0] else 0
        hi = int(parts[1]) if parts[1] else 65535
        return lo <= actual_port <= hi

    try:
        return actual_port == int(rule_port)
    except ValueError:
        return False


def _l4_match(rule_proto: str, pack) -> bool:
    if rule_proto in _TCP_APP_PROTOS or rule_proto == "tcp":
        return TCP in pack
    if rule_proto in _UDP_APP_PROTOS or rule_proto == "udp":
        return UDP in pack
    if rule_proto == "ip":
        return IP in pack
    return False


def _content_match(rule_contents: list, pack) -> bool:
    if not rule_contents:
        return True

    if Raw not in pack:
        return False

    payload = bytes(pack[Raw].load)

    search_from = 0
    for pattern in rule_contents:
        def replace_hex(m):
            return bytes(int(h, 16) for h in m.group(1).split()).decode("latin-1")

        raw_pattern = re.sub(r'\|([0-9A-Fa-f ]+)\|', replace_hex, pattern)
        needle      = raw_pattern.encode("latin-1")

        idx = payload.find(needle, search_from)
        if idx == -1:
            return False
        search_from = idx + len(needle) 

    return True


def check_signatures(pack, flow_key):
    if IP not in pack:
        return

    sport = pack[TCP].sport if TCP in pack else (pack[UDP].sport if UDP in pack else 0)
    dport = pack[TCP].dport if TCP in pack else (pack[UDP].dport if UDP in pack else 0)

    for rule in RULES:
        try:
            if not _l4_match(rule["proto"], pack):
                continue
            if not _port_match(rule["src_port"], sport):
                continue
            if not _port_match(rule["dst_port"], dport):
                continue
            if not _content_match(rule["content"], pack):
                continue

            sig_flagged_flows.add(flow_key)
            return   

        except Exception:
            pass    