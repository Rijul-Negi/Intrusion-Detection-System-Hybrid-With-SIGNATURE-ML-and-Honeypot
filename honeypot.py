import socket
import threading
import time

# ports nobody should ever connect to — any hit is guaranteed malicious
HONEYPOT_PORTS = [23, 80, 3389, 5900, 8888]

BANNERS = {
    23:   b"Welcome to Ubuntu 16.04 LTS\r\nlogin: ",
    80:   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.18 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Login</h1><form><input name='user'/><input name='pass' type='password'/><button>Submit</button></form></body></html>",
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x00\x00\x00\x00",
    5900: b"RFB 003.008\n",
    8888: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Admin Panel</h1><form><input name='user'/><input name='pass' type='password'/><button>Login</button></form></body></html>",
}

def _listen(port, alert_queue):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[honeypot] listening on port {port}")

    while True:
        try:
            conn, addr = s.accept()

            banner = BANNERS.get(port, b"")
            if banner:
                conn.send(banner)

            try:
                conn.settimeout(2)
                data = conn.recv(1024)
                payload = data.decode("latin-1", errors="replace").strip()
            except Exception:
                payload = ""

            conn.close()

            alert_queue.put({
                "is_attack":  True,
                "method":     "honeypot",
                "name":       f"Honeypot Hit ::{port}",
                "src":        addr[0],
                "confidence": 1.0,
                "severity":   "CRIT",
                "time":       time.strftime("%H:%M:%S"),
                "dport":      port,
            })

            if payload:
                print(f"[honeypot] port {port} — {addr[0]} sent: {repr(payload)}")

        except Exception:
            pass


def start_honeypot(alert_queue):
    for port in HONEYPOT_PORTS:
        threading.Thread(target=_listen, args=(port, alert_queue), daemon=True).start()
