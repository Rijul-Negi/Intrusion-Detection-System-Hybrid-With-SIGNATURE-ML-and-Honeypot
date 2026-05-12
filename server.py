from flask import Flask, Response, send_from_directory
import json
import time
import psutil
from datetime import datetime

app = Flask(__name__)

# Shared objects from main.py
alert_queue = None
process_ref = None


# Connection
def set_queue(queue, proc=None):
    global alert_queue, process_ref
    alert_queue = queue
    process_ref = proc


# is format
def format_alert(a):
    return {
        "type": "alert",
        "time": datetime.now().strftime("%H:%M:%S"),
        "src": a.get("src", "unknown"),
        "name": a.get("name", "Unknown Threat"),
        "confidence": float(a.get("confidence", 0.9)),
        "severity": a.get("severity", "WARN"),
        "method": a.get("method", "ml"),
        "is_attack": bool(a.get("is_attack", True)),
        "dport": a.get("dport", 0),
    }


def event_stream():
    while True:
        # Sends Alert
        if alert_queue is not None:
            try:
                while True:
                    raw = alert_queue.get_nowait()
                    alert = format_alert(raw)
                    yield f"data: {json.dumps(alert)}\n\n"
            except:
                pass

        # Resource util
        if process_ref:
            cpu = process_ref.cpu_percent(interval=None)
        else:
            cpu = psutil.cpu_percent()
        ram = process_ref.memory_info().rss / (1024 * 1024) if process_ref else 0 # MB
        stats = {
            "type": "stats",
            "cpu": round(cpu, 1),
            "ram": round(ram, 1)
        }
        
        yield f"data: {json.dumps(stats)}\n\n"
        time.sleep(0.5)


# routes
@app.route('/')
def index():
    return send_from_directory('.', 'dashboard.html')
@app.route('/stream')
def stream():
    return Response(event_stream(), mimetype="text/event-stream")
@app.route("/whitelist")
def whitelist():
    with open("whitelist.json") as f:
        return app.response_class(f.read(), mimetype="application/json")


def run():
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)