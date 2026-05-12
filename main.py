import time
import os
import psutil
import threading
import webbrowser
import server

from sniffer import pack_info_extract, check_flow, flow_exporter, flow_queue, alert_queue
from infer import ml_worker
from honeypot import start_honeypot

# ================================================================================================================
# - Hybrid Intrusion Detection System with ML + Signature based detection and Honeypots - 
## Rijul Negi - Backend development, Data Pre-processing , Feature Engineering, Model Training, and Testing
## Shivam Sharma - UI coding and design
## Simarpreet Singh - Paperwork, writing Synopsis and Final Report
# ================================================================================================================
# - Data Sets Used for Model Training -
## NF-UNSW-NB15-v3.csv
## NF-ToN-IoT-v3.csv
## CIC-DDoS2019
#================================================================================================================
# - Ruleset Used -
## snort3-community.rules
# ================================================================================================================

proc = psutil.Process(os.getpid())
proc.cpu_percent(interval=1)

server.set_queue(alert_queue, proc)

threads = [
    threading.Thread(target=pack_info_extract, daemon=True),
    threading.Thread(target=check_flow, daemon=True),
    threading.Thread(target=flow_exporter, daemon=True),
    threading.Thread(target=ml_worker, args=(flow_queue, alert_queue), daemon=True),
    threading.Thread(target=start_honeypot, args=(alert_queue,), daemon=True),
    threading.Thread(target=server.run, daemon=True),
]

for t in threads:
    t.start()

threading.Timer(1.5, lambda: webbrowser.open("http://localhost:8000")).start()

print("GUI — http://localhost:8000")
print("Press Ctrl+C to stop\n")

try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    print("\nShutting down")