import time
import os
import psutil
from threading import Thread
from Sniffer import pack_info_extract, check_flow, ml_inference
from honeypot_reciever import start_receiver

proc = psutil.Process(os.getpid())
proc.cpu_percent()

start = time.time()

Thread(target=pack_info_extract).start()
Thread(target=check_flow).start()
Thread(target=ml_inference).start()
Thread(target=start_receiver).start()

end = time.time()

print(end-start, "time taken")
print(proc.cpu_percent())
print(proc.memory_info().rss/1024/1024, "MB")