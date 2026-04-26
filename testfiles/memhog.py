# memhog.py

import time
import os
import psutil

data = []
MAX_MB = 510

while True:
    process = psutil.Process(os.getpid())
    current_mb = process.memory_info().rss / 1024 / 1024

    if current_mb < MAX_MB:
        data.append(' ' * 10**6) # I like RAM, yum yum

    time.sleep(0.5)