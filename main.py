# Robin Reinhardt
# OS Project 3
# Proc Blart: Mallware Cop

### Step 1: Real-Time Process Monitor

# Start by building a Python script that continuously monitors running processes. Your monitor should:

# - List active processes in real time
# - For each process, display:
#     - Process name
#     - PID
#     - CPU usage
#     - Memory usage

# Format the output clearly, and make it easy to observe system behavior over time.

import psutil
import time
import hashlib
import json
# from rich.live import Live
from rich.table import Table
from rich.console import Console

from helper import get_processes, get_filepath, get_filehash, compare_hashes

console = Console()





def show_process_table(processes):
    table = Table(title = "Active Processes")
    table.add_column("PID")
    table.add_column("Name")
    table.add_column("CPU %")
    table.add_column("Memory (MB)")

    for p in processes:
        table.add_row(
            str(p.info['pid']),
            p.info['name'],
            str(p.info['cpu_percent']),
            str(round(p.info['memory_info'].rss /1024 /1024, 2))
        )

    console.print(table)


def show_processes():
    print("get active processes")

    processes = get_processes()
    hashes = []

    if processes:
        show_process_table(processes)

        for p in processes:
            filepath = get_filepath(p)
            # print(f"Filepath: {filepath}")

            if not filepath or  filepath.startswith(r"C:\Windows\System32"):
                continue

            filehash = get_filehash(filepath)
            hashes.append(filehash)
            print(f"Hash Value: {filehash}")

    else:
        print("nothing")

    # print(f"Anzahl Hashes: {len(hashes)}")

    if hashes:
        compare_hashes(hashes)






def get_virustotal_info(file_hash):
    # API ansprechen
    print("Hier findet der API Request statt")
    print(f"Filehash: {file_hash}")

if __name__ == "__main__":

    show_processes()