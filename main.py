import os
import threading
import queue
import requests
import json
import time
# from rich.live import Live
from rich.table import Table
from rich.console import Console
from dotenv import load_dotenv
from helper import get_processes, get_filepath, get_filehash, check_virustotal

load_dotenv()
vt_queue = queue.Queue()
console = Console()

API_KEY = os.getenv("API_KEY")


def vt_worker(api_key):
    while True:
        filehash, filepath = vt_queue.get()
        result = check_virustotal(filehash, api_key)
        with open('cache.json', 'r') as f:
            cache = json.load(f)
        cache[filehash] = result
        with open('cache.json', 'w') as f:
            json.dump(cache, f, indent=4)
        time.sleep(15) # 4 per minute
        vt_queue.task_done()

thread = threading.Thread(target=vt_worker, args=(API_KEY,), daemon=True)
thread.start()


def compare_hashes(files):
    print(f"Anzahl Hashes: {len(files)}")
    with open('cache.json', 'r') as f:
        cache = json.load(f)
    for file in files:
        # print(f"compare hash: {file["filehash"]}")
        if file["filehash"] in cache:
            result = cache[file["filehash"]]
        else:
            # if not in cache put in queue for api request
            vt_queue.put((file["filehash"], file["filepath"]))


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
    processes = get_processes()
    files = []
    if processes:
        show_process_table(processes)
        for p in processes:
            filepath = get_filepath(p)

            if not filepath or  filepath.startswith(r"C:\Windows\System32"):
                continue
            filehash = get_filehash(filepath)
            if filehash:
                files.append({"filepath": filepath, "filehash": filehash})
    else:
        print("nothing")

    if files:
        compare_hashes(files)


if __name__ == "__main__":
    while True:
        show_processes()
        time.sleep(60)  # Every minute scan again