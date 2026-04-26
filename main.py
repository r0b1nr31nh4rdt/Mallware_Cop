# main.py

import os
import threading
import queue
import requests
import json
import time
from rich.live import Live
from rich.table import Table
from rich.console import Console
from dotenv import load_dotenv
from helper import get_processes, get_filepath, get_filehash, check_virustotal, load_cache

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
        if result:
            cache[filehash] = result
        else:
            cache[filehash] = {
                "malicious": None,
                "suspicious": None,
                "undetected": None,
                "reason": "not found on VirusTotal"
            }
        with open('cache.json', 'w') as f:
            json.dump(cache, f, indent=4)
        time.sleep(15) # 4 per minute
        vt_queue.task_done()

thread = threading.Thread(target=vt_worker, args=(API_KEY,), daemon=True)
thread.start()


def compare_hashes(files):
    console.log(f"Anzahl Hashes: {len(files)}")
    with open('cache.json', 'r') as f:
        cache = json.load(f)
    for file in files:
        if file["filehash"] in cache:
            result = cache[file["filehash"]]
        else:
            vt_queue.put((file["filehash"], file["filepath"]))


def build_table(processes, cache):
    table = Table(title = "Active Processes")
    table.add_column("PID")
    table.add_column("Name")
    table.add_column("CPU %")
    table.add_column("Memory (MB)")
    table.add_column("Malicious")

    for p in processes:
        filepath = get_filepath(p)
        if not filepath or  filepath.startswith(r"C:\Windows\System32"):
            continue
        filehash = get_filehash(filepath) if filepath else None
        vt_result = cache.get(filehash) or {}
        malicious = str(vt_result.get("malicious"))
        color = "red" if vt_result.get("malicious", 0) and vt_result.get("malicious", 0) > 0 else "green"

        table.add_row(
            str(p.info['pid']),
            p.info['name'],
            str(p.info['cpu_percent']),
            str(round(p.info['memory_info'].rss /1024 /1024, 2)),
            malicious,
            style=color
        )
    return table


def collect_paths(processes):
    files = []
    for p in processes:
        filepath = get_filepath(p)
        if not filepath or  filepath.startswith(r"C:\Windows\System32"):
            continue
        filehash = get_filehash(filepath)
        if filehash:
            files.append({"filepath": filepath, "filehash": filehash})
    if files:
        compare_hashes(files)


if __name__ == "__main__":
    with Live(refresh_per_second=1) as live:
        while True:
            # Get processes, load Cache, update table
            processes = get_processes()
            cache = load_cache()
            live.update(build_table(processes, cache))

            # Get paths, calculate hashs, actualize cache
            collect_paths(processes)

            time.sleep(60)  # Every minute scan again

    # # Test
    # eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    # result = check_virustotal(eicar_hash, API_KEY)
    # print(result)