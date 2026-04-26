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
import logging
from helper import (
    get_processes,
    get_filepath,
    get_filehash,
    check_virustotal,
    load_cache,
    get_badhash,
    kill_suspicious_process,
    init_cache,
    move_to_quarantine,
    suspend_process,
    memory_dump,
    get_process_hash
)

load_dotenv()
vt_queue = queue.Queue()
console = Console()

logging.basicConfig(
    filename='mallware_cop.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

API_KEY = os.getenv("API_KEY")
SUSPICIOUS_NAMES = ["virus.exe", "malware.exe", "ransomware.exe"]


def vt_worker(api_key):
    while True:
        filehash, filepath = vt_queue.get()
        result = check_virustotal(filehash, api_key)
        with open('cache.json', 'r') as f:
            cache = json.load(f)
        if result:
            result["filepath"] = filepath
            cache[filehash] = result
        else:
            cache[filehash] = {
                "malicious": None,
                "suspicious": None,
                "undetected": None,
                "reason": "not found on VirusTotal",
                "filepath": filepath
            }
        with open('cache.json', 'w') as f:
            json.dump(cache, f, indent=4)
        time.sleep(15) # 4 per minute
        vt_queue.task_done()

thread = threading.Thread(target=vt_worker, args=(API_KEY,), daemon=True)
thread.start()


def compare_hashes(files):
    # console.log(f"Anzahl Hashes: {len(files)}")
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

        filehash = get_process_hash(p, filepath)

        vt_result = cache.get(filehash) or {}

        # Table style
        memory_mb = p.info['memory_info'].rss / 1024 / 1024
        malicious_count = vt_result.get("malicious", 0)

        if malicious_count and malicious_count > 0:
            color = "red"
        elif memory_mb > 500:
            color = "yellow"
        else:
            color = "green"

        table.add_row(
            str(p.info['pid']),
            p.info['name'],
            str(p.info['cpu_percent']),
            str(round(p.info['memory_info'].rss /1024 /1024, 2)),
            str(malicious_count),
            style=color
        )
    return table


def collect_paths(processes):
    files = []
    for p in processes:
        filepath = get_filepath(p)
        if not filepath or  filepath.startswith(r"C:\Windows\System32"):
            continue

        filehash = get_process_hash(p, filepath)

        if filehash:
            files.append({"filepath": filepath, "filehash": filehash})
    if files:
        compare_hashes(files)


def apply_policy(processes, cache, handled_pids):
    for p in processes:
        # virus.exe
        if p.info['name'] in SUSPICIOUS_NAMES:
            filepath = get_filepath(p)
            logging.warning(f"Suspicious process detected: {p.info['name']} (PID {p.info['pid']})")
            kill_suspicious_process(p.info['pid'])
            logging.warning(f"Killed process: {p.info['name']} (PID {p.info['pid']})")
            if filepath:
                move_to_quarantine(filepath)
                logging.warning(f"Quarantined: {filepath}")

        # Memory > 500 MB
        memory_mb = p.info["memory_info"].rss /1024 /1024
        if memory_mb > 500:
            logging.warning(f"{p.info['name']} (PID {p.info['pid']}) uses {round(memory_mb, 2)}MB")

        # VirusTotal > 3 detections
        filepath = get_filepath(p)
        filehash = get_process_hash(p, filepath)
        vt_result = cache.get(filehash) or {}
        malicious_count = vt_result.get("malicious", 0) or 0

        if p.info['pid'] not in handled_pids and malicious_count > 3:
            handled_pids.add(p.info['pid'])
            logging.warning(f"VirusTotal detection: {p.info['name']} - {malicious_count} detections")
            memory_dump(p.info['pid'])
            suspend_process(p.info['pid'])
            logging.warning(f"Suspended: {p.info['name']} (PID {p.info['pid']})")
            if filepath:
                move_to_quarantine(filepath)
                logging.warning(f"Quarantined: {filepath}")


if __name__ == "__main__":

    handled_pids = set()

    with Live(refresh_per_second=1) as live:
        while True:
            init_cache()
            # Get processes, load Cache
            processes = get_processes()
            cache = load_cache()

            # Filter
            apply_policy(processes, cache, handled_pids)

            # Update table
            processes = sorted(processes, key=lambda p: p.info['memory_info'].rss, reverse=True)
            live.update(build_table(processes, cache))

            # Get paths, calculate hashs, actualize cache
            collect_paths(processes)

            time.sleep(5)