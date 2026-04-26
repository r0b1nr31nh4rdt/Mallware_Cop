# helper.py

import psutil
import time
import hashlib
import json
import requests
from rich.console import Console
import os
import shutil
import subprocess

console = Console()

def get_processes():
    return list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']))


def load_cache():
    try:
        with open('cache.json', 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def init_cache():
    if not os.path.exists('cache.json'):
        with open('cache.json', 'w') as f:
            json.dump({}, f)


def get_filepath(process):
    try:
        filepath = process.exe()
        return filepath
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None


def get_filehash(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return None
    except (TypeError, FileNotFoundError, PermissionError) as e:
        return None


def get_badhash():
    return hashlib.sha256(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode()).hexdigest()


def get_process_hash(p, filepath):
    if p.info['name'] == "badhash.exe":
        return get_badhash()
    return get_filehash(filepath) if filepath else None



def check_virustotal(filehash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        console.log(f"Error while fetching data: {response.status_code}")
        return None

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "undetected": stats["undetected"]
    }


def kill_suspicious_process(pid):
    # try to get and kill parent processes - childs get killed with them
    try:
        proc = psutil.Process(pid)
        parent = proc.parent()
        if parent and parent.pid > 4:  # PID 0 and 4 are system processes
            parent.kill()
        else:
            proc.kill()  # if no parent found, kill process itself
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass


def move_to_quarantine(filepath):
    if os.path.exists(filepath):
        os.makedirs("quarantine", exist_ok=True)
        shutil.move(filepath, "quarantine/")
    else:
        console.log("File not found")


def suspend_process(pid):
    proc = psutil.Process(pid)
    proc.suspend()

def memory_dump(pid):
    os.makedirs("dumps", exist_ok=True)
    subprocess.run(["procdump.exe", "-ma", str(pid), "dumps/"])