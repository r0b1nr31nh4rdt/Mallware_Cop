import psutil
import time
import hashlib
import json
import requests


def get_processes():
    return list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']))


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


def check_virustotal(filehash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{filehash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Fehler beim Abrufen der Daten: {response.status_code}")
        return None

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "undetected": stats["undetected"]
    }

