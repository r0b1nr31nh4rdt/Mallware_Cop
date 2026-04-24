import psutil
import time
import hashlib
import json


def get_processes():
    return list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']))


def get_filepath(process):
    try:
        filepath = process.exe()
        # print(filepath)
        return filepath
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        print("(kein Zugriff)")



def get_filehash(filepath):
    # print(filepath)
    # print("Open File")
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        print("(kein Zugriff)")
    except TypeError as e:
        print(f"TypeError bei: {filepath}")
    except FileNotFoundError as e:
        print(f"FileNotFound bei: {filepath}")



def compare_hashes(filehashes):
    print(f"Anzahl Hashes: {len(filehashes)}")
    # print(f"compare hashes")
    # # read
    with open('cache.json', 'r') as f:
        cache = json.load(f)
    # compare
    for filehash in filehashes:
        print(f"compare hash: {filehash}")
        if filehash in cache:
            result = cache[filehash]
        else:
            # api request
            result = get_virustotal_info(filehash)
            cache[filehash] = result
            # add to cache if not yet inside
            with open('cache.json', 'w') as f:
                json.dump(cache, f)
        return result



def get_virustotal_info(filehash):
    # API ansprechen
    print("Hier findet der API Request statt")
    print(f"Filehash: {filehash}")
    return "dummyvalue"