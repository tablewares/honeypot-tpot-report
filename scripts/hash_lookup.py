#!/usr/bin/python3

import os
import hashlib
import subprocess

import requests
import json
import sys
from datetime import datetime
import requests
import argparse

# ==============================
# CONFIGURATION
# ==============================

VT_API_KEY = "489e2074896c31304b5acf3aef1fa3deb62e2ff242d1ade1de5e1dad0746fdd6"
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
FILE_NAME = "scan_results.json"
LOG_FILE = f"/home/tools/{FILE_NAME}"
# Ensure directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


# ==============================
# CUSTOM SOURCE PORT ADAPTER
# ==============================


# ==============================
# VIRUSTOTAL QUERY
# ==============================

def query_virustotal(file_hash):
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/{file_hash}"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            return response.json()

        elif response.status_code == 404:
            return {"error": "not_found"}

        elif response.status_code == 429:
            return {"error": "rate_limited"}

        else:
            return {
                "error": "api_error",
                "status_code": response.status_code,
                "details": response.text
            }

    except requests.exceptions.RequestException as e:
        return {"error": "request_failed", "details": str(e)}


# ==============================
# LOGGING
# ==============================

def log_to_file(file_path, file_hash, vt_data):
    """Appends a single scan result as a JSON line for easy parsing."""

    entry = {
        "timestamp": datetime.now().isoformat(),
        "file_path": file_path,
        "hash": file_hash,
        "status": "Found" if vt_data and "data" in vt_data else "Not Found",
        "stats": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats") if vt_data else None,
        "full_response": vt_data
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ==============================
# HASHING
# ==============================

def compute_file_hash(file_path):
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] Failed to hash {file_path}: {e}")
        return None

# ==============================
# DIRECTORY SCAN (UPDATED)
# ==============================

def scan_directory(directory, use_hash=False):
    if not os.path.isdir(directory):
        print("[!] Invalid directory.")
        return

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            if use_hash:
                file_hash = compute_file_hash(file_path)
            else:
                file_hash = os.path.basename(file_path)

            if not file_hash:
                continue

            print(f"[*] Processing: {file}")
            vt_data = query_virustotal(file_hash)
            log_to_file(file_path, file_hash, vt_data)

# ==============================
# SINGLE FILE PROCESSING
# ==============================

def scan_single_file(directory, filename, use_hash=False):
    file_path = os.path.join(directory, filename)

    if not os.path.isfile(file_path):
        print("[!] File not found.")
        return

    if use_hash:
        file_hash = compute_file_hash(file_path)
    else:
        file_hash = filename

    if not file_hash:
        return

    print(f"[*] Processing single file: {filename}")
    vt_data = query_virustotal(file_hash)
    log_to_file(file_path, file_hash, vt_data)


# ==============================
# MAIN (REPLACED)
# ==============================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal Scanner")

    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--hash", action="store_true",
                        help="Compute file hash instead of using filename")
    parser.add_argument("-o", "--output", help="Output file")
    args = parser.parse_args()

    if args.output:
        FILE_NAME = args.output
        LOG_FILE = f"/home/tools/{FILE_NAME}"  # or rebuild full path if needed

    if args.hash:
        scan_directory(args.directory, args.hash)
    else:
        scan_directory(args.directory)

    print(f"\n[+] Scan complete. Results saved to {LOG_FILE}")
