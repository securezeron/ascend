import os
import requests
import hashlib
import json
import argparse
from pathlib import Path

# URL for the CISA Known Exploited Vulnerabilities feed
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def download_feed(url, dest_path):
    response = requests.get(url)
    response.raise_for_status()
    with open(dest_path, 'wb') as f:
        f.write(response.content)

def get_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def process_cisa_kev_feed(base_dir):
    kev_dir = Path(base_dir) / "cisa_kev"
    kev_dir.mkdir(parents=True, exist_ok=True)
    
    json_dest_path = kev_dir / "known_exploited_vulnerabilities.json"
    
    if json_dest_path.exists():
        old_md5 = get_md5(json_dest_path)
        download_feed(CISA_KEV_URL, json_dest_path)
        new_md5 = get_md5(json_dest_path)
        if old_md5 == new_md5:
            print(f"{json_dest_path.name} is up to date.")
            return
        else:
            print(f"{json_dest_path.name} has been updated.")
    else:
        download_feed(CISA_KEV_URL, json_dest_path)
        print(f"{json_dest_path.name} has been downloaded.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CISA Known Exploited Vulnerabilities Feed Updater")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the CISA KEV feed')

    args = parser.parse_args()

    base_dir = args.path

    process_cisa_kev_feed(base_dir)
