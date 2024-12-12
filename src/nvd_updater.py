import os
import requests
import hashlib
import json
import time
import gzip
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

NVD_FEED_URLS = {
    "recent": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
    "modified": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz",
    "base": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
}

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

def extract_gz(gz_path, json_path):
    with gzip.open(gz_path, 'rb') as f_in:
        with open(json_path, 'wb') as f_out:
            f_out.write(f_in.read())

def process_feed(url, gz_dest_path, json_dest_path):
    if gz_dest_path.exists():
        old_md5 = get_md5(gz_dest_path)
        download_feed(url, gz_dest_path)
        new_md5 = get_md5(gz_dest_path)
        if old_md5 == new_md5:
            print(f"{gz_dest_path.name} is up to date.")
            return
    else:
        download_feed(url, gz_dest_path)
    extract_gz(gz_dest_path, json_dest_path)
    print(f"{json_dest_path.name} updated and extracted.")

def update_feeds(base_dir, num_threads):
    base_dir = Path(base_dir) / "nvd"
    base_dir.mkdir(parents=True, exist_ok=True)

    tasks = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:  # Use specified number of threads
        for key, url in NVD_FEED_URLS.items():
            if key == "base":
                for year in range(2002, 2025):  # Adjust the range as needed
                    feed_url = url.format(year=year)
                    gz_file_name = f"nvdcve-1.1-{year}.json.gz"
                    json_file_name = f"nvdcve-1.1-{year}.json"
                    gz_dest_path = base_dir / gz_file_name
                    json_dest_path = base_dir / json_file_name
                    tasks.append(executor.submit(process_feed, feed_url, gz_dest_path, json_dest_path))
            else:
                gz_file_name = f"nvdcve-1.1-{key}.json.gz"
                json_file_name = f"nvdcve-1.1-{key}.json"
                gz_dest_path = base_dir / gz_file_name
                json_dest_path = base_dir / json_file_name
                tasks.append(executor.submit(process_feed, url, gz_dest_path, json_dest_path))
        
        for future in as_completed(tasks):
            future.result()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD Feed Updater")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store feeds')
    parser.add_argument('--time-unit', '-tu', type=str, choices=['s', 'm', 'h'], default='h', help='Time unit for the update interval (s=seconds, m=minutes, h=hours)')
    parser.add_argument('--time-interval', '-ti', type=int, default=6, help='Time interval for the update')
    parser.add_argument('--threads', '-t', type=int, default=4, help='Number of threads to use for downloading')

    args = parser.parse_args()

    time_multiplier = {'s': 1, 'm': 60, 'h': 3600}
    sleep_time = args.time_interval * time_multiplier[args.time_unit]

    base_dir = args.path
    num_threads = args.threads

    while True:
        update_feeds(base_dir, num_threads)
        time.sleep(sleep_time)
