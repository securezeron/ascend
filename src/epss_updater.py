import os
import requests
import hashlib
import time
import gzip
import argparse
from pathlib import Path

EPSS_FEED_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

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

def extract_gz(gz_path, dest_path):
    with gzip.open(gz_path, 'rb') as f_in:
        with open(dest_path, 'wb') as f_out:
            f_out.write(f_in.read())

def process_epss_feed(base_dir):
    epss_dir = Path(base_dir) / "epss"
    epss_dir.mkdir(parents=True, exist_ok=True)
    
    gz_dest_path = epss_dir / "epss_scores-current.csv.gz"
    csv_dest_path = epss_dir / "epss_scores-current.csv"
    
    if gz_dest_path.exists():
        old_md5 = get_md5(gz_dest_path)
        download_feed(EPSS_FEED_URL, gz_dest_path)
        new_md5 = get_md5(gz_dest_path)
        if old_md5 == new_md5:
            print(f"{gz_dest_path.name} is up to date.")
            return
    else:
        download_feed(EPSS_FEED_URL, gz_dest_path)
        
    extract_gz(gz_dest_path, csv_dest_path)
    print(f"{csv_dest_path.name} updated and extracted.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EPSS Feed Updater")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the EPSS feed')
    parser.add_argument('--time-unit', '-tu', type=str, choices=['s', 'm', 'h'], default='h', help='Time unit for the update interval (s=seconds, m=minutes, h=hours)')
    parser.add_argument('--time-interval', '-ti', type=int, default=6, help='Time interval for the update')

    args = parser.parse_args()

    time_multiplier = {'s': 1, 'm': 60, 'h': 3600}
    sleep_time = args.time_interval * time_multiplier[args.time_unit]

    base_dir = args.path

    while True:
        process_epss_feed(base_dir)
        time.sleep(sleep_time)
