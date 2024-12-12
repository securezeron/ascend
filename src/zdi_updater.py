import os
import requests
import hashlib
import argparse
from pathlib import Path
from datetime import datetime

# Base URL for ZDI RSS feeds by year
ZDI_RSS_URL_TEMPLATE = "https://www.zerodayinitiative.com/rss/published/{year}/"

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

def process_zdi_rss_feeds(base_dir, start_year=2005):
    current_year = datetime.now().year
    zdi_dir = Path(base_dir) / "zdi_rss_feeds"
    zdi_dir.mkdir(parents=True, exist_ok=True)

    for year in range(start_year, current_year + 1):
        rss_url = ZDI_RSS_URL_TEMPLATE.format(year=year)
        rss_file_name = f"zdi_published_{year}.rss"
        rss_dest_path = zdi_dir / rss_file_name
        
        if rss_dest_path.exists():
            old_md5 = get_md5(rss_dest_path)
            download_feed(rss_url, rss_dest_path)
            new_md5 = get_md5(rss_dest_path)
            if old_md5 == new_md5:
                print(f"{rss_file_name} is up to date.")
            else:
                print(f"{rss_file_name} has been updated.")
        else:
            download_feed(rss_url, rss_dest_path)
            print(f"{rss_file_name} has been downloaded.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZDI RSS Feed Downloader and Updater")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the ZDI RSS feeds')

    args = parser.parse_args()

    base_dir = args.path

    process_zdi_rss_feeds(base_dir)
