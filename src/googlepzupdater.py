import os
import requests
import json
import time
import argparse
from pathlib import Path
import re

GITHUB_API_URL = "https://api.github.com/repos/googleprojectzero/0days-in-the-wild/contents/0day-RCAs"

def fetch_file_contents(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to retrieve file. Status code: {response.status_code}")
        return None

def fetch_directory_contents(api_url):
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve directory. Status code: {response.status_code}")
        return None

def parse_directory(api_url):
    contents = fetch_directory_contents(api_url)
    cve_ids = []

    for item in contents:
        if item['type'] == 'file' and item['name'].endswith('.md'):
            file_url = item['download_url']
            file_contents = fetch_file_contents(file_url)
            if file_contents:
                # Extract CVE IDs from the file contents
                cve_ids += re.findall(r'CVE-\d{4}-\d{4,7}', file_contents)
        elif item['type'] == 'dir':
            new_api_url = item['url']
            sub_cve_ids = parse_directory(new_api_url)
            cve_ids += sub_cve_ids

    return cve_ids

def process_google_project_zero_feed(base_dir):
    projectzero_dir = Path(base_dir) / "googleprojectzero"
    projectzero_dir.mkdir(parents=True, exist_ok=True)
    
    cve_json_path = projectzero_dir / "cve_ids.json"

    # Parse the directory and fetch CVE IDs
    cve_ids = parse_directory(GITHUB_API_URL)

    # Load existing CVE IDs from the JSON file
    if cve_json_path.exists():
        with open(cve_json_path, 'r') as cve_id_file:
            existing_cve_ids = set(json.load(cve_id_file))
    else:
        existing_cve_ids = set()

    # Add new CVE IDs to the existing set
    updated_cve_ids = sorted(existing_cve_ids.union(cve_ids))

    # Save the updated CVE IDs to the file
    with open(cve_json_path, 'w') as cve_id_file:
        json.dump(updated_cve_ids, cve_id_file, indent=4)

    print(f"CVE IDs have been updated and saved to {cve_json_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Google Project Zero CVE Fetcher")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the fetched CVE IDs')
    parser.add_argument('--time-unit', '-tu', type=str, choices=['s', 'm', 'h'], default='h', help='Time unit for the update interval (s=seconds, m=minutes, h=hours)')
    parser.add_argument('--time-interval', '-ti', type=int, default=6, help='Time interval for the update')

    args = parser.parse_args()

    time_multiplier = {'s': 1, 'm': 60, 'h': 3600}
    sleep_time = args.time_interval * time_multiplier[args.time_unit]

    base_dir = args.path

    while True:
        process_google_project_zero_feed(base_dir)
        time.sleep(sleep_time)
