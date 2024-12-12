import os
import csv
import argparse
from pathlib import Path
import json

def fetch_epss_from_file(csv_file, cve_id):
    with open(csv_file, 'r', encoding='utf-8') as f:
        # Skip the first line manually
        next(f)
        
        reader = csv.DictReader(f)
        
        for row in reader:
            if row['cve'] == cve_id:
                return row
    return None

def fetch_epss(base_dir, cve_id):
    base_dir = Path(base_dir) / "epss"
    csv_file = base_dir / "epss_scores-current.csv"
    
    if csv_file.exists():
        result = fetch_epss_from_file(csv_file, cve_id)
        if result:
            return result
    return None

def fetch_multiple_epss(base_dir, cve_ids):
    results = {}
    for cve_id in cve_ids:
        cve_id = cve_id.strip()
        result = fetch_epss(base_dir, cve_id)
        if result:
            results[cve_id] = result
        else:
            results[cve_id] = "CVE not found in EPSS feed."
    return results

def read_cve_list(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EPSS CVE Fetcher")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to the EPSS feed directory')
    parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
    parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')

    args = parser.parse_args()

    base_dir = args.path

    if args.cve:
        epss_info = fetch_epss(base_dir, args.cve)
        if epss_info:
            print(json.dumps(epss_info, indent=2))
        else:
            print("CVE not found in EPSS feed.")
    elif args.json_file:
        with open(args.json_file, 'r') as f:
            cve_ids = json.load(f)
        epss_results = fetch_multiple_epss(base_dir, cve_ids)
        print(json.dumps(epss_results, indent=2))
    elif args.list_file:
        cve_ids = read_cve_list(args.list_file)
        epss_results = fetch_multiple_epss(base_dir, cve_ids)
        print(json.dumps(epss_results, indent=2))
    else:
        print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
