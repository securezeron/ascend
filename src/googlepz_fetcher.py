import os
import json
import argparse
from pathlib import Path

def fetch_cve_from_file(json_file, cve_id):
    with open(json_file, 'r', encoding='utf-8') as f:
        cve_list = json.load(f)
        if cve_id in cve_list:
            return {"id": cve_id, "source": "googleprojectzero"}
    return None

def fetch_cve(base_dir, cve_id):
    base_dir = Path(base_dir) / "googleprojectzero"
    json_file = base_dir / "cve_ids.json"
    
    if json_file.exists():
        result = fetch_cve_from_file(json_file, cve_id)
        if result:
            return result
    return None

def fetch_multiple_cves(base_dir, cve_ids):
    results = {}
    for cve_id in cve_ids:
        cve_id = cve_id.strip()
        result = fetch_cve(base_dir, cve_id)
        if result:
            results[cve_id] = result
        else:
            results[cve_id] = "FALSE"
    return results

def read_cve_list(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Google Project Zero CVE Checker")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to the Google Project Zero data directory')
    parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
    parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')

    args = parser.parse_args()

    base_dir = args.path

    if args.cve:
        cve_info = fetch_cve(base_dir, args.cve)
        if cve_info:
            print(json.dumps(cve_info, indent=2))
        else:
            print("FALSE")
    elif args.json_file:
        with open(args.json_file, 'r') as f:
            cve_ids = json.load(f)
        cve_results = fetch_multiple_cves(base_dir, cve_ids)
        print(json.dumps(cve_results, indent=2))
    elif args.list_file:
        cve_ids = read_cve_list(args.list_file)
        cve_results = fetch_multiple_cves(base_dir, cve_ids)
        print(json.dumps(cve_results, indent=2))
    else:
        print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
