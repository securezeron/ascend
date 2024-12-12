import json
import argparse
from pathlib import Path

def load_kev_data(kev_file):
    if kev_file.exists():
        with open(kev_file, 'r') as f:
            return json.load(f)
    else:
        print(f"Error: KEV file not found at {kev_file}")
        return None

def check_cve_in_kev(kev_data, cve_id):
    for entry in kev_data.get("vulnerabilities", []):
        if entry.get("cveID") == cve_id:
            return entry
    return None

def check_multiple_cves_in_kev(kev_data, cve_ids):
    results = {}
    for cve_id in cve_ids:
        cve_id = cve_id.strip()
        result = check_cve_in_kev(kev_data, cve_id)
        if result:
            results[cve_id] = result
        else:
            results[cve_id] = "CVE not found in CISA KEV feed."
    return results

def read_cve_list(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check if a CVE is in the CISA Known Exploited Vulnerabilities feed")
    parser.add_argument('--kev-path', '-kp', type=str, required=True, help='Path to the CISA KEV JSON file')
    parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to check')
    parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')

    args = parser.parse_args()

    kev_file = Path(args.kev_path) / "cisa_kev" / "known_exploited_vulnerabilities.json"
    kev_data = load_kev_data(kev_file)

    if not kev_data:
        exit(1)

    if args.cve:
        result = check_cve_in_kev(kev_data, args.cve)
        if result:
            print(f"CVE {args.cve} found in CISA KEV feed:")
            print(json.dumps(result, indent=4))
        else:
            print(f"CVE {args.cve} not found in CISA KEV feed.")
    elif args.json_file:
        with open(args.json_file, 'r') as f:
            cve_ids = json.load(f)
        results = check_multiple_cves_in_kev(kev_data, cve_ids)
        print(json.dumps(results, indent=4))
    elif args.list_file:
        cve_ids = read_cve_list(args.list_file)
        results = check_multiple_cves_in_kev(kev_data, cve_ids)
        print(json.dumps(results, indent=4))
    else:
        print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
