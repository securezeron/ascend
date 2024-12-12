import argparse
import json
import os

def fetch_inthewild_from_file(cve_ids, path):
    # Construct the full path to the JSON file
    file_path = os.path.join(path, "cve_ids.json")  

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"File not found at {file_path}")
        return []

    # Open and read the JSON file
    with open(file_path, "r") as file:
        data = json.load(file)

    # Prepare a list to collect results
    results = []

    # Search for each CVE ID in the JSON data
    for cve_id in cve_ids:
        found = False
        for entry in data:
            if entry.get("id") == cve_id:
                results.append(entry)
                found = True
                break
        if not found:
            print(f"In the wild CVE ID {cve_id} not found in the JSON file.")

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="In the wild Fetcher")
    parser.add_argument('--cve', '-c', type=str, required=True, nargs='+', help='Input CVE-ID(s)')
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to the In the wild directory')
    args = parser.parse_args()
    base_dir = args.path

    if args.cve:
        inthewildinfo = fetch_inthewild_from_file(args.cve, args.path)
        if inthewildinfo:
            print(json.dumps(inthewildinfo, indent=2))
        else:
            print("No data fetched!")
    else:
        print("Please provide at least one CVE ID.")
