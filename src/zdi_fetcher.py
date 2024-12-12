import os
import re
import json
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET
from html import unescape

def parse_rss_feed(file_path, debug=False):
    try:
        if debug:
            print(f"[DEBUG] Parsing RSS feed: {file_path}")
        tree = ET.parse(file_path)
        root = tree.getroot()

        advisories = []

        # Regular expression pattern to find CVE IDs
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')

        for item in root.findall('.//item'):
            title = item.find('title').text if item.find('title') else 'No title found'
            link = item.find('link').text if item.find('link') else 'No link found'
            description_element = item.find('description')
            
            if description_element is not None:
                description = description_element.text
            else:
                description = 'No description found'
            
            if debug:
                print(f"[DEBUG] Found item with title: {title}")
                print(f"[DEBUG] Raw description: {description}")

            # Unescape HTML entities and remove any surrounding CDATA
            description = unescape(description)

            if debug:
                print(f"[DEBUG] Processed description: {description}")

            # Search for CVE IDs in the description
            cve_ids = cve_pattern.findall(description)
            if debug:
                print(f"[DEBUG] Found CVE IDs: {cve_ids}")

            for cve_id in cve_ids:
                advisories.append({
                    "title": title,
                    "cve_id": cve_id,
                    "link": link,
                    "description": description
                })
        
        if debug:
            print(f"[DEBUG] Total advisories found in {file_path}: {len(advisories)}")
        return advisories
    except Exception as e:
        print(f"[ERROR] Error parsing RSS feed {file_path}: {e}")
        return []

def fetch_cve_from_zdi(cve_id, rss_feeds_dir, debug=False):
    advisories = []
    rss_feeds_dir = Path(rss_feeds_dir)

    if debug:
        print(f"[DEBUG] Searching for CVE {cve_id} in RSS feeds located at {rss_feeds_dir}")

    for rss_file in rss_feeds_dir.glob("*.rss"):
        if debug:
            print(f"[DEBUG] Checking RSS file: {rss_file}")
        advisories_in_file = parse_rss_feed(rss_file, debug)
        for advisory in advisories_in_file:
            if advisory['cve_id'] == cve_id:
                if debug:
                    print(f"[DEBUG] Match found for CVE {cve_id} in file {rss_file}")
                advisories.append(advisory)
    
    if debug:
        print(f"[DEBUG] Total advisories found for CVE {cve_id}: {len(advisories)}")
    return advisories

def fetch_multiple_cves_from_zdi(cve_ids, rss_feeds_dir, debug=False):
    results = {}
    if debug:
        print(f"[DEBUG] Fetching multiple CVEs from ZDI RSS feeds...")
    for cve_id in cve_ids:
        cve_id = cve_id.strip()
        if debug:
            print(f"[DEBUG] Fetching advisories for CVE {cve_id}")
        advisories = fetch_cve_from_zdi(cve_id, rss_feeds_dir, debug)
        if advisories:
            results[cve_id] = advisories
        else:
            if debug:
                print(f"[DEBUG] CVE {cve_id} not found in any RSS feeds.")
            results[cve_id] = "CVE not found in ZDI advisories."
    return results

def read_cve_list(file_path, debug=False):
    if debug:
        print(f"[DEBUG] Reading CVE list from file: {file_path}")
    with open(file_path, 'r') as f:
        cve_list = [line.strip() for line in f]
    if debug:
        print(f"[DEBUG] Total CVEs read: {len(cve_list)}")
    return cve_list

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch CVE information from ZDI RSS Feeds")
    parser.add_argument('--rss-path', '-rp', type=str, required=True, help='Path to the directory containing ZDI RSS feeds')
    parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
    parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug output')

    args = parser.parse_args()

    rss_feeds_dir = args.rss_path
    debug = args.debug

    if args.cve:
        if debug:
            print(f"[DEBUG] Fetching advisories for single CVE: {args.cve}")
        result = fetch_cve_from_zdi(args.cve, rss_feeds_dir, debug)
        if result:
            print(f"CVE {args.cve} found in ZDI advisories:")
            print(json.dumps(result, indent=4))
        else:
            print(f"CVE {args.cve} not found in ZDI advisories.")
    elif args.json_file:
        if debug:
            print(f"[DEBUG] Fetching advisories for CVEs listed in JSON file: {args.json_file}")
        with open(args.json_file, 'r') as f:
            cve_ids = json.load(f)
        results = fetch_multiple_ces_fromv_zdi(cve_ids, rss_feeds_dir, debug)
        print(json.dumps(results, indent=4))
    elif args.list_file:
        if debug:
            print(f"[DEBUG] Fetching advisories for CVEs listed in text file: {args.list_file}")
        cve_ids = read_cve_list(args.list_file, debug)
        results = fetch_multiple_cves_from_zdi(cve_ids, rss_feeds_dir, debug)
        print(json.dumps(results, indent=4))
    else:
        print("[ERROR] Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
