import requests
from bs4 import BeautifulSoup
import json
import os
import argparse
from pathlib import Path
import re

GITHUB_API_URL = "https://api.github.com/repos/googleprojectzero/0days-in-the-wild/contents/0day-RCAs"
INTHEWILD_URL = "https://inthewild.io/feed"

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

def parse_google_project_zero(api_url):
    contents = fetch_directory_contents(api_url)
    cve_dict = {}

    for item in contents:
        if item['type'] == 'file' and item['name'].endswith('.md'):
            file_url = item['download_url']
            file_contents = fetch_file_contents(file_url)
            if file_contents:
                # Extract CVE IDs from the file contents
                cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', file_contents)
                for cve_id in cve_ids:
                    if cve_id not in cve_dict:
                        cve_dict[cve_id] = {"id": cve_id, "sources": ["googleprojectzero"]}
                    elif "googleprojectzero" not in cve_dict[cve_id]["sources"]:
                        cve_dict[cve_id]["sources"].append("googleprojectzero")
        elif item['type'] == 'dir':
            new_api_url = item['url']
            sub_cve_dict = parse_google_project_zero(new_api_url)
            for cve_id, cve_data in sub_cve_dict.items():
                if cve_id not in cve_dict:
                    cve_dict[cve_id] = cve_data
                else:
                    for source in cve_data["sources"]:
                        if source not in cve_dict[cve_id]["sources"]:
                            cve_dict[cve_id]["sources"].append(source)

    return cve_dict

def parse_inthewild():
    response = requests.get(INTHEWILD_URL)
    cve_dict = {}

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tag = soup.find('script', {'id': '__NEXT_DATA__'})

        if script_tag:
            json_data = script_tag.string
            data = json.loads(json_data)
            recent_vulns = data.get('props', {}).get('pageProps', {}).get('recentVulns', [])
            for vuln in recent_vulns:
                cve_id = vuln.get('id')
                if cve_id not in cve_dict:
                    cve_dict[cve_id] = {"id": cve_id, "sources": ["inthewild.io"]}
                elif "inthewild.io" not in cve_dict[cve_id]["sources"]:
                    cve_dict[cve_id]["sources"].append("inthewild.io")
        else:
            print("JSON data not found in the <script> tag.")
    else:
        print(f"Failed to retrieve data from inthewild.io. Status code: {response.status_code}")

    return cve_dict

def process_cve_data(base_dir):
    cve_json_path = base_dir / "combined_cve_data.json"

    # Fetch CVE data from Google Project Zero
    cve_dict = parse_google_project_zero(GITHUB_API_URL)

    # Fetch CVE data from inthewild.io
    inthewild_cve_dict = parse_inthewild()

    # Combine the data from both sources, ensuring no duplicates and capturing all sources
    for cve_id, cve_data in inthewild_cve_dict.items():
        if cve_id not in cve_dict:
            cve_dict[cve_id] = cve_data
        else:
            for source in cve_data["sources"]:
                if source not in cve_dict[cve_id]["sources"]:
                    cve_dict[cve_id]["sources"].append(source)

    # Convert the dictionary to a list of CVE data
    combined_cve_list = list(cve_dict.values())

    # Save the combined CVE data to the JSON file
    with open(cve_json_path, 'w') as cve_id_file:
        json.dump(combined_cve_list, cve_id_file, indent=4)

    print(f"Combined CVE data has been updated and saved to {cve_json_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Google Project Zero and inthewild.io CVE Fetcher")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the combined CVE data')

    args = parser.parse_args()

    # Define the path to the 'wild' directory where the JSON file will be stored
    base_dir = Path(args.path) / "wild"
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Process and save the CVE data
    process_cve_data(base_dir)
