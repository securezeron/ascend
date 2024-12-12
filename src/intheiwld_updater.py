import requests
from bs4 import BeautifulSoup
import json
import os
import argparse
from pathlib import Path

def fetch_and_save_cve_data(temp_file):
    # Define the URL for the request
    url = "https://inthewild.io/feed"

    # Make a GET request to the website
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the <script> tag containing the JSON data
        script_tag = soup.find('script', {'id': '__NEXT_DATA__'})

        if script_tag:
            # Extract the JSON data from the <script> tag
            json_data = script_tag.string

            # Parse the JSON data
            data = json.loads(json_data)

            # Extract only the CVE IDs and add the source tag
            recent_vulns = data.get('props', {}).get('pageProps', {}).get('recentVulns', [])
            cve_ids = [{"id": vuln.get('id'), "source": "inthewild.io"} for vuln in recent_vulns]

            # Create the 'inthewild' directory if it doesn't exist
            os.makedirs(os.path.dirname(temp_file), exist_ok=True)

            # Load existing CVE IDs from the JSON file
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as cve_id_file:
                    existing_cve_ids = json.load(cve_id_file)
            else:
                existing_cve_ids = []

            # Create a set of existing CVE IDs for quick lookup
            existing_cve_set = {entry['id'] for entry in existing_cve_ids}

            # Add new CVE IDs to the existing list if they don't already exist
            for cve in cve_ids:
                if cve['id'] not in existing_cve_set:
                    existing_cve_ids.append(cve)

            # Save the updated CVE IDs to the file
            with open(temp_file, 'w') as cve_id_file:
                json.dump(existing_cve_ids, cve_id_file, indent=4)

            print(f"CVE IDs have been updated and saved to {temp_file}")
        else:
            print("JSON data not found in the <script> tag.")
    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="inthewild.io CVE Fetcher")
    parser.add_argument('--path', '-p', type=str, required=True, help='Path to store the fetched CVE data')

    args = parser.parse_args()

    # Define the path to the 'inthewild' directory inside the given base directory
    base_dir = Path(args.path) / "inthewild"
    
    # Define the path to the JSON file where the CVE data will be stored inside the 'inthewild' directory
    temp_file = base_dir / "cve_ids.json"

    # Fetch and save the CVE data
    fetch_and_save_cve_data(temp_file)
