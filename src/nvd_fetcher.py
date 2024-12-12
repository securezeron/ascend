# import os
# import json
# import argparse
# from pathlib import Path
# from concurrent.futures import ThreadPoolExecutor, as_completed

# def fetch_cve_from_file(json_file, cve_id):
#     with open(json_file, 'r', encoding='utf-8') as f:
#         data = json.load(f)
#         for item in data.get('CVE_Items', []):
#             if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == cve_id:
#                 return item
#     return None

# def fetch_cve(base_dir, cve_id):
#     base_dir = Path(base_dir) / "nvd"
#     year = cve_id.split('-')[1]
#     json_file = base_dir / f"nvdcve-1.1-{year}.json"
    
#     if json_file.exists():
#         result = fetch_cve_from_file(json_file, cve_id)
#         if result:
#             return result

#     # If not found in the specific year file, fall back to recent and modified files
#     json_files = [base_dir / "nvdcve-1.1-recent.json", base_dir / "nvdcve-1.1-modified.json"]
#     for json_file in json_files:
#         if json_file.exists():
#             result = fetch_cve_from_file(json_file, cve_id)
#             if result:
#                 return result

#     return None

# def fetch_multiple_cves(base_dir, cve_ids):
#     results = {}
#     with ThreadPoolExecutor(max_workers=4) as executor:  # Adjust number of threads as needed
#         tasks = {executor.submit(fetch_cve, base_dir, cve_id.strip()): cve_id.strip() for cve_id in cve_ids}
        
#         for future in as_completed(tasks):
#             cve_id = tasks[future]
#             result = future.result()
#             if result:
#                 results[cve_id] = result
#             else:
#                 results[cve_id] = "CVE not found."
#     return results

# def read_cve_list(file_path):
#     with open(file_path, 'r') as f:
#         return [line.strip() for line in f]

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="NVD CVE Fetcher")
#     parser.add_argument('--path', '-p', type=str, required=True, help='Path to the feeds directory')
#     parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
#     parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
#     parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')

#     args = parser.parse_args()

#     base_dir = args.path

#     if args.cve:
#         cve_info = fetch_cve(base_dir, args.cve)
#         if cve_info:
#             print(json.dumps(cve_info, indent=2))
#         else:
#             print("CVE not found.")
#     elif args.json_file:
#         with open(args.json_file, 'r') as f:
#             cve_ids = json.load(f)
#         cve_results = fetch_multiple_cves(base_dir, cve_ids)
#         print(json.dumps(cve_results, indent=2))
#     elif args.list_file:
#         cve_ids = read_cve_list(args.list_file)
#         cve_results = fetch_multiple_cves(base_dir, cve_ids)
#         print(json.dumps(cve_results, indent=2))
#     else:
#         print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")



import os
import json
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time

# Function to fetch CVE data from a JSON file
def fetch_cve_from_file(json_file, cve_id):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for item in data.get('CVE_Items', []):
            if item.get('cve', {}).get('CVE_data_meta', {}).get('ID') == cve_id:
                return item
    return None

# Function to fetch CVE data from local files and fallback to API if necessary
def fetch_cve(base_dir, cve_id):
    cve_details = {}
    base_dir = Path(base_dir) / "nvd"
    print(cve_id)
    year = cve_id.split('-')[1]
    json_file = base_dir / f"nvdcve-1.1-{year}.json"
    # Check the specific year file first
    if json_file.exists():
        result = fetch_cve_from_file(json_file, cve_id)
        if result and check_cvss_present(result):
            base_score = result['impact']['baseMetricV3']['cvssV3']['baseScore']
            exploitabilityScore = result['impact']['baseMetricV3']['exploitabilityScore']
            impactScore = result['impact']['baseMetricV3']['impactScore']
            # print(result['impact']['baseMetricV3']['impactScore'])
            cve_details['base_score'] = base_score
            cve_details['exploitabilityScore'] = exploitabilityScore
            cve_details['impactScore'] = impactScore
            # print(cve_details)
            return cve_details, result
    
    # Check recent and modified files as fallback
    json_files = [base_dir / "nvdcve-1.1-recent.json", base_dir / "nvdcve-1.1-modified.json"]
    for json_file in json_files:
        if json_file.exists():
            result = fetch_cve_from_file(json_file, cve_id)
            if result and check_cvss_present(result):
                print(result)
                return cve_details, result
    
    # If CVSS score is missing or CVE is not found, fetch from NVD API
    print(f"Fetching CVE {cve_id} from NVD API...")
    result = fetch_cve_from_nvd_api(cve_id)
    none_variable = (None, None)
    # print(none_variable)
    if result != none_variable:
        base_score = result['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        exploitabilityScore = result['metrics']['cvssMetricV31'][0]['exploitabilityScore']
        impactScore = result['metrics']['cvssMetricV31'][0]['impactScore']
        cve_details['base_score'] = base_score
        cve_details['exploitabilityScore'] = exploitabilityScore
        cve_details['impactScore'] = impactScore
    # print(cve_details)
    # result = json.loads(result)
        return cve_details , result


# Function to check if the CVSS score is present in the CVE data
def check_cvss_present(cve_data):
    return 'impact' in cve_data and 'baseMetricV3' in cve_data['impact']

# Function to fetch CVE data from the NVD API
def fetch_cve_from_nvd_api(cve_id):
    time.sleep(1)
    api_key = "05a8f790-23b4-47d7-8a00-2197168bbe17"  # Replace with your actual NVD API key
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key}

    response = requests.get(url, headers)
    if response.status_code == 200:
        data = response.json()
        if data and "vulnerabilities" in data:
            return data["vulnerabilities"][0]["cve"]  # Assuming the API returns a list of vulnerabilities
    else:
        print(f"Failed to fetch CVE {cve_id} from NVD API. Status code: {response.status_code}")
        return None, None
    
    return None

# Function to fetch multiple CVEs concurrently
def fetch_multiple_cves(base_dir, cve_ids, threads):
    results = {}
    scores = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:  # Adjust number of threads as needed
        tasks = {executor.submit(fetch_cve, base_dir, cve_id.strip()): cve_id.strip() for cve_id in cve_ids}
        
        for future in as_completed(tasks):
            cve_id = tasks[future]
            if future.result() != None:
                score, result = future.result()
                # print(score)
                if score:
                    # print(result['impact']['baseScore'])
                    scores[cve_id] = score
                if result:
                    # print(result['impact']['baseScore'])
                    results[cve_id] = result
                else:
                    results[cve_id] = "CVE not found."
            else:
                score, result = None, None

    # print(scores)
    return scores, results

# Function to read a list of CVEs from a file
def read_cve_list(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

# Main script execution
if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="NVD CVE Fetcher")
    # parser.add_argument('--path', '-p', type=str, required=True, help='Path to the feeds directory')
    # parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
    # parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    # parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')

    # args = parser.parse_args()

    # base_dir = args.path

    # if args.cve:
    #     cve_info = fetch_cve(base_dir, args.cve)
    #     if cve_info:
    #         print(json.dumps(cve_info, indent=2))
    #     else:
    #         print("CVE not found.")
    # elif args.json_file:
    #     with open(args.json_file, 'r') as f:
    #         cve_ids = json.load(f)
    #     cve_results = fetch_multiple_cves(base_dir, cve_ids)
    #     print(json.dumps(cve_results, indent=2))
    # elif args.list_file:
    #     cve_ids = read_cve_list(args.list_file)
    #     cve_results = fetch_multiple_cves(base_dir, cve_ids)
    #     print(json.dumps(cve_results, indent=2))
    # else:
    #     print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
    cve_ids = [
        "CVE-2023-1234",
        "CVE-2023-5678",
        "CVE-2022-0987",
        "CVE-2021-3456",
        "CVE-2023-52314",
        "CVE-2024-28200"
    ]
    base_dir = "/home/kali/Desktop/CVE-Weightage/VNR PRIOR/lake"
    fetch_multiple_cves(base_dir, cve_ids)