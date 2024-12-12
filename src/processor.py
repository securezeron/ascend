import json
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from nvd_fetcher import fetch_cve  # Import the fetch_cve function from nvd_fetcher

def load_config(config_path="config.json"):
    """
    Load configuration from the specified JSON file.
    
    Args:
        config_path (str): The path to the config file.
        
    Returns:
        dict: The loaded configuration.
    """
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)
    return config

def process_single_cve(base_dir, cve_id):
    """
    Process a single CVE ID by fetching its data from the NVD database.
    
    Args:
        base_dir (str): The directory containing the NVD JSON files.
        cve_id (str): The CVE ID to fetch.

    Returns:
        dict: The fetched CVE data or a message if the CVE was not found.
    """
    result = fetch_cve(base_dir, cve_id)
    if result:
        return result
    else:
        return {"error": f"CVE {cve_id} not found."}

def process_multiple_cves(base_dir, cve_ids, max_workers):
    """
    Process multiple CVE IDs by fetching their data from the NVD database.
    
    Args:
        base_dir (str): The directory containing the NVD JSON files.
        cve_ids (list): A list of CVE IDs to fetch.
        max_workers (int): The number of threads to use for concurrent processing.

    Returns:
        dict: A dictionary with CVE IDs as keys and their fetched data or error messages as values.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = {executor.submit(process_single_cve, base_dir, cve_id.strip()): cve_id.strip() for cve_id in cve_ids}
        
        for future in as_completed(tasks):
            cve_id = tasks[future]
            result = future.result()
            results[cve_id] = result
            
    return results

def read_cve_list(file_path):
    """
    Read a list of CVE IDs from a text file.
    
    Args:
        file_path (str): The path to the file containing CVE IDs.

    Returns:
        list: A list of CVE IDs.
    """
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Processor")
    parser.add_argument('--cve', '-c', type=str, help='Single CVE ID to fetch')
    parser.add_argument('--json-file', '-jf', type=str, help='Path to a JSON file containing a list of CVE IDs')
    parser.add_argument('--list-file', '-lf', type=str, help='Path to a text file with a list of CVE IDs (one per line)')
    parser.add_argument('--config', '-cfg', type=str, default='config.json', help='Path to the config file (default: config.json)')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    base_dir = config['nvd_data_path']
    max_workers = config.get('max_workers', 4)

    if args.cve:
        print(f"Processing single CVE: {args.cve}")
        cve_info = process_single_cve(base_dir, args.cve)
        print(json.dumps(cve_info, indent=2))
        
    elif args.json_file:
        print(f"Processing CVEs from JSON file: {args.json_file}")
        with open(args.json_file, 'r') as f:
            cve_ids = json.load(f)
        cve_results = process_multiple_cves(base_dir, cve_ids, max_workers)
        print(json.dumps(cve_results, indent=2))
        
    elif args.list_file:
        print(f"Processing CVEs from list file: {args.list_file}")
        cve_ids = read_cve_list(args.list_file)
        cve_results = process_multiple_cves(base_dir, cve_ids, max_workers)
        print(json.dumps(cve_results, indent=2))
        
    else:
        print("Please provide a single CVE ID, a JSON file, or a list file with CVE IDs.")
