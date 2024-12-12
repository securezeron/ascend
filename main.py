import src.nvd_fetcher as get_nvd
import src.epss_fetcher as get_epss
import src.zdi_fetcher as get_zdi
import src.cisa_kev_fetcher as get_cisa_kev
import src.googlepz_fetcher as get_google_pz
import src.inthewild_fetcher as get_inthewild 
import src.fetch_ttp_from_cwe as ttp_cwe
import src.fetch_advisories_from_ttp as adv_ttp
import json
from pathlib import Path
import argparse
from pathlib import Path
import time


""" Total Fetchers
1. CISA Fetcher
2. EPSS Fetcher
3. Fetch TTP From CWE
4. Googlepz Fetcher
5. NVD Fetcher
6. ZDI Fetcher
"""
results = []
def extractor_nvd(cve, nvd_results):
    # # Attack_Vector=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['attackVector']
    # # Attack_Complexity=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['attackComplexity']
    # # Privileges_Required=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
    # # User_Interaction=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['userInteraction']
    # # Confidentiality_Impact=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
    # # Integrity_Impact=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['integrityImpact']
    # # Availability_Impact=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
    # # Scope=nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['scope']

    # Exploitability_Sub_Score = nvd_results[cve]['impact']['baseMetricV3']['exploitabilityScore'] #need
    # Impact_Sub_Score = nvd_results[cve]['impact']['baseMetricV3']['impactScore'] #need
    # Temporal_Score = nvd_results[cve]['impact']['baseMetricV3']['cvssV3']['baseScore'] # As there is no temporal score and it depends on env
    # print(nvd_results)
    # try:
    val = nvd_results.get(cve)
    cves_found = list(nvd_results.keys())
    print(cves_found)
    cve = cve.lstrip()
    cve = cve.rstrip()
    if cve in cves_found:
        # print(cve.rstrip())
        # print(type(nvd_results))
        Base_Score = nvd_results[cve]['base_score']
        Exploitability_Sub_Score = nvd_results[cve]['exploitabilityScore']
        Impact_Sub_Score = nvd_results[cve]['impactScore']
        Temporal_Score = nvd_results[cve]['base_score'] # As there is no temporal score and it depends on env
        # print("\n\n", Base_Score)
        print(Base_Score, "\n\n", Exploitability_Sub_Score, "\n\n", Impact_Sub_Score, "\n\n", Temporal_Score)
        return Base_Score, Exploitability_Sub_Score, Impact_Sub_Score, Temporal_Score
    else:
        print(f"{cve_id} not in NVD")
        return None, None, None, None
    # except Exception as e:
    #     print(e)
    #     return None, None, None, None


    # print(nvd_results)
    # print(json.dumps(nvd_results[cve],indent=2))
    # print('~'*20)
    # print(Exploitability_Sub_Score)
    # return Exploitability_Sub_Score, Impact_Sub_Score, Temporal_Score
    # print(nvd_results)
    
#--------------------------------------------------------------------------------------------------------------------------------

def extractor_number_cpe(cve_id, nvd_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    cve_cpe_counts = {}
    list_example = [1, 2]
    cve_info = nvd_results.get(cve_id, {})
    configurations = cve_info.get('configurations', {})
    # print(nvd_results[cve_id]['configurations'])
    # print(configurations)
    # print("*"*80)
    # print(type(configurations))
    if type(configurations) != type(list_example):
        nodes = configurations.get('nodes', [])
    else:
        nodes = configurations
    cpe_count = 0
    for node in nodes:
        cpe_count += len(node.get('cpe_match', []))
        for child in node.get('children', []):
            cpe_count += len(child.get('cpe_match', []))
    cve_cpe_counts[cve_id] = cpe_count
    # print(cve_cpe_counts)
    impact = calc_cpe_impact(cve_id, cve_cpe_counts)
    return impact
    

def calc_cpe_impact(cve_id, num_cpe):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    num = num_cpe.get(cve_id)
    if num == None:
        num = 0
    impact = 1 - (1/(1+num))
    print(f"Impact of the CPE is: {impact}")
    return impact
#--------------------------------------------------------------------------------------------------------------------------------

def extractor_number_cwe(cve_id, nvd_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    cve_cwe_counts = {}
    cwe_names = []

    # Extract the CVE information from the provided nvd_results
    cve_info = nvd_results.get(cve_id, {})
    problemtype = cve_info.get('cve', {}).get('problemtype', {})
    problemtype_data = problemtype.get('problemtype_data', [])
    
    cwe_count = 0

    # Iterate through the problemtype_data to count the CWEs
    for entry in problemtype_data:
        cwe_count += len(entry.get('description', []))
        # print(entry.get('description', []))
        cwe_details = entry.get('description', [])
        # cwe_name = cwe_details.get('value')
        for i in cwe_details:
            cwe_name = i.get('value')
            # print(cwe_name)
            if cwe_name == 'NVD-CWE-noinfo':
                cwe_count +=1
                cwe_names.append(cwe_name)
            else:
                cwe_count +=1
                # extractor_advisories(cwe_name)
                cwe_names.append(cwe_name)
                pass

    # Store the count in the dictionary
    cve_cwe_counts[cve_id] = cwe_names
    
    # Print the result (for debugging purposes)
    # print(cve_cwe_counts)
    
    # Call the calc_cwe_impact function with the results
    impact = calc_cwe_impact(cve_id, cve_cwe_counts)
    # print(cve_cwe_counts)
    return cve_cwe_counts, impact

    return cve_cwe_counts


def calc_cwe_impact(cve_id, num_cwe):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    num = len(num_cwe.get(cve_id))
    # print(num)
    impact = 1 - (1/(1+num))
    # print(f"Impact of the CWE is: {impact}")
    return impact
#--------------------------------------------------------------------------------------------------------------------------------


def extractor_advisories(cve_id, cwe_data):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    total_count = 0
    #ADVISORIES FROM CWE
    # cwe_id = "CWE-78"
    combined_advisories = []
    # print(cwe_data)
    # print(type(cwe_data))
    cwes_names = cwe_data[cve_id]
    for i in cwes_names:
        if i == 'NVD-CWE-noinfo':
            pass
        else:
            # print(cwes_names)
            
            cwe_id = i
            links_to_follow = ttp_cwe.main(cwe_id)
            #print(links_to_follow)

            for link in links_to_follow:
                advisories = adv_ttp.main(link)
                # print(advisories)
                combined_advisories.append(advisories)
                # print(combined_advisories)

            for advisories in combined_advisories:
                adv = json.loads(advisories)
                adv_count = adv.get('total_count')
                total_count += int(adv_count)
                # print(adv.get('total_count'))
    # print(combined_advisories)
    # print(f"The total number of Advisories associated with {cve_id} is: {total_count}")
    impact = calc_advisories_impact(cve_id, total_count)
    return impact

def calc_advisories_impact(cve_id, total_num_adv):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    num = total_num_adv
    impact = 1 - (1/(1+num))
    # print(f"Impact of the Advisories for {cve_id} is: {impact}")
    return impact

    
#--------------------------------------------------------------------------------------------------------------------------------

def extractor_epss(cve_id, epss_json_result):
    # print(epss_json_result)
    # print(cve_id)
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    epss_json_result=json.loads(epss_json_result)
    if cve_id in epss_json_result:
        epss = epss_json_result[cve_id]["epss"]
        # print(epss)
        epss_percentile = epss_json_result[cve_id]["percentile"]
        # print(epss_percentile)
        return epss, epss_percentile
    else:
        return None, None

def extractor_zdi(cve_id, zdi_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    # print(cve_id)
    is_present = zdi_results[cve_id]
    if is_present == 'CVE not found in ZDI advisories.':
        return False
    else:
        return True
    # print(is_present, "\n")

def extractor_kev(cve_id, kev_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    # print("The next 2 is kev")
    # print(cve_id)
    print(kev_results[cve_id])
    return kev_results[cve_id]


def extractor_google_pz(cve_id, google_pz_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    # print("The next 2 is Google Project Zero")
    # print(cve_id)
    # print(google_pz_results[cve_id])
    return google_pz_results[cve_id]

def extractor_inthewild(cve_id, inthewild_results):
    cve_id = cve_id.lstrip()
    cve_id = cve_id.rstrip()
    for i in inthewild_results:
        if i['id'] == cve_id:
            # print(i['source'])
            return True
    return False

    # print(inthewild_results)

def calculator(temporal_score, impact_sub_score, exploitability_sub_score, cpe_impact, cwe_impact, adv_impact, epss_score, exploited_in_wild, cisa_kev, zdi, epss_percentile):
    weight_exploited_in_wild = 20
    weight_exploitability_sub_score = 18
    weight_adv_impact = 15
    weight_impact_sub_score = 12
    weight_epss_score = 10 #done
    weight_cpe_impact = 6 #done
    weight_cwe_impact = 5
    weight_epss_percentile = 4
    weight_cisa_kev = 5
    weight_zdi = 5
    # print("="*30)
    # print(cpe_impact)
    a = (weight_cisa_kev * int(cisa_kev)) 
    b = (weight_impact_sub_score * int(impact_sub_score)) 
    c = (weight_exploitability_sub_score * int(exploitability_sub_score)) 
    d = (weight_cpe_impact * int (cpe_impact)) 
    e = (weight_cwe_impact * int (cwe_impact)) 
    f = (weight_adv_impact * int (adv_impact)) 
    g = (weight_epss_score * float(epss_score))
    h = (weight_exploited_in_wild * int(exploited_in_wild)) 
    i = (weight_zdi * int (zdi)) 
    j = (weight_epss_percentile * float(epss_percentile))

    # print("\n\n", "The weight of G is: ", weight_epss_score, "\n", "The multiply value is: ", epss_score, "The value of G is: ", g)
    #final_score = a+b+c+d+e+f+int(g)+h+i+j
    # print(j)
    final_score = a+b+c+d+e+f+g+h+i+j
    return final_score

def call_calculator(Temporal_Score, Impact_Sub_Score, Exploitability_Sub_Score, impact_of_cpe, impact_of_cwe, impact_of_adv, epss_score, is_google_pz, is_inthewild, is_kev, is_zdi, epss_percentile):
    
    if is_google_pz or is_inthewild or is_zdi == True:
        exploited_in_wild = 1
    else:
        exploited_in_wild = 0

    if is_kev == True:
        cisa_kev = 1
    else:
        cisa_kev = 0

    if is_zdi == True:
        zdi = 1
    else:
        zdi = 0
    final_score = calculator(Temporal_Score, Impact_Sub_Score, Exploitability_Sub_Score, impact_of_cpe, impact_of_cwe, impact_of_adv, epss_score, exploited_in_wild, cisa_kev, zdi, epss_percentile)
    print("*"*30, "THE FINAL SCORE OF THE CVE IS ", final_score, "*"*30)
    return final_score
    


def load_cves_from_file(file_path):
    """Load CVEs from a JSON or text file."""
    if file_path.suffix == ".json":
        with open(file_path, 'r') as f:
            return json.load(f)
    elif file_path.suffix == ".txt":
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        raise ValueError("Unsupported file format. Use .json or .txt files.")

def load_cves_from_directory(directory_path):
    """Load CVEs from all JSON or text files in a directory."""
    cves = []
    for file in Path(directory_path).glob('*'):
        if file.suffix in ['.json', '.txt']:
            cves += load_cves_from_file(file)
    return cves

def write_config_file(config_file, base_dir, cves, sort_order):
    """Write the configuration to a JSON file."""
    config = {
        "base_dir": base_dir,
        "cves": cves,
        "sort_order": sort_order
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)

def read_config_file(config_file):
    """Read configuration from a JSON file."""
    with open(config_file, 'r') as f:
        return json.load(f)








    # Constants for testing
    # base_dir = "/home/kali/Desktop/CVE-Weightage/VNR PRIOR/lake"
    # zdi_feeds = '/home/kali/Desktop/CVE-Weightage/VNR PRIOR/lake/zdi_rss_feeds'
    # cve_ids = [
    #     "CVE-2023-1234",
    #     "CVE-2023-5678",
    #     "CVE-2022-0987",
    #     "CVE-2021-3456",
    #     "CVE-2023-52314",
    #     "CVE-2024-28200"
    # ]

if __name__ == "__main__":
    # Argument parser setup
    start_time = time.time()
    parser = argparse.ArgumentParser(description="CVE Processing Script")
    parser.add_argument('--cve_list', help="Comma-separated list of CVEs", type=str)
    parser.add_argument('--cve_file', help="Path to a JSON file containing CVEs", type=str)
    parser.add_argument('--cve_dir', help="Directory containing files with CVEs", type=str)
    parser.add_argument('--base_dir', help="Base directory", required=True, type=str)
    parser.add_argument('--sort_order', help="Sort order: ascending or descending", choices=['ascending', 'descending'], default='descending')
    parser.add_argument('--config', help="Path to a config file", type=str)
    parser.add_argument('--write_config', help="Write configuration to a file", type=str)
    parser.add_argument('--outfile', help="Output JSON file name (default: results.json)", type=str, default="results.json")
    parser.add_argument('--nvd_threads', help="Number of threads NVD Fetcher will use to get data", type=int, default=10, required=True)

    args = parser.parse_args()

    # Load base_dir and cve list from config if provided
    if args.config:
        config = read_config_file(args.config)
        base_dir = config.get('base_dir', args.base_dir)
        cves = config.get('cves', [])
        sort_order = config.get('sort_order', args.sort_order)
    else:
        base_dir = args.base_dir
        sort_order = args.sort_order
        cves = []

    # Load CVEs based on provided options
    if args.cve_list:
        cves += args.cve_list.split(',')
    if args.cve_file:
        cves += load_cves_from_file(Path(args.cve_file))
    if args.cve_dir:
        cves += load_cves_from_directory(Path(args.cve_dir))

    # Ensure there are no duplicates
    cves = list(set(cves))

    # Store the results for all CVEs in a list of dictionaries
    cve_results = []

    # INITIAL FETCHES (adjust the following functions according to your implementation) ----------
    # NVD Part
    scores, nvd_results = get_nvd.fetch_multiple_cves(base_dir, cves, args.nvd_threads)
    print(scores)
    epss_result = get_epss.fetch_multiple_epss(base_dir, cves)
    epss_json_result = json.dumps(epss_result, indent=2)
    zdi_results = get_zdi.fetch_multiple_cves_from_zdi(cves, base_dir + '/zdi_rss_feeds')
    kev_file = Path(base_dir) / "cisa_kev" / "known_exploited_vulnerabilities.json"
    kev_data = get_cisa_kev.load_kev_data(kev_file)
    kev_results = get_cisa_kev.check_multiple_cves_in_kev(kev_data, cves)
    google_pz_results = get_google_pz.fetch_multiple_cves(base_dir, cves)
    inthewild_results = get_inthewild.fetch_inthewild_from_file(cves, base_dir + "/inthewild/")

    # Function Caller
    for cve_id in cves:
        Base_Score, Exploitability_Sub_Score, Impact_Sub_Score, Temporal_Score = extractor_nvd(cve_id, scores)
        print("~"*20, Base_Score, Exploitability_Sub_Score, Impact_Sub_Score, Temporal_Score, "~"*20)
        if Base_Score !=None and Exploitability_Sub_Score !=None and Impact_Sub_Score!=None and Temporal_Score !=None:
            epss_score, epss_percentile = extractor_epss(cve_id, epss_json_result)
            print(epss_score, epss_percentile)
            if epss_score !=None and epss_percentile !=None:
                is_zdi = extractor_zdi(cve_id, zdi_results)
                is_kev = extractor_kev(cve_id, kev_results)
                is_google_pz = extractor_google_pz(cve_id, google_pz_results)
                is_inthewild = extractor_inthewild(cve_id, inthewild_results)
                impact_of_cpe = extractor_number_cpe(cve_id, nvd_results)
                cwe_data, impact_of_cwe = extractor_number_cwe(cve_id, nvd_results)
                impact_of_adv = extractor_advisories(cve_id, cwe_data)

            
            if Base_Score !=None and Exploitability_Sub_Score !=None and Impact_Sub_Score!=None and Temporal_Score !=None:
                # CALL TO CALCULATOR
                final_Score = call_calculator(Temporal_Score, Impact_Sub_Score, Exploitability_Sub_Score, impact_of_cpe, impact_of_cwe, impact_of_adv, epss_score, is_google_pz, is_inthewild, is_kev, is_zdi, epss_percentile)

            # Append the results for this CVE to the cve_results list
            cve_results.append({
                "CVE_ID": cve_id,
                "Status": "Success",
                "Exploitability_Sub_Score": Exploitability_Sub_Score,
                "Temporal_Score": Temporal_Score,
                "Impact_Sub_Score": Impact_Sub_Score,
                "EPSS_Score": epss_score,
                "EPSS_Percentile": epss_percentile,
                "ZDI_Presence": is_zdi,
                "KEV_Presence": is_kev,
                "Google_Project_Zero_Presence": is_google_pz,
                "In_The_Wild": is_inthewild,
                "CPE_Impact": impact_of_cpe,
                "CWE_Impact": impact_of_cwe,
                "Advisories_Impact": impact_of_adv,
                "Final_Score": final_Score
            })
        else:
            cve_results.append({
                "CVE_ID": cve_id,
                "Status": "Failure",
                "Reason": "Not Enough Data Found!",
                "Final_Score": 0
            })

    # Sort the results by Final_Score
    if sort_order == 'ascending':
        cve_results = sorted(cve_results, key=lambda x: x["Final_Score"])
    else:
        cve_results = sorted(cve_results, key=lambda x: x["Final_Score"], reverse=True)

    # Write the final sorted JSON result to the output file
    print(cve_results)
    end_time = time.time()
    total_time = end_time - start_time
    print(f'Total time taken is: {total_time}')
    with open(args.outfile, 'w') as outfile:
        json.dump(cve_results, outfile, indent=2)
        print(f"Results saved to {args.outfile}")

    # Optionally write the configuration to a file
    if args.write_config:
        write_config_file(args.write_config, base_dir, cves, sort_order)
