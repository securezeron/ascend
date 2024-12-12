import fetch_ttp_from_cwe as ttp_cwe
import fetch_advisories_from_ttp as adv_ttp
import json

def main(CWE_ID):
    # cwe_id = "CWE-78"
    combined_advisories = []
    cwe_id = CWE_ID
    links_to_follow = ttp_cwe.main(cwe_id)
    #print(links_to_follow)

    for link in links_to_follow:
        advisories = adv_ttp.main(link)
        print(advisories)
        combined_advisories.append(advisories)

    for advisories in combined_advisories:
        print(advisories)
    return combined_advisories
if __name__ == "__main__":
    cwe_id = input("Enter the CWE-ID to fetch Advisories:")
    print(f"Found CWE-ID: {cwe_id}")
    print(f"Looking for Advisories with CWE-ID: {cwe_id}")
    main(cwe_id)

