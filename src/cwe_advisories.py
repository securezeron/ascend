import requests
from bs4 import BeautifulSoup
import json
import argparse
from pathlib import Path
import tempfile

### CWE -> TTP

def fetch_and_parse(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup
    except requests.RequestException as e:
        print(f"Failed to fetch data from {url}. Error: {e}")
        return None

def extract_details(soup):
    try:
        # Extract Description
        description_tag = soup.find('div', {'id': 'Description'})
        description = description_tag.find('div', class_='detail').text.strip() if description_tag else "No description found."
        
        # Check for deprecation and redirection
        if "this attack pattern has been deprecated as it is a duplicate of" in description.lower():
            redirect_url_tag = description_tag.find('div', class_='detail')
            link_tag = redirect_url_tag.find('a')
            if link_tag and 'href' in link_tag.attrs:
                new_url = link_tag['href']
                if new_url.startswith('/data'):
                    new_url = f"https://capec.mitre.org{new_url}"
                    print(f"Redirecting to {new_url}")
                    soup = fetch_and_parse(new_url)
                    if soup:
                        return extract_details(soup)
                else:
                    print(f"Found an invalid URL: {new_url}")
                    return None
        elif "This pattern has been deprecated as it was determined to be a duplicate of another pattern." in description.lower():
            redirect_url_tag = description_tag.find('div', class_='detail')
            link_tag = redirect_url_tag.find('a')
            if link_tag and 'href' in link_tag.attrs:
                new_url = link_tag['href']
                if new_url.startswith('/data'):
                    new_url = f"https://capec.mitre.org{new_url}"
                    print(f"Redirecting to {new_url}")
                    soup = fetch_and_parse(new_url)
                    if soup:
                        return extract_details(soup)
                else:
                    print(f"Found an invalid URL: {new_url}")
                    return None
        
        # Extract Typical Severity
        severity_tag = soup.find('div', {'id': 'Typical_Severity'})
        severity = severity_tag.find('div', class_='detail').text.strip() if severity_tag else "No typical severity found."
        
        # Extract Taxonomy Mappings
        taxonomy_mappings = []
        taxonomy_tag = soup.find('div', {'id': 'Taxonomy_Mappings'})
        if taxonomy_tag:
            table = taxonomy_tag.find('table')
            if table:
                for row in table.find_all('tr')[1:]:  # Skip the header row
                    cols = row.find_all('td')
                    if cols:
                        mapping_name = cols[1].text.strip()
                        mapping_link = cols[0].find('a')['href'] if cols[0].find('a') else ''
                        taxonomy_mappings.append({'name': mapping_name, 'link': mapping_link})
            else:
                redirect_div = taxonomy_tag.find('div', class_='tax_title')
                if redirect_div:
                    redirect_link = redirect_div.find('a')['href'] if redirect_div.find('a') else ''
                    if redirect_link.startswith('/data'):
                        redirect_url = f"https://capec.mitre.org{redirect_link}"
                        print(f"Following taxonomy mapping link: {redirect_url}")
                        redirect_soup = fetch_and_parse(redirect_url)
                        if redirect_soup:
                            taxonomy_mappings = extract_details(redirect_soup).get('Taxonomy Mappings', [])
        
        capec_details = {
            'Description': description,
            'Typical Severity': severity,
            'Taxonomy Mappings': taxonomy_mappings
        }
        
        return capec_details
    except Exception as e:
        print(f"Error extracting details: {e}")
        return None

def get_capec_details(cwe_id):
    try:
        url = f"https://capec.mitre.org/data/definitions/{cwe_id}.html"
        soup = fetch_and_parse(url)
        
        if not soup:
            return
        
        details = extract_details(soup)
        if details:
            details['CWE ID'] = cwe_id
        
        return details
    except Exception as e:
        print(f"Error getting CAPEC details for CWE ID {cwe_id}: {e}")
        return None

### TTP -> Advisories with Procedure Count

def follow_redirect(response):
    soup = BeautifulSoup(response.content, 'html.parser')
    meta_tag = soup.find('meta', attrs={'http-equiv': 'refresh'})
    if meta_tag:
        content = meta_tag.get('content')
        if content:
            url_part = content.split('url=')[-1]
            new_url = response.url.split('/wiki/')[0] + url_part
            return new_url
    return None

def get_advisories(url):
    response = requests.get(url)
    if response.status_code != 200:
        return {"error": f"Failed to fetch data from {url}"}

    redirect_url = follow_redirect(response)
    if redirect_url:
        response = requests.get(redirect_url)
        if response.status_code != 200:
            return {"error": f"Failed to fetch data from {redirect_url}"}

    soup = BeautifulSoup(response.content, 'html.parser')
    table_div = soup.find('div', {'class': 'tables-mobile'})

    if not table_div:
        return {"error": "Procedure Examples table not found"}

    table = table_div.find('table')
    rows = table.find_all('tr')[1:]  # Skip the header row

    examples = []
    for row in rows:
        cols = row.find_all('td')
        if len(cols) >= 3:
            example = {
                "id": cols[0].text.strip(),
                "name": cols[1].text.strip(),
                "description": cols[2].text.strip()
            }
            examples.append(example)

    # Extract technique ID and name
    technique_name_tag = soup.find('h1', class_='title')
    technique_name = technique_name_tag.text.strip() if technique_name_tag else "Unknown"
    technique_id_tag = soup.find('span', class_='sub-technique')
    technique_id = technique_id_tag.text.strip() if technique_id_tag else url.split('/')[-1]

    result = {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "total_count": len(examples),
        "examples": examples
    }
    
    return result

def save_to_tempfile(data):
    json_output = json.dumps(data, indent=4)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
    with open(temp_file.name, 'w') as file:
        file.write(json_output)
    return temp_file.name

### Command-line Interface

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch details from CAPEC (CWE -> TTP) and MITRE ATT&CK (TTP -> Advisories).")
    parser.add_argument('--cwe', '-c', type=int, help="CWE ID to fetch CAPEC details.")
    parser.add_argument('--ttp-url', '-t', type=str, help="URL to fetch advisories related to TTP.")
    parser.add_argument('--save', '-s', action='store_true', help="Save advisories data to a temporary file.")
    
    args = parser.parse_args()

    if args.cwe:
        details = get_capec_details(args.cwe)
        if details:
            print(f"Details for CWE ID {details['CWE ID']}:")
            print(f"Description: {details['Description']}")
            print(f"Typical Severity: {details['Typical Severity']}")
            print("Taxonomy Mappings:")
            for mapping in details['Taxonomy Mappings']:
                print(f"  Name: {mapping['name']}, Link: {mapping['link']}")
    print(args.ttp_url)
    if args.ttp_url:
        advisories = get_advisories(args.ttp_url)
        if args.save:
            temp_filename = save_to_tempfile(advisories)
            print(f"Data saved to temporary file: {temp_filename}")
        print(f"Technique ID: {advisories.get('technique_id')}")
        print(f"Technique Name: {advisories.get('technique_name')}")
        print(f"Number of Procedure Examples: {advisories.get('total_count')}")
        print(json.dumps(advisories, indent=4))
