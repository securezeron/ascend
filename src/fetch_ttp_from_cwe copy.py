import requests
from bs4 import BeautifulSoup

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

def main():
    details = get_capec_details(78)
    if details:
        try:
            print(f"Details for CWE ID {details['CWE ID']}:")
            print(f"Description: {details['Description']}")
            print(f"Typical Severity: {details['Typical Severity']}")
            print("Taxonomy Mappings:")
            for mapping in details['Taxonomy Mappings']:
                print(f"  Name: {mapping['name']}, Link: {mapping['link']}")
                if 'details' in mapping:
                    print("  Followed ATT&CK Mapping Details:")
                    print(f"    Description: {mapping['details']['Description']}")
                    print(f"    Typical Severity: {mapping['details']['Typical Severity']}")
        except Exception as e:
            print(f"Error printing details for CWE ID {i}: {e}")

if __name__ == "__main__":
    main()
