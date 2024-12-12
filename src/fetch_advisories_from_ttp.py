import requests
from bs4 import BeautifulSoup
import json
import tempfile

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

    result = {
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


def main(url):
    # url = "https://attack.mitre.org/wiki/Technique/T1027"
    advisories = get_advisories(url)
    #temp_filename = save_to_tempfile(advisories)
    #print(f"Data saved to temporary file: {temp_filename}")
    #print(json.dumps(advisories, indent=4))
    return(json.dumps(advisories, indent=4))

# Example usage
if __name__ == "__main__":
    url = "https://attack.mitre.org/wiki/Technique/T1027"
    main(url)
