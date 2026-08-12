import json
import urllib.request

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = urllib.request.urlopen(url)
data = json.loads(response.read())
vulns = data.get("vulnerabilities", [])

dates = [v.get("dateAdded") for v in vulns if v.get("dateAdded")]
dates.sort(reverse=True)
print(f"Total vulns: {len(vulns)}")
print(f"Top 5 most recent dates: {dates[:5]}")
