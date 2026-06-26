import requests
import urllib3
urllib3.disable_warnings()

resp = requests.get('https://localhost:8089/services/search/jobs?output_mode=json', auth=('admin', 'ZeroTrust2026!'), verify=False)
jobs = resp.json().get('entry', [])
for job in jobs:
    sid = job['name']
    requests.delete(f'https://localhost:8089/services/search/jobs/{sid}', auth=('admin', 'ZeroTrust2026!'), verify=False)
print(f"Deleted {len(jobs)} jobs")
