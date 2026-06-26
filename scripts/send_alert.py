import urllib.request
import json
import ssl

url = "https://localhost:8088/services/collector/event"
headers = {"Authorization": "Splunk a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
data = {
    "index": "zerotrust",
    "sourcetype": "_json",
    "event": {
        "msg": "Nmap Scan Detected (Port 10000)",
        "src_addr": "172.20.0.1",
        "dst_addr": "172.20.0.8",
        "proto": "TCP",
        "action": "alert"
    }
}

req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

try:
    response = urllib.request.urlopen(req, context=ctx)
    print(response.read().decode("utf-8"))
except Exception as e:
    print(e)
