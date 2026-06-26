HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
  rules = [[
    alert icmp any any -> any any (msg:"ICMP test detected"; sid:1000001; rev:1;)
    alert tcp any any -> any 10000 (msg:"Nmap Scan Detected (Port 10000)"; flags:S; sid:1000002; rev:1;)
  ]]
}

alert_json = { file = true }
