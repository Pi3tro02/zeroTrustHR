HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
  rules = [[
    alert icmp any any -> any any (msg:"ICMP test detected"; sid:1000001; rev:1;)
  ]]
}
