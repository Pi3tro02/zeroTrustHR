
---

#  1. Avvio e accesso Kali Linux

## Verifica container attivo

```powershell
docker ps

Deve essere presente:

zerotrust-kali
Accesso shell Kali
docker exec -it zerotrust-kali bash
Aggiornamento strumenti base

Dentro Kali:

apt update && apt install -y iproute2 curl nmap netcat-traditional iputils-ping

2. Ricognizione rete ZeroTrust
Visualizza interfacce
ip a
Routing table
ip route
Test con backend
ping 172.20.0.6
curl http://backend:3000

Oppure:

curl http://zerotrust-backend:3000
3. Simulazioni di traffico (ATTACK SIMULATION)
Nota
Questi non sono attacchi reali su internet, ma test di generazione log e detection pipeline

3.1 Port Scanning (Nmap)
nmap -sS -sV 172.20.0.6
Cosa testa:
TCP SYN scan
enumerazione servizi
trigger IDS (Snort)
3.2 Scan su porta specifica
nmap -p 3000,8181,8088 172.20.0.6
3.3 HTTP traffic flood test
for i in {1..50}; do curl http://backend:3000; done
3.4 Test Envoy entrypoint (Zero Trust enforcement)
curl http://envoy:10000

oppure:

curl http://localhost:10000
Output atteso:
log prefisso nftables:
ZTA-ENVOY-ACCESS:
3.5 Test OPA policy engine
curl http://opa:8181/v1/data

Oppure query:

curl http://opa:8181/v1/data/app/rules
3.6 Test MongoDB access
mongosh "mongodb://admin:ZeroTrust2026!@mongodb:27017"
 4. LOGGING PIPELINE (CORE ESAME)
 Flusso log completo
Kali
  ↓
Envoy (L7 proxy)
  ↓
OPA decision (allow/deny)
  ↓
Backend Node.js logs
  ↓
Splunk HEC ingestion
  ↓
Correlation engine SIEM
 5. nftables logging (Firewall L3/L4)
Regola principale
log prefix "ZTA-ENVOY-ACCESS: " group 1 flags all
Log atteso
ZTA-ENVOY-ACCESS: IN=eth0 OUT= MAC=... SRC=172.18.0.2 DST=172.20.0.6
 6. Snort IDS (Intrusion Detection)
Log file
/var/log/snort/alert_json.txt
Esempio alert JSON
{
  "event_type": "alert",
  "src_ip": "172.18.0.2",
  "dest_ip": "172.20.0.6",
  "signature": "SYN scan detected",
  "severity": 2
}
 7. Splunk SIEM (central logging)
UI access
http://localhost:8000
Query base
index=zerotrust
Sourcetype attesi
backend_node_pino
envoy_access
nftables_json
mongodb_json
opa_decision
 8. OPA Policy Decision Logs
Esempio decision log
{
  "decision_id": "abc123",
  "input": {
    "user": "kali",
    "action": "access_backend"
  },
  "result": "deny"
}
 9. Troubleshooting
Kali non raggiunge rete
docker network inspect zerotrusthr_wan_net
nftables non logga
docker logs zerotrust-nftables
Snort non genera alert
docker exec -it zerotrust-snort ls /var/log/snort
Splunk non riceve eventi
curl -k https://localhost:8088/services/collector/health/1.0
Docker logging driver error (EOF / 500)

Fix tipici:

docker compose down -v
docker system prune -af

poi:

docker compose up -d --build
 10. Attacchi dimostrabili all’esame

Il sistema rileva:

Port scanning (nmap)
Reconnaissance (service enumeration)
Unauthorized API access
HTTP flood simulation
DB access attempt
Policy denial via OPA
 11. Conclusione architettura

✔ Kali = attacker simulation
✔ nftables = firewall L3/L4 + logging kernel
✔ Snort = IDS detection layer
✔ Envoy = L7 + mTLS enforcement
✔ OPA = policy decision engine
✔ Splunk = SIEM centralizzato