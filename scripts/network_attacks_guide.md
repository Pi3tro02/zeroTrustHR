# Guida agli Attacchi di Rete (IDS/Snort)

Questo documento contiene i comandi da lanciare tramite Kali Linux (o un qualsiasi container/macchina con i tool di sicurezza installati) per simulare gli attacchi di rete menzionati dal professore.
Questi attacchi saranno rilevati da Snort, il quale invierà l'alert a Splunk e alzerà istantaneamente il Risk Score (`P_net = 0.95`).

## Prerequisiti
- Avere installato `nmap` e `hydra` sulla macchina attaccante.
- Identificare l'IP del container Envoy (es. `172.20.0.10` o localhost `127.0.0.1` se stai testando da fuori Docker, ma è meglio lanciare da dentro la rete Docker `zerotrust_net`).

---

## 1. Port Scanning (Nmap)

La scansione delle porte serve a trovare i servizi esposti in modo aggressivo. Snort dovrebbe avere regole attive per rilevare pacchetti SYN o scan aggressivi.

**Comando per un TCP SYN Scan rapido su tutte le porte:**
```bash
nmap -sS -p- -T4 <IP_ENVOY>
```

**Comando per un Aggressive Scan (rileva OS e versioni):**
```bash
nmap -A -p 10000,10001 <IP_ENVOY>
```

*Risultato atteso*: Snort rileva la scansione e genera alert di tipo "Attempted Information Leak" o "Portscan". La Probabilità di Rete sale a 0.95.

---

## 2. Password Brute Force (Hydra)

Sebbene Envoy termini mTLS e non gestisca direttamente una password SSH/FTP, possiamo simulare un attacco Brute Force HTTP verso l'endpoint di login del backend tramite il proxy Envoy.

**Comando per Brute Force su endpoint Login:**
*(Sostituisci `<IP_ENVOY>` e crea un file `passwords.txt` con le password comuni)*

```bash
hydra -l admin -P passwords.txt -s 10000 <IP_ENVOY> http-post-form "/api/auth/login:username=^USER^&password=^PASS^:F=Unauthorized"
```

*Risultato atteso*: Centinaia di richieste HTTP fallite in pochi secondi verranno intercettate da Snort se configurato per "HTTP Brute Force" o viste come anomalia di picco dal proxy. Questo farà schizzare la componente `P_net` del rischio.
