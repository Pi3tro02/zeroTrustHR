# ZeroTrustHR

Un'architettura Zero Trust all'avanguardia per la gestione sicura delle risorse umane. Il sistema implementa una valutazione dinamica del rischio in tempo reale basata su Machine Learning e analisi del traffico di rete, garantendo una difesa adattiva

---

## Architettura del Sistema

L'architettura Zero Trust si fonda su componenti chiave che collaborano per calcolare il rischio in tempo reale:

- **PEP (Policy Enforcement Point) - Envoy Proxy**: Funge da gateway perimetrale con autenticazione mTLS, respingendo attacchi grossolani ancor prima che raggiungano il backend.
- **PDP (Policy Decision Point) - OPA (Open Policy Agent)**: Valuta ogni singola richiesta in base a policy dinamiche, calcolando l'impatto e interrogando il modello di rischio.
- **Motore di Rischio e SIEM - Splunk**: Raccoglie tutti i log via HTTP Event Collector (HEC). Ospita il modello di Machine Learning (*Random Forest*) per calcolare la Probabilità Applicativa ($P_{app}$) analizzando i comportamenti anomali (es. orari insoliti, ruoli non autorizzati).
- **IDS (Intrusion Detection System) - Snort 3**: Monitora il traffico di rete. Quando rileva anomalie infrastrutturali (es. Port Scanning), alza drasticamente la Probabilità di Rete ($P_{net}$).
- **Firewall L3/L4 - nftables**: Gestisce la sicurezza e il logging a livello di rete basale.
- **Backend (Node.js/TS) & Frontend (React/Vite)**: Gestiscono la logica di business e l'interfaccia utente sicura per il dipartimento HR.
- **CA Interna**: Gestisce l'emissione dei certificati per l'autenticazione dei dispositivi sicuri (mTLS).

---

## Strumenti e Tecnologie

- **Docker & Docker Compose**: Containerizzazione dell'intera infrastruttura per una facile riproducibilità.
- **Node.js & TypeScript**: Backend API e microservizio CA interno.
- **React & Vite**: Frontend reattivo e veloce.
- **MongoDB**: Database NoSQL per la conservazione sicura dei dati HR.
- **OPA (Open Policy Agent)**: Motore di regole per l'autorizzazione a grana fine e il calcolo dell'impatto.
- **Envoy Proxy**: Edge proxy ad alte prestazioni e gestione mTLS.
- **Splunk**: SIEM centralizzato, dashboard e Machine Learning Toolkit (AITK).
- **Snort 3**: Intrusion Detection System per l'ispezione profonda dei pacchetti.
- **nftables**: Firewall di rete avanzato.
- **Kali Linux**: Ambiente (via container) dedicato per simulazioni avanzate di attacchi di rete.

---

## Modello di Calcolo del Rischio

Il cuore dell'architettura è la valutazione matematica e continua della minaccia, calcolata per ogni singola richiesta:

**Rischio Totale = max($P_{app}$, $P_{net}$) × Impatto**

Dove:
- **$P_{app}$ (Probabilità Applicativa)**: È calcolata in tempo reale dal modello di Machine Learning (*Random Forest*) ospitato su Splunk. Il modello analizza lo storico degli accessi (es. tentativi fuori orario, richieste verso reparti non autorizzati, dispositivi non attendibili) e assegna una probabilità di anomalia comportamentale tra 0 e 1.
- **$P_{net}$ (Probabilità di Rete)**: Subentra quando l'infrastruttura subisce un attacco diretto (es. Port Scanning). Viene innalzata automaticamente dall'IDS (Snort) nel momento in cui rileva un'offesa; questo valore di allerta (es. $P_{net} = 0.95$) bypassa le normali valutazioni applicative per garantire il blocco immediato della sorgente ostile.
- **Impatto**: Misura il potenziale danno nel caso in cui la richiesta dovesse avere successo in modo illecito. Viene determinato dinamicamente in base alla **criticità della risorsa** richiesta (ad esempio, leggere i *dati finanziari* ha un impatto alto, ma tentare di modificarli ha un impatto massimo) e ai **privilegi dell'utente** (la compromissione di un *amministratore* aggiunge una penalità extra, aggravando l'impatto complessivo).

---

## Configurazione e Avvio

### Prerequisiti
- **Docker** e **Docker Compose** installati.
- (Opzionale ma necessario per la demo) Scaricare da [Splunkbase](https://splunkbase.splunk.com/) (richiede account gratuito):
  - Splunk AI Toolkit (AITK)
  - Python for Scientific Computing (Linux 64-bit)

### 1. Configurazione Iniziale
Creare un file `.env` nella directory root del progetto. Puoi usare i seguenti valori di base per lo sviluppo:
```env
MONGO_ROOT_USER=admin
MONGO_ROOT_PASSWORD=ZeroTrust2026!
SPLUNK_PASSWORD=ZeroTrust2026!
SPLUNK_HEC_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890
SPLUNK_OPA_TOKEN=b2c3d4e5-f6a1-8901-bcde-f12345678901
JWT_SECRET=dev_jwt_secret_zerotrust_2026
SPLUNK_WEBHOOK_SECRET=dev_webhook_secret_zerotrust_2026
```

### 2. Avvio dei Servizi
Dal terminale (es. PowerShell), ferma eventuali istanze precedenti, pulisci i volumi e avvia il sistema:
```bash
docker-compose down -v
docker-compose up --build -d
```
*Attendi qualche minuto affinché Splunk sia online su `http://localhost:8000`.*

### 3. Setup delle App di Machine Learning
Installa i pacchetti bypassando l'interfaccia web per evitare timeout (sostituisci i percorsi con quelli reali in cui hai scaricato i `.tgz`):
```bash
docker cp "C:\Percorso\python-for-scientific-computing.tgz" zerotrust-splunk:/tmp/
docker cp "C:\Percorso\splunk-ai-toolkit.tgz" zerotrust-splunk:/tmp/

docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/python-for-scientific-computing.tgz -update 1 -auth admin:ZeroTrust2026!
docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/splunk-ai-toolkit.tgz -update 1 -auth admin:ZeroTrust2026!

docker-compose restart splunk
```

---

##  Guide alle Simulazioni e Test di Splunk

Il progetto include script e configurazioni specifiche per dimostrare la resilienza dell'architettura in vari scenari.

### Fase 1: Addestramento del Modello (Behavioral Analysis)
Simula traffico legittimo misto ad attacchi per addestrare il classificatore Random Forest su Splunk a distinguere i comportamenti ostili:
```bash
python scripts/simulate_auth_attacks.py
```
Successivamente, su Splunk, lancia la query SQL dedicata (descritta nella [Guida Demo](demo_guide.md)) per istruire e salvare il modello `app_risk_model`.

### Fase 2: Blocco Dinamico Predittivo (Live Demo)
Lancia la simulazione live per vedere l'infrastruttura reagire in tempo reale:
```bash
python scripts/demo_live_attacks.py
```
Gli utenti normali avranno un punteggio di rischio basso, mentre quelli ostili vedranno incrementare il loro livello fino al blocco preventivo. Sotto attacco massivo, il sistema passa in modalità di auto-protezione (**Fail-Closed**).

### Fase 3: Attacchi Infrastrutturali (Network & IDS)
Utilizza container isolati per sferrare attacchi simulati (fare riferimento a [Guida Attacchi Rete](scripts/network_attacks_guide.md)):

**Port Scanning (Nmap):** Intercettato da Snort, innalza drasticamente la Probabilità di Rete ($P_{net}$) dell'attaccante.
```bash
docker run --rm --network zerotrusthr_zerotrust_net instrumentisto/nmap -sS -p- -T4 zerotrust-envoy
```

**Brute Force su mTLS (Hydra):** Viene respinto nativamente al livello L4/L7 dall'Edge Proxy.
```bash
docker run --rm -v "${PWD}/passwords.txt:/passwords.txt" --network zerotrusthr_zerotrust_net secsi/hydra -l admin -P /passwords.txt -s 10000 zerotrust-envoy http-post-form "/api/auth/login:username=^USER^&password=^PASS^:F=Unauthorized"
```


## Guide alle simluzioni e test su nftables

Guardare il file [README.md](nftables/README.md).

---

> [!TIP]
> **Documentazione Completa**
> Per maggiori approfondimenti e istruzioni estese passo-passo, fai riferimento ai file [demo_guide.md](demo_guide.md) e [network_attacks_guide.md](scripts/network_attacks_guide.md).