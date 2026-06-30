# Guida alla Dimostrazione: Calcolo del Rischio Zero Trust

Questa guida descrive passo-passo come avviare l'infrastruttura da zero e replicare i test per dimostrare il calcolo dinamico del rischio. Il sistema utilizza un modello di Machine Learning (Random Forest) su Splunk per rilevare comportamenti anomali e bloccare potenziali attaccanti.

La formula base del rischio è:
**Rischio = Probabilità × Impatto**

Il sistema calcola due probabilità in tempo reale:
1. **$P_{app}$ (Probabilità Applicativa)**: Calcolata in tempo reale dal modello di Machine Learning (`app_risk_model`) che analizza lo storico degli accessi negati da OPA.
2. **$P_{net}$ (Probabilità di Rete)**: Innalzata dinamicamente quando l'IDS (Snort) rileva anomalie di rete.

Il rischio finale viene valutato come: **$max(P_{app}, P_{net}) \times Impatto$**.

### Come viene calcolato l'Impatto?
L'**Impatto** misura il potenziale danno in caso di esfiltrazione o abuso. Viene determinato combinando:
- **La criticità della risorsa e il tipo di azione**: Il calcolo dell'impatto base è implementato dinamicamente all'interno della query stessa (tramite uno statement matematico `case`). Questo garantisce la massima velocità ed evita problemi di permessi incrociati tra le varie App di Splunk. Leggere i dati finanziari (`financial_data`, `read`) ha un impatto molto alto, ma sovrascriverli o cancellarli (`financial_data`, `write`) ha un impatto ancora più devastante e farà schizzare la severità al massimo, a parità di risorsa.
- **Il livello di privilegio dell'utente**: Se l'utente è un amministratore (`admin`) o ha un ruolo delicato (`hr`), viene sommata una penalità extra (+0.2 o +0.1) all'impatto base, poiché la compromissione di un utente privilegiato causa danni strutturali più gravi. Il totale è limitato a un massimo di 1.0.

---

## 1. Avvio dell'Infrastruttura

Per replicare il tutto da zero, è necessario assicurarsi di aver fermato e pulito i container precedenti, per poi ricrearli.

1. Aprire un terminale (PowerShell) nella cartella principale del progetto `zeroTrustHR`.
2. Fermare l'ambiente corrente e pulire i volumi:
   ```bash
   docker-compose down -v
   ```
3. Ricreare e avviare tutti i servizi in background:
   ```bash
   docker-compose up --build -d
   ```
4. Attendere qualche minuto affinché Splunk termini l'avvio e diventi raggiungibile.

## 2. Installazione delle App di Machine Learning (AITK e PSC)

Per poter utilizzare il Machine Learning su Splunk, è necessario installare due applicazioni fondamentali. Poiché una di queste è molto grande (~1 GB), l'installazione tramite interfaccia web potrebbe fallire per timeout. Verrà quindi seguita l'installazione via linea di comando (CLI).

### Download dei pacchetti
1. Accedere a [Splunkbase](https://splunkbase.splunk.com/) (è richiesto un account Splunk gratuito).
2. Cercare e scaricare i file `.tgz` delle seguenti app:
   - **Splunk AI Toolkit (AITK)**
   - **Python for Scientific Computing (for Linux 64-bit)**
3. Salvare i due file scaricati in una cartella facilmente accessibile, ad esempio `C:\Users\Utente\Downloads\`.

### Installazione tramite Docker CLI
1. Aprire un terminale (PowerShell) e utilizzare il comando `docker cp` per copiare i file scaricati all'interno del container di Splunk (nella cartella temporanea `/tmp/`).
   Sostituire il percorso con quello effettivo in cui sono stati salvati i file:
   ```bash
   docker cp "C:\Percorso\Ai\File\python-for-scientific-computing-for-linux-64-bit_432.tgz" zerotrust-splunk:/tmp/
   docker cp "C:\Percorso\Ai\File\splunk-ai-toolkit_574.tgz" zerotrust-splunk:/tmp/
   ```
2. Installare la libreria Python per il calcolo scientifico scavalcando l'interfaccia web, eseguendo questo comando:
   ```bash
   docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/python-for-scientific-computing-for-linux-64-bit_432.tgz -update 1 -auth admin:ZeroTrust2026!
   ```
   *(Nota: Il processo estrarrà quasi 1 GB di file, attendere qualche minuto finché il terminale non restituisce il prompt).*
3. Installare subito dopo l'AI Toolkit:
   ```bash
   docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/splunk-ai-toolkit_574.tgz -update 1 -auth admin:ZeroTrust2026!
   ```
4. **Passaggio Fondamentale**: Riavviare il container di Splunk affinché agganci correttamente i binari C++ e la libreria Python appena estratti:
   ```bash
   docker-compose restart splunk
   ```
5. Attendere circa 1-2 minuti. Quando Splunk torna online su `http://localhost:8000`, l'ambiente è pronto per essere utilizzato!

---

## 3. Fase 1: Creazione e Addestramento del Modello (AITK)

Prima di poter bloccare gli attaccanti, dobbiamo addestrare il modello di Machine Learning (Random Forest) affinché sappia riconoscere un comportamento ostile in base allo storico.

### Generazione dei Dati di Addestramento
1. Dallo stesso terminale, lanciare lo script Python per generare i dati storici. 
   *(Nota: lo script è progettato per simulare un ambiente realistico. Invierà circa l'80% di traffico legittimo "di fondo" e un 20% di attacchi mirati. Questo mix è essenziale affinché l'Intelligenza Artificiale impari a distinguere la normalità dalle minacce).*
   ```bash
   py scripts/simulate_auth_attacks.py
   ```
2. Attendere la fine della simulazione. Tutte le decisioni di OPA verranno inviate via HEC a Splunk. 
   *(Nota: durante questa prima esecuzione, si noterà a video che gli attacchi di Eve ricevono quasi sempre un rischio basso pari a `0.1`. Questo è assolutamente normale: il modello di Intelligenza Artificiale è ancora vuoto e OPA non ha ancora imparato a riconoscere le minacce avanzate).*

### Addestramento su Splunk
1. Aprire il browser all'indirizzo [http://localhost:8000](http://localhost:8000).
2. Effettuare l'accesso (credenziali: `admin` / `ZeroTrust2026!`).
3. Andare all'app **Search & Reporting**.
4. Eseguire questa query esatta impostando il tempo su **"All time"**:
   ```spl
   search (index=zerotrust sourcetype=opa_decision)
   | spath input=_raw path=line.result.allowed output=allowed
   | spath input=_raw path=line.result.user output=user_id
   | eval is_opa=1
   | eval is_deny=if(allowed="false", 1, 0)
   | eval reason_time = if(is_deny=1 AND match('line.result.deny_reasons{}', "outside_working_hours"), 1, 0)
   | eval reason_priv = if(is_deny=1 AND match('line.result.deny_reasons{}', "role_not_allowed|action_not_allowed|department_not_allowed"), 1, 0)
   | eval reason_auth = if(is_deny=1 AND match('line.result.deny_reasons{}', "untrusted_device|device_not_active|mfa_required|ja3_fingerprint_blocked|ip_not_in_allowed_zone|unsupported_os"), 1, 0)
   | eval device_ip_header = 'line.input.attributes.request.http.headers.x-device-ip'
   | eval src_ip = coalesce(device_ip_header, src_ip, src)
   | stats 
       sum(is_deny) AS total_denies
       sum(reason_time) AS time_denies
       sum(reason_priv) AS priv_denies
       sum(reason_auth) AS auth_denies
       count(eval(is_opa=1)) AS total_opa_requests
       dc(eval(if(is_opa=1, src_ip, null()))) AS distinct_ips
       BY user_id
   | eval deny_ratio = if(total_opa_requests > 0, total_denies / total_opa_requests, 0)
   | eval is_attacker = if(user_id="eve_attacker" OR user_id="oscar_attacker", 1, 0)
   | fit RandomForestClassifier is_attacker from total_denies time_denies priv_denies auth_denies distinct_ips deny_ratio into app_risk_model
   ```
5. **Risultato atteso**: Compariranno i risultati dell'addestramento e il modello `app_risk_model` verrà salvato all'interno di Splunk.

---

## 4. Fase 2: Blocco Dinamico Predittivo (Calcolo $P_{app}$)

Ora che il modello è addestrato, verrà dimostrato come il sistema interviene in tempo reale per bloccare gli attaccanti e permettere l'accesso agli utenti legittimi.

1. Lanciare il secondo script di simulazione (ottimizzato per la demo live con piccole pause) dal terminale:
   ```bash
   py scripts/demo_live_attacks.py
   ```
2. **Risultato atteso**: Questa volta, il sistema interrogherà il modello in tempo reale per calcolare il rischio.
   - Gli utenti legittimi come **Alice e Bob** manterranno un rischio basso (0.1) anche se commettono piccoli errori, come tentare un accesso fuori orario.
   - L'utente **Eve** (e **Oscar**), invece, commettendo violazioni più gravi (come cercare di accedere a dati per cui non hanno i permessi da un IP sospetto), vedranno il loro livello di rischio salire gradualmente a ogni tentativo (ad esempio `0.5`). 
   - Se le richieste sono troppo frequenti (simulazione Denial of Service), si noterà che l'architettura Zero Trust reagisce automaticamente con una politica **Fail-Closed**, assegnando un rischio preventivo di `1.0` a tutti finché il carico anomalo non si stabilizza, dimostrando l'incredibile resilienza del sistema.

---

## 5. Fase 3: Attacchi di Rete (Calcolo $P_{net}$)

In questa fase viene dimostrata la capacità dell'architettura di intercettare attacchi di rete diretti (come il Port Scanning) e alzare istantaneamente il rischio, superando le valutazioni del modello.

### Esecuzione dell'Attacco
*(Nota: Per un'esperienza completa e per sferrare diverse tipologie di attacchi oltre a quello base mostrato qui sotto, si consiglia di aprire il file `scripts/network_attacks_guide.md` e seguire i comandi avanzati ivi descritti).*

1. Utilizzare un container Nmap temporaneo per lanciare un "TCP SYN Scan" contro il proxy Envoy. Eseguire:
   ```bash
   docker run --rm --network zerotrusthr_zerotrust_net instrumentisto/nmap -sS -p- -T4 zerotrust-envoy
   ```
2. Attendere circa 10-15 secondi che la scansione finisca. Snort intercetterà il traffico TCP anomalo sulla porta 10000 e genererà un alert in `snort/logs/alert_json.txt`.

### Verifica su Splunk
1. Tornare su Splunk ed eseguire la ricerca dedicata all'IDS:
   ```spl
   search index=zerotrust sourcetype=_json "alert"
   | spath input=_raw path=msg output=alert_message
   | spath input=_raw path=src_addr output=source_ip
   | search alert_message="*Nmap*" OR alert_message="*Brute Force*"
   | eval network_risk_score = 0.95
   | table source_ip, alert_message, network_risk_score
   ```
2. **Risultato atteso**: Comparirà l'evento `Nmap Scan Detected` con l'indirizzo IP della sorgente. Il sistema, rilevando questo evento, assocerà all'IP un $P_{net}$ elevatissimo (es. 0.95), bloccando preventivamente le richieste future da quel nodo.

---

## 6. Conclusione: Il Rischio Totale e la Blocklist

Grazie ai dati comportamentali valutati dal **Modello** ($P_{app}$) e ai dati infrastrutturali di rete ($P_{net}$), il backend e Splunk hanno tutte le informazioni necessarie:
- Quando viene fatta una nuova richiesta, viene determinato l'impatto della risorsa.
- Viene interrogato in tempo reale il modello Machine Learning per la probabilità applicativa.
- OPA emette la decisione bloccando l'utente se il `Risk Score` combinato supera la soglia di tolleranza per quella specifica risorsa, chiudendo il ciclo architetturale Zero Trust.
