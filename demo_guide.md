# Guida alla Dimostrazione: Motore di Rischio Zero Trust con Intelligenza Artificiale

Questa guida descrive passo-passo come avviare l'infrastruttura da zero e replicare i test per dimostrare il calcolo dinamico del rischio. Il sistema utilizza un modello di Machine Learning (Random Forest) su Splunk per rilevare comportamenti anomali e bloccare potenziali attaccanti.

La formula base del motore di rischio è:
**Rischio = Probabilità × Impatto**

Il sistema calcola due probabilità in tempo reale:
1. **$P_{app}$ (Probabilità Applicativa)**: Calcolata in tempo reale dal modello di AI (`app_risk_model`) che analizza lo storico degli accessi negati da OPA.
2. **$P_{net}$ (Probabilità di Rete)**: Innalzata dinamicamente quando l'IDS (Snort) rileva anomalie di rete.

Il rischio finale viene valutato come: **$max(P_{app}, P_{net}) \times Impatto$**.

### Come viene calcolato l'Impatto?
L'**Impatto** misura il potenziale danno in caso di esfiltrazione o abuso. Viene determinato combinando:
- **La criticità della risorsa e il tipo di azione**: Splunk utilizza una tabella interna (`resource_impact.csv`) per valutare non solo *cosa* stai toccando, ma *come*. Mappa infatti ogni coppia di "risorsa" e "azione" (es. `read` vs `write`). Leggere i dati finanziari (`financial_data`, `read`) ha un impatto molto alto, ma sovrascriverli o cancellarli (`financial_data`, `write`) ha un impatto ancora più devastante e farà schizzare la severità al massimo, a parità di risorsa.
- **Il livello di privilegio dell'utente**: Se l'utente è un amministratore (`admin`) o ha un ruolo delicato (`hr`), viene sommata una penalità extra (+0.2 o +0.1) all'impatto base, poiché la compromissione di un utente privilegiato causa danni strutturali più gravi. Il totale è limitato a un massimo di 1.0.

---

## 1. Avvio dell'Infrastruttura

Per replicare il tutto da zero, assicurati di aver fermato e pulito i container precedenti, per poi ricrearli.

1. Apri un terminale (PowerShell) nella cartella principale del progetto `zeroTrustHR`.
2. Ferma l'ambiente corrente e pulisci i volumi:
   ```bash
   docker-compose down -v
   ```
3. Ricrea e avvia tutti i servizi in background:
   ```bash
   docker-compose up --build -d
   ```
4. Attendi qualche minuto affinché Splunk termini l'avvio e diventi raggiungibile.

## 2. Installazione delle App di Intelligenza Artificiale (MLTK e PSC)

Per poter utilizzare il Machine Learning su Splunk, è necessario installare due applicazioni fondamentali. Poiché una di queste è molto grande (~1 GB), l'installazione tramite interfaccia web potrebbe fallire per timeout. Seguiremo quindi l'installazione via linea di comando (CLI).

### Download dei pacchetti
1. Vai su [Splunkbase](https://splunkbase.splunk.com/) (è richiesto un account Splunk gratuito).
2. Cerca e scarica i file `.tgz` delle seguenti app:
   - **Splunk Machine Learning Toolkit (MLTK)**
   - **Python for Scientific Computing (for Linux 64-bit)**
3. Salva i due file scaricati in una cartella facilmente accessibile, ad esempio `C:\Users\TuoUtente\Downloads\`.

### Installazione tramite Docker CLI
1. Apri un terminale (PowerShell) e usa il comando `docker cp` per copiare i file scaricati all'interno del container di Splunk (nella cartella temporanea `/tmp/`).
   Sostituisci il percorso con quello effettivo in cui hai salvato i file:
   ```bash
   docker cp "C:\Percorso\Ai\File\python-for-scientific-computing-for-linux-64-bit_432.tgz" zerotrust-splunk:/tmp/
   docker cp "C:\Percorso\Ai\File\splunk-ai-toolkit_574.tgz" zerotrust-splunk:/tmp/
   ```
2. Installa la libreria Python per il calcolo scientifico scavalcando l'interfaccia web, eseguendo questo comando:
   ```bash
   docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/python-for-scientific-computing-for-linux-64-bit_432.tgz -update 1 -auth admin:ZeroTrust2026!
   ```
   *(Nota: Il processo estrarrà quasi 1 GB di file, attendi qualche minuto finché il terminale non ti restituisce il prompt).*
3. Installa subito dopo il Machine Learning Toolkit:
   ```bash
   docker exec -u root zerotrust-splunk /opt/splunk/bin/splunk install app /tmp/splunk-ai-toolkit_574.tgz -update 1 -auth admin:ZeroTrust2026!
   ```
4. **Passaggio Fondamentale**: Riavvia il container di Splunk affinché agganci correttamente i binari C++ e la libreria Python appena estratti:
   ```bash
   docker-compose restart splunk
   ```
5. Attendi circa 1-2 minuti. Quando Splunk torna online su `http://localhost:8000`, il motore di intelligenza artificiale è pronto per essere utilizzato!

---

## 3. Fase 1: Creazione e Addestramento del Modello AI (MLTK)

Prima di poter bloccare gli attaccanti, dobbiamo addestrare il modello di Machine Learning (Random Forest) affinché sappia riconoscere un comportamento ostile in base allo storico.

### Generazione dei Dati di Addestramento
1. Dallo stesso terminale, lancia lo script Python che inonderà l'endpoint OPA di richieste non autorizzate per creare una base di dati storici:
   ```bash
   py scripts/simulate_auth_attacks.py
   ```
2. Attendi la fine della simulazione. Tutte le decisioni di OPA verranno inviate via HEC a Splunk.

### Addestramento su Splunk
1. Apri il browser all'indirizzo [http://localhost:8000](http://localhost:8000).
2. Effettua l'accesso (credenziali: `admin` / `ZeroTrust2026!`).
3. Vai all'app **Search & Reporting**.
4. Esegui questa query esatta impostando il tempo su **"All time"**:
   ```spl
   search (index=zerotrust sourcetype=opa_decision)
   | spath input=_raw path=line.result.allowed output=allowed
   | spath input=_raw path=line.result.user output=user_id
   | eval is_opa=1
   | eval is_deny=if(allowed="false", 1, 0)
   | stats 
       sum(is_deny) AS total_denies
       count(eval(is_opa=1)) AS total_opa_requests
       BY user_id
   | eval deny_ratio = if(total_opa_requests > 0, total_denies / total_opa_requests, 0)
   | eval is_attacker = if(user_id="eve_attacker", 1, 0)
   | fit RandomForestClassifier is_attacker from total_denies deny_ratio into app_risk_model
   ```
5. **Risultato atteso**: Compariranno i risultati dell'addestramento e il modello `app_risk_model` verrà salvato all'interno di Splunk.

---

## 4. Fase 2: Blocco Dinamico Predittivo (Calcolo $P_{app}$)

Ora che l'AI è addestrata, dimostreremo come interviene in tempo reale per bloccare gli attaccanti e permettere l'accesso agli utenti legittimi.

1. Lancia di nuovo lo script di simulazione dal terminale:
   ```bash
   py scripts/simulate_auth_attacks.py
   ```
2. **Risultato atteso**: Questa volta, quando il backend valuterà la richiesta, interrogherà dinamicamente l'AI usando il comando `| apply app_risk_model`. 
   - Noterai che utenti legittimi come **Alice e Bob** riceveranno un `Risk: 0.1` (Safe) e verranno bloccati solo se operano fuori dall'orario lavorativo.
   - L'utente **Eve** verrà identificato come minaccia dall'AI (`Risk: 1.0` o simili) e riceverà sistematicamente un divieto di accesso per `risk_score_too_high`.

*(Nota: La primissima esecuzione del modello dopo un riavvio richiede 15-20 secondi a Splunk per "scaldare" il processo Python. Le richieste successive saranno istantanee).*

---

## 5. Fase 3: Attacchi di Rete (Calcolo $P_{net}$)

In questa fase dimostriamo la capacità dell'architettura di intercettare attacchi di rete diretti (come il Port Scanning) e alzare istantaneamente il rischio, superando le valutazioni dell'AI.

### Esecuzione dell'Attacco
1. Utilizziamo un container Nmap temporaneo per lanciare un "TCP SYN Scan" contro il nostro Proxy Envoy. Esegui:
   ```bash
   docker run --rm --network zerotrusthr_zerotrust_net instrumentisto/nmap -sS -p- -T4 zerotrust-envoy
   ```
2. Attendi circa 10-15 secondi che la scansione finisca. Snort intercetterà il traffico TCP anomalo sulla porta 10000 e genererà un alert in `snort/logs/alert_json.txt`.

### Verifica su Splunk
1. Torna su Splunk ed esegui la ricerca dedicata all'IDS:
   ```spl
   search index=zerotrust sourcetype=_json 
   | search "Nmap" OR "alert"
   | table msg src_addr dst_addr proto action
   ```
2. **Risultato atteso**: Comparirà l'evento `Nmap Scan Detected` con l'indirizzo IP della sorgente. Il sistema, rilevando questo evento, assocerà all'IP un $P_{net}$ elevatissimo (es. 0.95), bloccando preventivamente le richieste future da quel nodo.

---

## 6. Conclusione: Il Rischio Totale e la Blocklist

Grazie ai dati comportamentali valutati dall'**Intelligenza Artificiale** ($P_{app}$) e ai dati infrastrutturali di rete ($P_{net}$), il backend e Splunk hanno tutte le informazioni necessarie:
- Quando viene fatta una nuova richiesta, viene determinato l'impatto della risorsa.
- Viene interrogato in tempo reale il modello Machine Learning per la probabilità applicativa.
- OPA emette la decisione bloccando l'utente se il `Risk Score` combinato supera la soglia di tolleranza per quella specifica risorsa, chiudendo il ciclo architetturale Zero Trust.
