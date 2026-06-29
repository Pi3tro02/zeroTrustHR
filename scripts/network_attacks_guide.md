# Guida agli Attacchi di Rete (IDS/Snort)

Questo documento illustra i comandi necessari per simulare gli attacchi di rete. Tali attacchi vengono rilevati dall'Intrusion Detection System (Snort) a livello infrastrutturale, dimostrando la priorità del Rischio di Rete ($P_{net}$) nell'architettura Zero Trust.

## Prerequisiti
- È possibile utilizzare container Docker usa-e-getta (già inclusi nei comandi sottostanti) per lanciare gli attacchi direttamente all'interno della rete locale `zerotrusthr_zerotrust_net`, simulando un nodo compromesso.

---

## 1. Port Scanning (Nmap)

La scansione delle porte viene utilizzata per mappare i servizi esposti. Snort è configurato per intercettare raffiche di pacchetti TCP SYN anomale.

**Comando per lanciare l'attacco tramite container Docker:**
```bash
docker run --rm --network zerotrusthr_zerotrust_net instrumentisto/nmap -sS -p- -T4 zerotrust-envoy
```

**Verifica su Splunk:**
1. Accedere all'interfaccia web di Splunk.
2. Eseguire la seguente query:
   ```spl
   search index=zerotrust sourcetype=_json 
   | search "Nmap" OR "alert"
   | table msg src_addr dst_addr proto action
   ```
3. **Risultato atteso**: Comparirà l'alert `Nmap Scan Detected (Port 10000)` con l'indirizzo IP della sorgente. Da questo momento, qualsiasi richiesta proveniente da quell'IP riceverà un Risk Score di rete elevatissimo ($P_{net} = 0.95$), causando il blocco immediato dell'utente da parte del policy engine.

---

## 2. Password Brute Force (Hydra) su endpoint mTLS

In questo test viene sferrato un attacco HTTP Brute Force contro il proxy Envoy, per dimostrare l'efficacia del livello di sicurezza perimetrale (mTLS).

**Preparazione (creazione wordlist):**
Creare un file `passwords.txt` nella cartella di progetto contenente alcune password di test (es. `admin`, `password`, `123456`).

**Comando per lanciare l'attacco tramite container Docker:**
```bash
docker run --rm -v "${PWD}/passwords.txt:/passwords.txt" --network zerotrusthr_zerotrust_net secsi/hydra -l admin -P /passwords.txt -s 10000 zerotrust-envoy http-post-form "/api/auth/login:username=^USER^&password=^PASS^:F=Unauthorized"
```

**Risultato atteso (Defense in Depth):**
L'attacco fallirà quasi istantaneamente con un errore di rete (es. `1 target did not resolve or could not be connected`). Questo rappresenta un successo architetturale: Envoy, aspettandosi un handshake mTLS crittografato, rifiuta e chiude immediatamente le connessioni HTTP inviate in chiaro dall'attaccante. 
Questo livello di difesa perimetrale garantisce la neutralizzazione degli attacchi grossolani a monte, prima ancora che raggiungano l'Intrusion Detection System o il motore predittivo di Machine Learning.
