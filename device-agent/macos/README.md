# Guida al Device Agent macOS (Secure Enclave / Apple T2)

Questo documento descrive come usare il device-agent macOS per completare la fase di enrollment di un dispositivo hardware-bound.  
L'obiettivo è generare i dati richiesti dal frontend usando una chiave privata **non esportabile** custodita nel Secure Enclave / chip Apple T2.

Il device-agent produce:
- **CSR PEM**: richiesta di certificato firmata dalla chiave privata del dispositivo.
- **Public key PEM**: chiave pubblica associata alla chiave privata non esportabile.
- **Firma challenge in Base64**: prova crittografica che il dispositivo possiede la private key.

---

## 1. Prerequisiti

Per usare il flusso reale con chiave persistente nel Keychain sono necessari:

- macOS su dispositivo con Secure Enclave o chip Apple T2.
- Xcode installato.
- Apple Development Certificate creato da Xcode.
- Target macOS App con signing automatico abilitato.
- Capability **Keychain Sharing** attiva.

Per verificare la presenza del chip Apple T2:

```bash
system_profiler SPiBridgeDataType
```

Risultato atteso su Mac Intel con T2:

```text
Chip di sicurezza Apple T2
```

---

## 2. Perché serve un'app macOS e non solo un CLI

La chiave Secure Enclave deve essere:

- generata localmente sul dispositivo;
- non esportabile;
- riutilizzabile dopo l'enrollment;
- associata a un'identità applicativa stabile.

Un binario CLI compilato con `swiftc` può firmare temporaneamente una challenge, ma spesso non può salvare una chiave permanente nel Keychain. In quel caso macOS restituisce:

```text
NSOSStatusErrorDomain Code=-34018
```

Per la versione reale è quindi necessario eseguire il codice dentro una vera app macOS firmata e provisionata da Xcode.

---

## 3. Creazione del progetto Xcode

1. Apri Xcode.
2. Seleziona `File -> New -> Project...`.
3. Scegli `macOS -> App`.
4. Imposta:

```text
Product Name: ZeroTrustHRDeviceAgent
Interface: SwiftUI
Language: Swift
Testing System: None
Storage: None
```

5. Usa un bundle identifier stabile, ad esempio:

```text
it.zerotrusthr.device-agent
```

6. Dopo la creazione del progetto, apri il target `ZeroTrustHRDeviceAgent`.
7. Vai in `Signing & Capabilities`.
8. Abilita:

```text
Automatically manage signing
Team: il tuo Personal Team / Apple Development Team
```

9. Premi `+ Capability` e aggiungi:

```text
Keychain Sharing
```

10. Il gruppo Keychain deve iniziare con il Team ID Apple, ad esempio:

```text
TEAMID.it.zerotrusthr.device-agent
```

---

## 4. File Swift da aggiungere al progetto Xcode

Aggiungi al target Xcode questi file:

```text
device-agent/macos/SecureEnclaveIdentity.swift
device-agent/macos/EnrollmentOutput.swift
device-agent/macos/DeviceAgentApp.swift
```

Se Xcode ha generato automaticamente un file `ZeroTrustHRDeviceAgentApp.swift`, deve esserci un solo `@main` nel progetto.

Configurazione consigliata:

- `ZeroTrustHRDeviceAgentApp.swift`: contiene `@main`.
- `DeviceAgentApp.swift`: contiene solo la view `EnrollmentView`.

In alternativa, rimuovi il file generato da Xcode e lascia `@main` dentro `DeviceAgentApp.swift`.

---

## 5. Flusso di enrollment

1. Avvia il frontend ZeroTrustHR.
2. Accedi con l'utente da registrare.
3. Seleziona `Secure Enclave` come hardware key.
4. Premi `Crea challenge`.
5. Il frontend compilerà:

```text
Device ID
Certificate SAN URI
Stato enrollment
Challenge da firmare con device-agent nativo
```

6. Apri l'app macOS `ZeroTrustHRDeviceAgent` da Xcode.
7. Incolla nell'app:

```text
Device ID
Certificate SAN URI
Challenge
```

8. Premi `Genera dati enrollment`.
9. L'app genera un JSON con:

```json
{
  "challengeSignature": "...",
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----..."
}
```

10. Copia i tre valori nel frontend:

```text
csrPem             -> CSR PEM generata dal device-agent
publicKeyPem       -> Public key PEM del dispositivo
challengeSignature -> Firma challenge in Base64
```

11. Premi `Verifica enrollment`.
12. Quando il frontend mostra `Enrollment verificato`, l'admin può approvare il dispositivo.

---

## 6. Approvazione admin e certificato

Dopo la verifica dell'enrollment:

1. L'admin accede alla dashboard.
2. Trova il dispositivo nello stato `pending`.
3. Approva il dispositivo.
4. Il backend invia la CSR al servizio CA.
5. La CA firma il certificato client mTLS.
6. Il dispositivo passa allo stato `active` / `trusted`.

Da quel momento il certificato emesso identifica il dispositivo nelle richieste mTLS verso Envoy.

---

## 7. Build CLI per test rapido

Il CLI è utile solo per test tecnici. Per il flusso reale persistente usare l'app Xcode descritta sopra.

Compilazione:

```bash
CLANG_MODULE_CACHE_PATH=/tmp/zerotrusthr-swift-module-cache swiftc \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/SecureEnclaveIdentity.swift \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/EnrollmentOutput.swift \
  /Users/pietrosalvatore/zeroTrustHR/device-agent/macos/main.swift \
  -o /tmp/ZeroTrustHRDeviceAgent
```

Esecuzione:

```bash
/tmp/ZeroTrustHRDeviceAgent \
  "DEVICE_ID_DAL_FRONTEND" \
  "CERTIFICATE_SAN_URI_DAL_FRONTEND" \
  "CHALLENGE_DAL_FRONTEND"
```

Se compare l'errore `-34018`, usare il progetto Xcode con Keychain Sharing.

---

## 8. Troubleshooting

### Errore `-34018`

Significa che macOS non consente al processo di salvare la chiave nel Keychain.

Controllare:

- Il target è una vera app macOS.
- `Automatically manage signing` è attivo.
- Il Team Apple è selezionato.
- `Keychain Sharing` è presente.
- Il bundle identifier è stabile.
- Il gruppo Keychain inizia con il Team ID.

### Errore `Invalid redeclaration of ZeroTrustHRDeviceAgentApp`

Nel progetto esistono due `@main`.

Soluzione:

- lasciare `@main` in un solo file;
- rimuovere o modificare l'altro file generato automaticamente da Xcode.

### Frontend bloccato su `Verifico firma hardware e salvo CSR...`

Controllare i log del backend:

```bash
docker compose logs -f backend
```

Risultato atteso durante la verifica:

```text
[Device Enrollment] enroll start
[Device Enrollment] pending device found
[Device Enrollment] verifying hardware challenge signature
[Device Enrollment] hardware challenge signature verified
[Device Enrollment] saving CSR and public key
[Device Enrollment] enrollment saved
```

Se il device arriva all'admin ma manca la CSR, significa che è stata creata la challenge ma non è stata completata la fase `Verifica enrollment`.
