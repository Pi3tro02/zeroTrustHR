# ZeroTrustHR TPM Device Agent

Questo agent Windows genera i dati di enrollment usando una chiave privata RSA
non esportabile custodita nel TPM tramite `Microsoft Platform Crypto Provider`.

## Verifica TPM

Prima di eseguire l'agent, aprire PowerShell come amministratore:

```powershell
Get-Tpm
```

Risultato atteso:

```text
TpmPresent : True
TpmReady   : True
```

Se `TpmPresent` è `False`, il PC non espone un TPM utilizzabile da Windows.
Se `TpmReady` è `False`, aprire `tpm.msc` e verificare che il TPM sia abilitato
e inizializzato.

Non eseguire `Clear-Tpm` senza prima controllare BitLocker e la chiave di
ripristino del dispositivo.

## Build

```powershell
cd device-agent\windows
dotnet build -c Release
```

## Esecuzione

Dal frontend copia:

- `Device ID`
- `Certificate SAN URI`
- `Challenge da firmare con device-agent nativo`

Poi esegui:

```powershell
.\bin\Release\net8.0-windows\ZeroTrustHR.TpmAgent.exe `
  "DEVICE_ID_DAL_FRONTEND" `
  "CERTIFICATE_SAN_URI_DAL_FRONTEND" `
  "CHALLENGE_DAL_FRONTEND"
```

L'output JSON contiene:

```json
{
  "csrPem": "...",
  "publicKeyPem": "...",
  "challengeSignature": "..."
}
```

Questi tre valori vanno copiati nei campi corrispondenti del frontend e poi si
preme `Verifica enrollment`.

## Troubleshooting

### `Il dispositivo necessario per il provider del servizio di crittografia non è pronto per l'uso`

Questo errore arriva da Windows CNG prima della generazione della CSR. Le cause
più comuni sono:

- TPM disabilitato dal BIOS/UEFI.
- TPM non inizializzato in Windows.
- PC virtuale o ambiente senza TPM esposto.
- Policy aziendale/antivirus che blocca il provider TPM.

Controllare:

```powershell
Get-Tpm
tpm.msc
```
