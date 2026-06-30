# ZeroTrustHR TPM Device Agent

Questo agent Windows genera i dati di enrollment usando una chiave privata RSA
non esportabile custodita nel TPM tramite `Microsoft Platform Crypto Provider`.

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
