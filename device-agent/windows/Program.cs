using System;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length != 3)
{
    Console.Error.WriteLine("""
    Uso:
      ZeroTrustHR.TpmAgent.exe <device_id> <certificate_san_uri> <challenge>

    Esempio:
      ZeroTrustHR.TpmAgent.exe "abc-device-id" "urn:zerotrusthr:device:abc-device-id" "challenge-dal-frontend"
    """);
    Environment.Exit(1);
}

var deviceId = args[0].Trim();
var certificateSanUri = args[1].Trim();
var challenge = args[2];

if (string.IsNullOrWhiteSpace(deviceId) ||
    certificateSanUri != $"urn:zerotrusthr:device:{deviceId}" ||
    string.IsNullOrWhiteSpace(challenge))
{
    Console.Error.WriteLine("Argomenti non validi: controlla Device ID, Certificate SAN URI e challenge.");
    Environment.Exit(1);
}

try
{
    using var key = TpmIdentity.CreateOrLoadNonExportableTpmKey();

    var output = new EnrollmentOutput(
        CsrPem: TpmIdentity.ToPem(
            "CERTIFICATE REQUEST",
            TpmIdentity.CreateCertificateRequestDer(key, deviceId)
        ),
        PublicKeyPem: TpmIdentity.ToPem(
            "PUBLIC KEY",
            TpmIdentity.ExportPublicKeyDer(key)
        ),
        ChallengeSignature: Convert.ToBase64String(
            TpmIdentity.SignChallenge(key, challenge)
        )
    );

    Console.WriteLine(JsonSerializer.Serialize(output, new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    }));
}
catch (Exception error)
{
    if (error is CryptographicException cryptoError)
    {
        Console.Error.WriteLine($"""
        Errore TPM/CNG: {cryptoError.Message}

        Verifiche sul PC Windows:
          1. Apri PowerShell come amministratore.
          2. Esegui: Get-Tpm
          3. Controlla che TpmPresent=True e TpmReady=True.
          4. Se TpmReady=False, apri tpm.msc e verifica che il TPM sia inizializzato/abilitato.

        Nota: non eseguire Clear-Tpm senza prima verificare BitLocker/chiavi di ripristino.
        """);
        Environment.Exit(1);
    }

    Console.Error.WriteLine(error.Message);
    Environment.Exit(1);
}

internal sealed record EnrollmentOutput(
    string CsrPem,
    string PublicKeyPem,
    string ChallengeSignature
);
