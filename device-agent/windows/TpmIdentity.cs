using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class TpmIdentity
{
    private const string KeyName = "ZeroTrustHR-Device-Identity";
    private static readonly CngProvider TpmProvider = new("Microsoft Platform Crypto Provider");

    public static CngKey CreateOrLoadNonExportableTpmKey()
    {
        if (CngKey.Exists(KeyName, TpmProvider))
        {
            return CngKey.Open(KeyName, TpmProvider);
        }

        return CreateNonExportableTpmKey();
    }

    private static CngKey CreateNonExportableTpmKey()
    {
        var parameters = new CngKeyCreationParameters
        {
            Provider = TpmProvider,
            ExportPolicy = CngExportPolicies.None
        };

        parameters.Parameters.Add(
            new CngProperty(
                "Length",
                BitConverter.GetBytes(2048),
                CngPropertyOptions.None
            )
        );

        return CngKey.Create(CngAlgorithm.Rsa, KeyName, parameters);
    }

    public static byte[] CreateCertificateRequestDer(CngKey key, string deviceId)
    {
        using var rsa = new RSACng(key);

        var request = new CertificateRequest(
            $"CN=zerotrusthr-device,O=ZeroTrustHR,OU=tpm,SERIALNUMBER={deviceId}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        return request.CreateSigningRequest();
    }

    public static byte[] ExportPublicKeyDer(CngKey key)
    {
        using var rsa = new RSACng(key);
        return rsa.ExportSubjectPublicKeyInfo();
    }

    public static byte[] SignChallenge(CngKey key, string challenge)
    {
        using var rsa = new RSACng(key);
        var challengeBytes = Encoding.UTF8.GetBytes(challenge);

        return rsa.SignData(
            challengeBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }

    public static string ToPem(string label, byte[] der)
    {
        var base64 = Convert.ToBase64String(der);
        var builder = new StringBuilder();

        builder.AppendLine($"-----BEGIN {label}-----");

        for (var i = 0; i < base64.Length; i += 64)
        {
            builder.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
        }

        builder.AppendLine($"-----END {label}-----");

        return builder.ToString();
    }
}
