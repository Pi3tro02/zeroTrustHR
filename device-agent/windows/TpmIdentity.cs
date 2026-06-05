using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class TpmIdentity
{
    private const string KeyName = "ZeroTrustHR-Device-Identity";

    public static CngKey CreateNonExportableTpmKey()
    {
        var parameters = new CngKeyCreationParameters
        {
            Provider = new CngProvider("Microsoft Platform Crypto Provider"),
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
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

    public static byte[] CreateCertificateRequestDer(CngKey key)
    {
        using var rsa = new RSACng(key);

        var request = new CertificateRequest(
            "CN=zerotrusthr-device,O=ZeroTrustHR,OU=tpm",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        return request.CreateSigningRequest();
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
