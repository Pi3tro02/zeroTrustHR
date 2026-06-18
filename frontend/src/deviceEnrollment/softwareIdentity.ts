import forge from "node-forge";

function generateRsaKeyPair(): Promise<forge.pki.rsa.KeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (error, keypair) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(keypair);
    });
  });
}

async function createDemoJa3Fingerprint(): Promise<string> {
  const source = [
    navigator.userAgent,
    navigator.platform,
    navigator.language
  ].join("|");
  const bytes = new TextEncoder().encode(source);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function createSoftwareEnrollmentIdentity(params: {
  deviceId: string;
  certificateSanUri: string;
}) {
  const keypair = await generateRsaKeyPair();
  const csr = forge.pki.createCertificationRequest();

  csr.publicKey = keypair.publicKey;
  csr.setSubject([
    {
      name: "commonName",
      value: params.deviceId
    },
    {
      name: "organizationName",
      value: "ZeroTrustHR"
    },
    {
      name: "organizationalUnitName",
      value: "software-fallback"
    }
  ]);
  csr.setAttributes([
    {
      name: "extensionRequest",
      extensions: [
        {
          name: "subjectAltName",
          altNames: [
            {
              type: 6,
              value: params.certificateSanUri
            }
          ]
        }
      ]
    }
  ]);
  csr.sign(keypair.privateKey, forge.md.sha256.create());

  return {
    csrPem: forge.pki.certificationRequestToPem(csr),
    publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey),
    ja3Fingerprint: await createDemoJa3Fingerprint()
  };
}
