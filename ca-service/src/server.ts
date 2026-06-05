import express, { Request, Response, NextFunction } from "express";
import { mkdtemp, readFile, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
const app = express();

app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT ?? 4000;
const CA_CERT_PATH = process.env.CA_CERT_PATH ?? "/ca/ca.crt";
const CA_KEY_PATH = process.env.CA_KEY_PATH ?? "/ca/ca.key";
const CA_SERIAL_PATH = process.env.CA_SERIAL_PATH ?? "/tmp/zerotrusthr-ca.srl";
const CA_SERVICE_TOKEN = process.env.CA_SERVICE_TOKEN ?? "dev-ca-token";

interface SignRequest {
  csr_pem?: string;
  device_id?: string;
  san_uri?: string;
  public_key_pem?: string;
}

function normalizePem(pem: string): string {
  return pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
}

function requireServiceToken(req: Request, res: Response, next: NextFunction): void {
  const token = req.header("x-ca-service-token");

  if (token !== CA_SERVICE_TOKEN) {
    res.status(401).json({ message: "Token servizio CA non valido" });
    return;
  }

  next();
}

function validateSignRequest(body: SignRequest): asserts body is Required<SignRequest> {
  if (!body.csr_pem || !body.device_id || !body.san_uri || !body.public_key_pem) {
    throw new Error("Campi obbligatori mancanti: csr_pem, device_id, san_uri, public_key_pem");
  }

  if (!body.san_uri.startsWith(`urn:zerotrusthr:device:${body.device_id}`)) {
    throw new Error("san_uri non coerente con device_id");
  }

  if (!body.csr_pem.includes("BEGIN CERTIFICATE REQUEST")) {
    throw new Error("CSR non valida");
  }

  if (!body.public_key_pem.includes("BEGIN PUBLIC KEY")) {
    throw new Error("Public key non valida");
  }
}

async function signCsr({ csr_pem, device_id, san_uri, public_key_pem }: Required<SignRequest>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "zerotrust-ca-"));

  try {
    const csrPath = join(dir, `${device_id}.csr`);
    const certPath = join(dir, `${device_id}.crt`);
    const extPath = join(dir, `${device_id}.ext`);

    await writeFile(csrPath, csr_pem, "utf8");

    const { stdout: csrPublicKeyPem } = await execFileAsync("openssl", [
      "req",
      "-in", csrPath,
      "-pubkey",
      "-noout"
    ]);

    if (normalizePem(csrPublicKeyPem) !== normalizePem(public_key_pem)) {
      throw new Error("La public key della CSR non coincide con quella verificata via challenge");
    }

    await writeFile(
      extPath,
      [
        "basicConstraints=CA:FALSE",
        "keyUsage=digitalSignature,keyEncipherment",
        "extendedKeyUsage=clientAuth",
        `subjectAltName=URI:${san_uri},DNS:${device_id}`,
        ""
      ].join("\n"),
      "utf8"
    );

    await execFileAsync("openssl", [
      "x509",
      "-req",
      "-in", csrPath,
      "-CA", CA_CERT_PATH,
      "-CAkey", CA_KEY_PATH,
      "-CAserial", CA_SERIAL_PATH,
      "-CAcreateserial",
      "-out", certPath,
      "-days", "365",
      "-sha256",
      "-extfile", extPath
    ]);

    return await readFile(certPath, "utf8");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

app.post("/sign", requireServiceToken, async (req, res) => {
  try {
    const body = req.body as SignRequest;
    validateSignRequest(body);

    const certificatePem = await signCsr(body);

    res.status(200).json({
      certificate_pem: certificatePem
    });
  } catch (error) {
    res.status(400).json({
      message: (error as Error).message
    });
  }
});

app.listen(PORT, () => {
  console.log(`CA service avviato sulla porta ${PORT}`);
});
