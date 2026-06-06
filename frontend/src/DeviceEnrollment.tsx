import { useState } from "react";
import {
  approveDevice,
  createEnrollmentChallenge,
  enrollDevice,
  type HardwareKeyType,
} from "./deviceEnrollment/api";
import { downloadTextFile } from "./deviceEnrollment/download";

export function DeviceEnrollment() {
  const [jwt, setJwt] = useState("");
  const [deviceName, setDeviceName] = useState("macbook-pietro");
  const [deviceType, setDeviceType] = useState("laptop");
  const [os, setOs] = useState("macOS");
  const [hardwareKeyType, setHardwareKeyType] =
    useState<HardwareKeyType>("secure_enclave");

  const [deviceId, setDeviceId] = useState("");
  const [challenge, setChallenge] = useState("");
  const [csrPem, setCsrPem] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [challengeSignature, setChallengeSignature] = useState("");
  const [ja3Fingerprint, setJa3Fingerprint] = useState("");
  const [status, setStatus] = useState("");

  const isSoftwareFallback = hardwareKeyType === "software";
  const isHardwareBound = hardwareKeyType === "tpm" || hardwareKeyType === "secure_enclave";

  async function handleCreateChallenge() {
    setStatus("Creo la challenge di enrollment...");

    const result = await createEnrollmentChallenge({
      jwt,
      deviceName,
      deviceType,
      os,
      hardwareKeyType,
    });

    setDeviceId(result.device_id);
    setChallenge(result.challenge);
    setStatus(`Challenge creata per il device ${result.device_id}`);
  }

  async function handleEnroll() {
    setStatus("Verifico firma hardware e salvo CSR...");

    const result = await enrollDevice({
      jwt,
      deviceId,
      csrPem,
      publicKeyPem,
      challengeSignature: isHardwareBound ? challengeSignature : undefined,
      ja3Fingerprint: isSoftwareFallback ? ja3Fingerprint : undefined
    });

    setStatus(`Enrollment verificato: ${result.device_id}`);
  }

  async function handleApprove() {
    setStatus("Approvo dispositivo e richiedo firma certificato...");

    const result = await approveDevice({
      jwt,
      deviceId,
    });

    downloadTextFile(`${result.device_id}.crt`, result.certificate_pem);
    setStatus("Certificato creato e scaricato.");
  }

  return (
    <main className="page">
      <section className="panel">
        <h1>ZeroTrustHR Device Enrollment</h1>

        <label>
          JWT
          <textarea value={jwt} onChange={(event) => setJwt(event.target.value)} />
        </label>

        <label>
          Nome dispositivo
          <input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} />
        </label>

        <label>
          Tipo dispositivo
          <select value={deviceType} onChange={(event) => setDeviceType(event.target.value)}>
            <option value="laptop">Laptop</option>
            <option value="desktop">Desktop</option>
            <option value="server">Server</option>
            <option value="other">Altro</option>
          </select>
        </label>

        <label>
          Sistema operativo
          <input value={os} onChange={(event) => setOs(event.target.value)} />
        </label>

        <label>
          Hardware key
          <select
            value={hardwareKeyType}
            onChange={(event) => setHardwareKeyType(event.target.value as HardwareKeyType)}
          >
            <option value="secure_enclave">Secure Enclave</option>
            <option value="tpm">TPM</option>
            <option value="software">Software fallback</option>
          </select>
        </label>

        <button onClick={handleCreateChallenge}>Crea challenge</button>

        <label>
          Device ID
          <input value={deviceId} onChange={(event) => setDeviceId(event.target.value)} />
        </label>

        {isHardwareBound && (
          <label>
            Challenge da firmare con device-agent nativo
            <textarea readOnly value={challenge} />
          </label>
        )}

        <label>
          CSR PEM generata dal device-agent
          <textarea value={csrPem} onChange={(event) => setCsrPem(event.target.value)} />
        </label>

        <label>
          Public key PEM del dispositivo
          <textarea value={publicKeyPem} onChange={(event) => setPublicKeyPem(event.target.value)} />
        </label>

        {isSoftwareFallback && (
          <label>
            JA3 fingerprint 
            <input 
              value={ja3Fingerprint}
              onChange={(event) => setJa3Fingerprint(event.target.value)}
            />
          </label>
        )}

        {isHardwareBound && (
          <label>
            Firma challenge in Base64
            <textarea 
              value={challengeSignature}
              onChange={(event) => setChallengeSignature(event.target.value)}
            />
          </label>
        )}

        <button
          onClick={handleEnroll}
          disabled={!deviceId || 
            !csrPem || 
            !publicKeyPem || 
            (isHardwareBound && !challengeSignature) ||
            (isSoftwareFallback && !ja3Fingerprint)
          }
        >
          Verifica enrollment
        </button>

        <button onClick={handleApprove} disabled={!deviceId}>
          Approva e scarica certificato
        </button>

        <p>{status}</p>
      </section>
    </main>
  );
}
