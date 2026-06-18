import { useState } from "react";
import {
  approveDevice,
  createEnrollmentChallenge,
  enrollDevice,
  type HardwareKeyType,
} from "./deviceEnrollment/api";
import { downloadTextFile } from "./deviceEnrollment/download";
import { createSoftwareEnrollmentIdentity } from "./deviceEnrollment/softwareIdentity";

interface DeviceEnrollmentProps {
  jwt: string;
  embedded?: boolean;
  showAdminApprove?: boolean;
}

export function DeviceEnrollment({
  jwt,
  embedded = false,
  showAdminApprove = false
}: DeviceEnrollmentProps) {
  const [deviceName, setDeviceName] = useState("macbook-pietro");
  const [deviceType, setDeviceType] = useState("laptop");
  const [os, setOs] = useState("macOS");
  const [hardwareKeyType, setHardwareKeyType] =
    useState<HardwareKeyType>("software");

  const [deviceId, setDeviceId] = useState("");
  const [challenge, setChallenge] = useState("");
  const [certificateSanUri, setCertificateSanUri] = useState("");
  const [enrollmentStatus, setEnrollmentStatus] = useState("");
  const [csrPem, setCsrPem] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [challengeSignature, setChallengeSignature] = useState("");
  const [ja3Fingerprint, setJa3Fingerprint] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [creatingChallenge, setCreatingChallenge] = useState(false);

  const isSoftwareFallback = hardwareKeyType === "software";
  const isHardwareBound = hardwareKeyType === "tpm" || hardwareKeyType === "secure_enclave";

  async function handleCreateChallenge() {
    setCreatingChallenge(true);
    setError("");
    setStatus("Creo la challenge di enrollment...");
    setDeviceId("");
    setChallenge("");
    setCertificateSanUri("");
    setEnrollmentStatus("");
    setCsrPem("");
    setPublicKeyPem("");
    setChallengeSignature("");
    setJa3Fingerprint("");

    try {
      const result = await createEnrollmentChallenge({
        jwt,
        deviceName,
        deviceType,
        os,
        hardwareKeyType,
      });

      setDeviceId(result.device_id);
      setChallenge(result.challenge);
      setCertificateSanUri(result.certificate_san_uri);
      setEnrollmentStatus(result.status);
      setStatus(`Challenge creata per il device ${result.device_id}`);

      if (hardwareKeyType === "software") {
        setStatus("Genero identita software e verifico enrollment...");

        const softwareIdentity = await createSoftwareEnrollmentIdentity({
          deviceId: result.device_id,
          certificateSanUri: result.certificate_san_uri
        });

        setCsrPem(softwareIdentity.csrPem);
        setPublicKeyPem(softwareIdentity.publicKeyPem);
        setJa3Fingerprint(softwareIdentity.ja3Fingerprint);

        const enrollmentResult = await enrollDevice({
          jwt,
          deviceId: result.device_id,
          csrPem: softwareIdentity.csrPem,
          publicKeyPem: softwareIdentity.publicKeyPem,
          ja3Fingerprint: softwareIdentity.ja3Fingerprint
        });

        setEnrollmentStatus(enrollmentResult.status);
        setStatus(`Enrollment verificato automaticamente: ${enrollmentResult.device_id}`);
      }
    } catch (error) {
      setError((error as Error).message);
      setStatus("");
    } finally {
      setCreatingChallenge(false);
    }
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

  const content = (
    <section className={embedded ? "enrollment-panel" : "panel"}>
        <h1>ZeroTrustHR Device Enrollment</h1>

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

        <button onClick={handleCreateChallenge} disabled={creatingChallenge}>
          {creatingChallenge
            ? "Enrollment in corso..."
            : isSoftwareFallback
              ? "Crea challenge e verifica enrollment"
              : "Crea challenge"}
        </button>

        <label>
          Device ID
          <input readOnly value={deviceId} />
        </label>

        <label>
          Certificate SAN URI
          <input readOnly value={certificateSanUri} />
        </label>

        <label>
          Stato enrollment
          <input readOnly value={enrollmentStatus} />
        </label>

        {isHardwareBound && (
          <label>
            Challenge da firmare con device-agent nativo
            <textarea readOnly value={challenge} />
          </label>
        )}

        <label>
          CSR PEM generata dal device-agent
          <textarea
            readOnly={isSoftwareFallback}
            value={csrPem}
            onChange={(event) => setCsrPem(event.target.value)}
          />
        </label>

        <label>
          Public key PEM del dispositivo
          <textarea
            readOnly={isSoftwareFallback}
            value={publicKeyPem}
            onChange={(event) => setPublicKeyPem(event.target.value)}
          />
        </label>

        {isSoftwareFallback && (
          <label>
            JA3 fingerprint 
            <input 
              readOnly={isSoftwareFallback}
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

        {!isSoftwareFallback && (
          <button
            onClick={handleEnroll}
            disabled={!deviceId ||
              !csrPem ||
              !publicKeyPem ||
              (isHardwareBound && !challengeSignature)
            }
          >
            Verifica enrollment
          </button>
        )}

        {showAdminApprove && (
          <button onClick={handleApprove} disabled={!deviceId}>
            Approva e scarica certificato
          </button>
        )}

        {status && <p>{status}</p>}
        {error && <p className="status-message error">{error}</p>}
      </section>
  );

  if (embedded) {
    return content;
  }

  return (
    <main className="page">
      {content}
    </main>
  );
}
