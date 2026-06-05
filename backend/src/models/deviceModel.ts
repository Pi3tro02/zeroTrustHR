import { Device, DeviceStatus, DeviceType, HardwareKeyType } from "../types/device";

interface CreateDeviceParams {
  device_id: string;
  user_id: string;
  device_name: string;
  device_type: DeviceType;
  os: string;
  ip_address: string;
  trusted?: boolean;
  hardware_key_type?: HardwareKeyType;
  public_key_pem?: string | null;
  enrollment_challenge?: string | null;
  challenge_expires_at?: Date | null;
  challenge_verified_at?: Date | null;
  certificate_subject?: string | null;
  certificate_san_uri?: string | null;
  ja3_fingerprint?: string | null;
  status?: DeviceStatus;
}

/**
 * Crea un documento device.
 *
 * Logica:
 * - un device nuovo/sconosciuto può essere active ma trusted = false
 * - suspended indica un device temporaneamente bloccato o sospetto
 * - revoked indica un device revocato/non più ammesso
 */
export function createDevice({
  device_id,
  user_id,
  device_name,
  device_type,
  os,
  ip_address,
  trusted = false,
  hardware_key_type = "software",
  public_key_pem = null,
  enrollment_challenge = null,
  challenge_expires_at = null,
  challenge_verified_at = null,
  certificate_subject = null,
  certificate_san_uri = null,
  ja3_fingerprint = null,
  status = "active"
}: CreateDeviceParams): Device {
  const now = new Date();

  return {
    device_id,
    user_id,
    device_name,
    device_type,
    os,
    ip_address,
    trusted,
    hardware_key_type,
    public_key_pem,
    enrollment_challenge,
    challenge_expires_at,
    challenge_verified_at,
    certificate_subject,
    certificate_san_uri,
    ja3_fingerprint,
    status,
    last_seen: now,
    created_at: now,
    updated_at: now
  };
}
