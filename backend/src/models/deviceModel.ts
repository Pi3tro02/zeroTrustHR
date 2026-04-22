import { Device, DeviceStatus, DeviceType } from "../types/device";

interface CreateDeviceParams {
  user_id: string;
  device_name: string;
  device_type: DeviceType;
  os: string;
  ip_address: string;
  trusted?: boolean;
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
  user_id,
  device_name,
  device_type,
  os,
  ip_address,
  trusted = false,
  ja3_fingerprint = null,
  status = "active"
}: CreateDeviceParams): Device {
  const now = new Date();

  return {
    user_id,
    device_name,
    device_type,
    os,
    ip_address,
    trusted,
    ja3_fingerprint,
    status,
    last_seen: now,
    created_at: now,
    updated_at: now
  };
}