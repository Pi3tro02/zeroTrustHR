export type DeviceStatus = "pending" | "active" | "suspended" | "revoked";
export type DeviceType = "laptop" | "desktop" | "smartphone" | "tablet" | "server" | "other";
export type HardwareKeyType = "tpm" | "secure_enclave" | "android_keystore" | "software";

export interface Device {
  device_id: string;
  user_id: string;
  device_name: string;
  device_type: DeviceType;
  os: string;
  ip_address: string;
  trusted: boolean;
  hardware_key_type: HardwareKeyType;
  certificate_subject?: string | null;
  certificate_san_uri?: string | null;
  ja3_fingerprint?: string | null;
  status: DeviceStatus;
  last_seen: Date;
  created_at: Date;
  updated_at: Date;
}

/* trusted: indica se il dispositivo lo conosco, come ad esempio una laptop aziendale
* status: indica lo stato del dispositivo
 * - active: dispositivo attivo
 * - suspended: dispositivo sospesa, ad esempio per comportamenti sospetti
 * - revoked: dispositivo compromesso, bannato o certificato revocato
 */
