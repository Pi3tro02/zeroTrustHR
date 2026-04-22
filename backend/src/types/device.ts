export type DeviceStatus = "active" | "suspended" | "revoked";
export type DeviceType = "laptop" | "desktop" | "smartphone" | "tablet" | "server" | "other";

export interface Device {
  user_id: string;
  device_name: string;
  device_type: DeviceType;
  os: string;
  ip_address: string;
  trusted: boolean;
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