const BACKEND_BASE_URL = import.meta.env.VITE_BACKEND_BASE_URL ?? "http://localhost:3000";
const PROTECTED_BASE_URL = import.meta.env.VITE_PROTECTED_BASE_URL ?? "https://localhost:10000";

export type UserRole = "customer" | "employee" | "hr" | "admin";
export type DeviceStatus = "pending" | "active" | "suspended" | "revoked";

export interface AuthUser {
  id: string;
  username: string;
  role: UserRole;
  department: string;
  name: {
    first: string;
    last: string;
  };
  email: string;
  status: string;
  mfa_enabled: boolean;
}

export interface UserDevice {
  id: string;
  device_id: string;
  user_id: string;
  device_name: string;
  device_type: string;
  os: string;
  ip_address: string;
  trusted: boolean;
  hardware_key_type: string;
  certificate_subject?: string | null;
  certificate_san_uri?: string | null;
  ja3_fingerprint?: string | null;
  status: DeviceStatus;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface ProtectedResourceResponse {
  message: string;
  resource?: string;
  data?: unknown[];
  error?: string;
  deny_reasons?: string[];
}

export interface ProtectedResourceDefinition {
  path: string;
  resourceName: string;
}

async function parseJsonResponse(response: Response) {
  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.message ?? "Richiesta fallita");
  }

  return body;
}

async function parseProtectedResponse(response: Response): Promise<ProtectedResourceResponse> {
  const body = await response.json().catch(() => ({
    message: response.statusText || "Risposta non JSON dalla risorsa protetta"
  }));

  if (!response.ok) {
    return {
      message: body.message ?? body.error ?? "Accesso negato alla risorsa protetta",
      error: body.error,
      deny_reasons: body.deny_reasons
    };
  }

  return body as ProtectedResourceResponse;
}

export async function login(params: { username: string; password: string }) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(params)
  });

  return parseJsonResponse(response) as Promise<{
    message: string;
    token: string;
    user: AuthUser;
  }>;
}

export async function getMe(token: string) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/auth/me`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    user: AuthUser;
  }>;
}

export async function getMyDevices(token: string) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/devices/me`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    devices: UserDevice[];
  }>;
}

export async function getDevicesByStatus(token: string, status: DeviceStatus) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/devices?status=${status}`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    devices: UserDevice[];
  }>;
}

export async function approveDevice(token: string, deviceId: string) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/devices/${deviceId}/approve`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    message: string;
    device_id: string;
    certificate_pem?: string;
  }>;
}

export async function rejectDevice(token: string, deviceId: string) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/devices/${deviceId}/reject`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    message: string;
    device_id: string;
    status: "suspended";
  }>;
}

export async function revokeDevice(token: string, deviceId: string) {
  const response = await fetch(`${BACKEND_BASE_URL}/api/devices/${deviceId}/revoke`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return parseJsonResponse(response) as Promise<{
    message: string;
    device_id: string;
    status: "revoked";
  }>;
}

export async function getProtectedResource(params: {
  token: string;
  user: AuthUser;
  device: UserDevice;
  resource: ProtectedResourceDefinition;
}) {
  const response = await fetch(`${PROTECTED_BASE_URL}${params.resource.path}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${params.token}`,
      "x-user": params.user.username,
      "x-role": params.user.role,
      "x-department": params.user.department,
      "x-mfa-enabled": String(params.user.mfa_enabled),
      "x-resource-name": params.resource.resourceName,
      "x-action": "read",
      "x-device-trusted": String(params.device.trusted),
      "x-device-status": params.device.status,
      "x-device-os": params.device.os,
      "x-device-ip": params.device.ip_address,
      "x-ja3": params.device.ja3_fingerprint ?? ""
    }
  });

  return {
    ok: response.ok,
    status: response.status,
    body: await parseProtectedResponse(response)
  };
}

export async function getEmployeeRecords(params: {
  token: string;
  user: AuthUser;
  device: UserDevice;
}) {
  return getProtectedResource({
    ...params,
    resource: {
      path: "/protected/employee-records",
      resourceName: "employee_records"
    }
  });
}
