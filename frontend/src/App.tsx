import { useEffect, useState, type FormEvent } from "react";
import "./App.css";
import {
  approveDevice,
  getDevicesByStatus,
  getMe,
  getMyDevices,
  getProtectedResource,
  login,
  rejectDevice,
  revokeDevice,
  type AuthUser,
  type DeviceStatus,
  type UserDevice
} from "./api";
import { DeviceEnrollment } from "./DeviceEnrollment";

const TOKEN_STORAGE_KEY = "zerotrusthr.jwt";
const deviceStatuses: DeviceStatus[] = ["pending", "active", "suspended", "revoked"];
const protectedResources = [
  {
    key: "employee_records",
    title: "Employee records",
    path: "/protected/employee-records",
    resourceName: "employee_records"
  },
  {
    key: "company_policies",
    title: "Company policies",
    path: "/protected/company-policies",
    resourceName: "company_policies"
  },
  {
    key: "public_products",
    title: "Public products",
    path: "/protected/public-products",
    resourceName: "public_products"
  }
] as const;

function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_STORAGE_KEY) ?? "");
  const [user, setUser] = useState<AuthUser | null>(null);
  const [devices, setDevices] = useState<UserDevice[]>([]);
  const [adminDevices, setAdminDevices] = useState<UserDevice[]>([]);
  const [adminStatus, setAdminStatus] = useState<DeviceStatus>("pending");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [adminActionDeviceId, setAdminActionDeviceId] = useState("");
  const [message, setMessage] = useState("");
  const [protectedLoadingKey, setProtectedLoadingKey] = useState("");
  const [protectedResults, setProtectedResults] = useState<Record<string, string>>({});

  const hasActiveDevice = devices.some((device) => device.status === "active");
  const activeDevice = devices.find((device) => device.status === "active");
  const isAdmin = user?.role === "admin";

  async function loadSession(jwt: string) {
    const [meResult, devicesResult] = await Promise.all([
      getMe(jwt),
      getMyDevices(jwt)
    ]);

    setUser(meResult.user);
    setDevices(devicesResult.devices);
  }

  async function loadAdminDevices(jwt: string, status: DeviceStatus) {
    const result = await getDevicesByStatus(jwt, status);
    setAdminDevices(result.devices);
  }

  useEffect(() => {
    if (!token) {
      return;
    }

    setLoading(true);
    loadSession(token)
      .catch((error) => {
        setMessage((error as Error).message);
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        setToken("");
        setUser(null);
        setDevices([]);
      })
      .finally(() => setLoading(false));
  }, [token]);

  useEffect(() => {
    if (!token || !isAdmin) {
      setAdminDevices([]);
      return;
    }

    loadAdminDevices(token, adminStatus)
      .catch((error) => setMessage((error as Error).message));
  }, [adminStatus, isAdmin, token]);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setMessage("");

    try {
      const result = await login({ username, password });
      localStorage.setItem(TOKEN_STORAGE_KEY, result.token);
      setToken(result.token);
      setUser(result.user);
      setPassword("");
      await loadSession(result.token);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken("");
    setUser(null);
    setDevices([]);
    setAdminDevices([]);
    setMessage("");
  }

  async function handleAdminDeviceAction(
    deviceId: string,
    action: "approve" | "reject" | "revoke"
  ) {
    setAdminActionDeviceId(deviceId);
    setMessage("");

    try {
      if (action === "approve") {
        await approveDevice(token, deviceId);
      }

      if (action === "reject") {
        await rejectDevice(token, deviceId);
      }

      if (action === "revoke") {
        await revokeDevice(token, deviceId);
      }

      await Promise.all([
        loadSession(token),
        loadAdminDevices(token, adminStatus)
      ]);

      setMessage(`Azione ${action} completata per ${deviceId}`);
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setAdminActionDeviceId("");
    }
  }

  async function handleProtectedResourceAccess(resource: (typeof protectedResources)[number]) {
    if (!user) {
      setProtectedResults((current) => ({
        ...current,
        [resource.key]: "Sessione utente non disponibile."
      }));
      return;
    }

    if (!activeDevice) {
      setProtectedResults((current) => ({
        ...current,
        [resource.key]: "Nessun device active disponibile per tentare l'accesso."
      }));
      return;
    }

    setProtectedLoadingKey(resource.key);
    setProtectedResults((current) => ({
      ...current,
      [resource.key]: ""
    }));

    try {
      const result = await getProtectedResource({
        token,
        user,
        device: activeDevice,
        resource: {
          path: resource.path,
          resourceName: resource.resourceName
        }
      });

      setProtectedResults((current) => ({
        ...current,
        [resource.key]: JSON.stringify(result, null, 2)
      }));
    } catch (error) {
      setProtectedResults((current) => ({
        ...current,
        [resource.key]: (error as Error).message
      }));
    } finally {
      setProtectedLoadingKey("");
    }
  }

  if (!token || !user) {
    return (
      <main className="page">
        <section className="panel auth-panel">
          <p className="eyebrow">ZeroTrustHR</p>
          <h1>Login</h1>

          <form className="form-grid" onSubmit={handleLogin}>
            <label>
              Username
              <input value={username} onChange={(event) => setUsername(event.target.value)} />
            </label>

            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>

            <button disabled={loading || !username || !password}>
              {loading ? "Accesso in corso..." : "Accedi"}
            </button>
          </form>

          {message && <p className="status-message error">{message}</p>}
        </section>
      </main>
    );
  }

  return (
    <main className="page app-page">
      <section className="panel">
        <div className="topbar">
          <div>
            <p className="eyebrow">ZeroTrustHR</p>
            <h1>Ciao {user.name.first}</h1>
          </div>
          <button className="secondary-button" onClick={handleLogout}>Logout</button>
        </div>

        {message && <p className="status-message error">{message}</p>}

        <section className="summary-grid">
          <div className="summary-item">
            <span>Ruolo</span>
            <strong>{user.role}</strong>
          </div>
          <div className="summary-item">
            <span>Dipartimento</span>
            <strong>{user.department}</strong>
          </div>
          <div className="summary-item">
            <span>Device active</span>
            <strong>{devices.filter((device) => device.status === "active").length}</strong>
          </div>
        </section>

        {!hasActiveDevice ? (
          <section className="notice">
            <h2>Home limitata</h2>
            <p>Il tuo utente e autenticato, ma non risulta ancora un device active associato.</p>
          </section>
        ) : (
          <section className="notice success">
            <h2>Home standard</h2>
            <p>Hai almeno un device active. Puoi tentare l'accesso alle risorse protette.</p>
          </section>
        )}

        <section className="section-block">
          <div className="section-heading">
            <h2>Device associati</h2>
            <button className="secondary-button" onClick={() => loadSession(token)} disabled={loading}>
              Aggiorna
            </button>
          </div>

          {devices.length === 0 ? (
            <p className="muted">Nessun device associato.</p>
          ) : (
            <div className="device-list">
              {devices.map((device) => (
                <article className="device-row" key={device.device_id}>
                  <div>
                    <strong>{device.device_name}</strong>
                    <span>{device.os} - {device.hardware_key_type}</span>
                  </div>
                  <span className={`badge badge-${device.status}`}>{device.status}</span>
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="section-block protected-resource-block">
          <h2>Risorse protette</h2>
          {protectedResources.map((resource) => (
            <section className="section-block" key={resource.key}>
              <div className="section-heading">
                <h2>{resource.title}</h2>
                <button
                  className="secondary-button"
                  onClick={() => handleProtectedResourceAccess(resource)}
                  disabled={protectedLoadingKey === resource.key || !activeDevice}
                >
                  {protectedLoadingKey === resource.key ? "Accesso in corso..." : "Tenta accesso"}
                </button>
              </div>
              <p className="muted">
                Richiesta reale a {resource.path} con x-resource-name {resource.resourceName}.
              </p>
              {!activeDevice && (
                <p className="status-message error">
                  Serve almeno un device active per costruire una richiesta coerente.
                </p>
              )}
              {protectedResults[resource.key] && (
                <pre className="result-box">{protectedResults[resource.key]}</pre>
              )}
            </section>
          ))}
        </section>

        {!hasActiveDevice && (
          <section className="section-block">
            <DeviceEnrollment jwt={token} embedded showAdminApprove={isAdmin} />
          </section>
        )}

        {isAdmin && (
          <section className="section-block admin-block">
            <div className="section-heading">
              <h2>Admin device</h2>
              <label className="inline-filter">
                Filtro stato
                <select
                  value={adminStatus}
                  onChange={(event) => setAdminStatus(event.target.value as DeviceStatus)}
                >
                  {deviceStatuses.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
                </select>
              </label>
            </div>

            <div className="device-list">
              {adminDevices.map((device) => (
                <article className="device-row" key={device.device_id}>
                  <div>
                    <strong>{device.device_name}</strong>
                    <span>{device.user_id}</span>
                  </div>
                  <div className="admin-device-actions">
                    <span className={`badge badge-${device.status}`}>{device.status}</span>
                    {device.status === "pending" && (
                      <>
                        <button
                          className="small-button"
                          disabled={adminActionDeviceId === device.device_id}
                          onClick={() => handleAdminDeviceAction(device.device_id, "approve")}
                        >
                          Approve
                        </button>
                        <button
                          className="small-button danger-button"
                          disabled={adminActionDeviceId === device.device_id}
                          onClick={() => handleAdminDeviceAction(device.device_id, "reject")}
                        >
                          Reject
                        </button>
                      </>
                    )}
                    {device.status === "active" && (
                      <button
                        className="small-button danger-button"
                        disabled={adminActionDeviceId === device.device_id}
                        onClick={() => handleAdminDeviceAction(device.device_id, "revoke")}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </article>
              ))}
              {adminDevices.length === 0 && <p className="muted">Nessun device per questo stato.</p>}
            </div>
          </section>
        )}
      </section>
    </main>
  );
}

export default App;
