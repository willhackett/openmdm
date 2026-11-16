import type { Api, SecretValue, Profile } from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const BASE = "/api/v1";

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-Requested-With"] = "openmdm";
  let payload: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(BASE + path, { method, headers, body: payload, credentials: "same-origin" });
  } catch {
    throw new ApiError(0, "Could not reach the server. Check your connection and try again.");
  }
  if (res.status === 401) {
    const next = location.pathname + location.search;
    location.assign("/auth/login?next=" + encodeURIComponent(next));
    // Never resolves: the page is going away.
    return new Promise<T>(() => {});
  }
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const msg =
      data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
        ? (data as { error: string }).error
        : `The server answered ${res.status}.`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

const e = encodeURIComponent;

export const realApi: Api = {
  mock: false,
  caPemHref: BASE + "/settings/ca.pem",
  me: () => request("GET", "/me"),
  users: async () => (await request<{ users: never[] }>("GET", "/users")).users,
  user: (u) => request("GET", `/users/${e(u)}`),
  userSecrets: async (u) => (await request<{ secrets: never[] }>("GET", `/users/${e(u)}/secrets`)).secrets,
  setUserSecret: (u, k, v: SecretValue) => request("PUT", `/users/${e(u)}/secrets/${e(k)}`, v),
  deleteUserSecret: (u, k) => request("DELETE", `/users/${e(u)}/secrets/${e(k)}`),
  globalSecrets: async () => (await request<{ secrets: never[] }>("GET", "/secrets/global")).secrets,
  setGlobalSecret: (k, v) => request("PUT", `/secrets/global/${e(k)}`, v),
  deleteGlobalSecret: (k) => request("DELETE", `/secrets/global/${e(k)}`),
  devices: async () => (await request<{ devices: never[] }>("GET", "/devices")).devices,
  device: (id) => request("GET", `/devices/${e(id)}`),
  setOwner: (id, username) => request("PUT", `/devices/${e(id)}/owner`, { username }),
  sync: (id) => request("POST", `/devices/${e(id)}/sync`),
  lock: (id, pin, message) => request("POST", `/devices/${e(id)}/lock`, { pin, message }),
  erase: (id, confirm) => request("POST", `/devices/${e(id)}/erase`, { confirm }),
  removeDevice: (id) => request("DELETE", `/devices/${e(id)}`),
  profiles: async () => (await request<{ profiles: never[] }>("GET", "/profiles")).profiles,
  profile: (id) => request("GET", `/profiles/${e(id)}`),
  saveProfile: (p: Profile) => request("PUT", `/profiles/${e(p.id)}`, p),
  deleteProfile: (id) => request("DELETE", `/profiles/${e(id)}`),
  validateProfile: async (p) => (await request<{ info: never }>("POST", "/profiles/validate", p)).info,
  createEnrollment: (username) => request("POST", "/enrollments", username ? { username } : {}),
  enrollments: async () => (await request<{ enrollments: never[] }>("GET", "/enrollments")).enrollments,
  settings: () => request("GET", "/settings"),
  setPushCertificate: async (certificate_pem, key_pem) =>
    (await request<{ push: never }>("PUT", "/settings/push-certificate", key_pem ? { certificate_pem, key_pem } : { certificate_pem })).push,
  generatePushCsr: () => request("POST", "/settings/push-certificate/csr"),
  pushCsr: () => request("GET", "/settings/push-certificate/csr"),
  pushRequest: async () => (await request<{ request: never }>("GET", "/settings/push-certificate/request")).request,
  requestPushCertificate: async (email) => (await request<{ request: never }>("POST", "/settings/push-certificate/request", { email })).request,
  decryptPushRequest: (encrypted) => request("POST", "/settings/push-certificate/request/decrypt", { encrypted }),
  cancelPushRequest: () => request("DELETE", "/settings/push-certificate/request"),
  events: async (limit = 200) => (await request<{ events: never[] }>("GET", `/events?limit=${limit}`)).events,
  logout: async () => {
    await fetch("/auth/logout", {
      method: "POST",
      headers: { "X-Requested-With": "openmdm" },
      credentials: "same-origin",
    });
  },
};
