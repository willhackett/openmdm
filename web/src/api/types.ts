// Mirrors the JSON of internal/core (types.go, interfaces.go) and docs/API.md.

export type Platform = "macos" | "ios" | "ipados";
export type Role = "admin" | "user";
export type DeviceStatus = "enrolled" | "pending" | "unenrolled";
export type Channel = "device" | "user";
export type ProfileState = "pending" | "blocked" | "sent" | "installed" | "failed" | "removing";
export type CommandStatus = "queued" | "acknowledged" | "error" | "notnow";

export interface User {
  username: string;
  email: string;
  name: string;
  groups: string[];
  role: Role;
  created_at: string;
  last_login_at: string;
}

export interface Device {
  id: string;
  username: string;
  platform: Platform;
  serial_number: string;
  model: string;
  device_name: string;
  os_version: string;
  status: DeviceStatus;
  user_channel_id: string;
  enrolled_at: string;
  last_seen_at: string;
}

export interface Assignment {
  everyone: boolean;
  users: string[];
  groups: string[];
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  platforms: Platform[];
  macos_channel: Channel;
  assignment: Assignment;
  template: string;
  source: "file" | "ui" | string;
  updated_at: string;
}

export interface DeviceProfile {
  device_id: string;
  profile_id: string;
  state: ProfileState;
  channel: Channel;
  identifier: string;
  content_hash: string;
  command_uuid: string;
  detail: string;
  updated_at: string;
}

export interface CommandRecord {
  uuid: string;
  device_id: string;
  channel: Channel;
  request_type: string;
  profile_id: string;
  status: CommandStatus;
  detail: string;
  created_at: string;
  updated_at: string;
}

export interface Enrollment {
  token: string;
  username: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  downloaded_at: string | null;
  used_at: string | null;
}

export interface Event {
  id: number;
  at: string;
  actor: string;
  kind: string;
  subject: string;
  detail: string;
}

export interface PushInfo {
  configured: boolean;
  topic: string;
  not_after: string;
}

/** A push certificate request made through mdmcert.download, as GET /settings/push-certificate/request reports it. */
export interface PushRequest {
  pending: boolean;
  email?: string;
  requested_at?: string;
}

export interface PushCsr {
  filename: string;
  csr_pem: string;
  request: PushRequest;
}

export interface TemplateInfo {
  identifier: string;
  user_secrets: string[];
  global_secrets: string[];
  payload_types: string[];
}

export interface PlanEntry {
  profile_id: string;
  name: string;
  wanted: boolean;
  reason: string;
  state: ProfileState | "";
  channel: Channel;
  detail: string;
}

export type ProfileCounts = Partial<Record<ProfileState, number>>;
export type ProfileListItem = Profile & { info: TemplateInfo; counts: ProfileCounts };

export interface SecretEntry {
  key: string;
  set: boolean;
  used_by: string[];
}

export interface Me {
  user: User;
  push: PushInfo;
  public_url: string;
  version: string;
}

export interface Settings {
  push: PushInfo;
  ca: { subject: string; not_after: string; sha256: string };
  secrets: { backend: string; healthy: boolean; error: string };
  public_url: string;
  organization: string;
}

export interface DeviceDetail {
  device: Device;
  owner: User | null;
  profiles: PlanEntry[];
  commands: CommandRecord[];
}

export interface ProfileDetail {
  profile: Profile;
  info: TemplateInfo;
  devices: { device: Device; state: DeviceProfile }[];
}

export interface SecretValue {
  value: string;
  encoding?: "base64";
}

/** Everything the screens need from the server. The real client and the mock both implement it. */
export interface Api {
  readonly mock: boolean;
  readonly caPemHref: string;
  me(): Promise<Me>;
  users(): Promise<User[]>;
  user(username: string): Promise<{ user: User; devices: Device[] }>;
  userSecrets(username: string): Promise<SecretEntry[]>;
  setUserSecret(username: string, key: string, v: SecretValue): Promise<void>;
  deleteUserSecret(username: string, key: string): Promise<void>;
  globalSecrets(): Promise<SecretEntry[]>;
  setGlobalSecret(key: string, v: SecretValue): Promise<void>;
  deleteGlobalSecret(key: string): Promise<void>;
  devices(): Promise<Device[]>;
  device(id: string): Promise<DeviceDetail>;
  setOwner(id: string, username: string): Promise<void>;
  sync(id: string): Promise<void>;
  lock(id: string, pin: string, message: string): Promise<{ command_uuid: string }>;
  erase(id: string, confirm: string): Promise<{ command_uuid: string }>;
  removeDevice(id: string): Promise<void>;
  profiles(): Promise<ProfileListItem[]>;
  profile(id: string): Promise<ProfileDetail>;
  saveProfile(p: Profile): Promise<{ profile: Profile; info: TemplateInfo }>;
  deleteProfile(id: string): Promise<void>;
  validateProfile(p: Profile): Promise<TemplateInfo>;
  createEnrollment(username?: string): Promise<{ enrollment: Enrollment; url: string }>;
  enrollments(): Promise<Enrollment[]>;
  settings(): Promise<Settings>;
  /** With no key, the certificate is paired with the key made for the pending request. */
  setPushCertificate(certificatePem: string, keyPem?: string): Promise<PushInfo>;
  pushRequest(): Promise<PushRequest>;
  /** Makes a new key and CSR on the server (replacing a pending one). */
  generatePushCsr(): Promise<PushCsr>;
  /** The pending CSR again; rejects with a 404 ApiError when none is pending. */
  pushCsr(): Promise<PushCsr>;
  requestPushCertificate(email: string): Promise<PushRequest>;
  decryptPushRequest(encrypted: string): Promise<{ filename: string; content: string }>;
  cancelPushRequest(): Promise<void>;
  events(limit?: number): Promise<Event[]>;
  logout(): Promise<void>;
}
