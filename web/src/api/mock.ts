// In-memory stand-in for the server, used by `npm run dev` and `?mock=1`.
// All names are invented; addresses are example.com.

import { ApiError } from "./client";
import type {
  Api,
  CommandRecord,
  Device,
  DeviceProfile,
  Enrollment,
  Event,
  PlanEntry,
  Profile,
  ProfileState,
  PushInfo,
  PushCsr,
  PushRequest,
  SecretEntry,
  TemplateInfo,
  User,
} from "./types";

export interface MockControls {
  viewer(): string;
  setViewer(username: string): void;
  pushConfigured(): boolean;
  setPushConfigured(on: boolean): void;
  subscribe(fn: () => void): () => void;
}

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
const ahead = (ms: number) => new Date(Date.now() + ms).toISOString();
const delay = (ms = 120) => new Promise<void>((r) => setTimeout(r, ms));
const uuid = () =>
  "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 3) | 8).toString(16);
  });
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

// ---------------------------------------------------------------- fixtures

const users: User[] = [
  {
    username: "alex",
    email: "alex@example.com",
    name: "Alex Rivera",
    groups: ["admins", "family", "design"],
    role: "admin",
    created_at: ago(90 * DAY),
    last_login_at: ago(5 * MIN),
  },
  {
    username: "sam",
    email: "sam@example.com",
    name: "Sam Okafor",
    groups: ["family"],
    role: "user",
    created_at: ago(60 * DAY),
    last_login_at: ago(2 * DAY),
  },
  {
    username: "jordan",
    email: "jordan.whitcombe-featherstonehaugh@example.com",
    name: "Jordan Whitcombe-Featherstonehaugh",
    groups: ["family"],
    role: "user",
    created_at: ago(30 * DAY),
    last_login_at: ago(9 * DAY),
  },
  {
    username: "priya",
    email: "priya@example.com",
    name: "Priya Nair",
    groups: ["design", "contractors"],
    role: "user",
    created_at: ago(21 * DAY),
    last_login_at: ago(4 * HOUR),
  },
  {
    username: "tomasz",
    email: "tomasz@example.com",
    name: "Tomasz Kowalczyk",
    groups: ["contractors"],
    role: "user",
    created_at: ago(14 * DAY),
    last_login_at: ago(1 * DAY),
  },
];

const devices: Device[] = [
  {
    id: "00008112-000A1B2C3D4E5F01",
    username: "alex",
    platform: "macos",
    serial_number: "C02XK1ABJG5H",
    model: "MacBookPro18,3",
    device_name: "Alex's MacBook Pro",
    os_version: "15.1",
    status: "enrolled",
    user_channel_id: "00008112-000A1B2C3D4E5F01:6F0A2E1C-5B1D-4C3A-9E55-0A1B2C3D4E5F",
    enrolled_at: ago(80 * DAY),
    last_seen_at: ago(3 * MIN),
  },
  {
    id: "00008110-001C2D3E4F5A6B02",
    username: "alex",
    platform: "ios",
    serial_number: "F2LXQ9T0N7",
    model: "iPhone15,2",
    device_name: "Alex's iPhone",
    os_version: "18.1",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(75 * DAY),
    last_seen_at: ago(22 * MIN),
  },
  {
    id: "00008103-002D3E4F5A6B7C03",
    username: "sam",
    platform: "macos",
    serial_number: "C02ZP7QDML85",
    model: "Mac14,2",
    device_name: "Sam's MacBook Air",
    os_version: "14.7.1",
    status: "enrolled",
    user_channel_id: "00008103-002D3E4F5A6B7C03:1B2C3D4E-0F0A-4A6B-8C7D-112233445566",
    enrolled_at: ago(40 * DAY),
    last_seen_at: ago(3 * HOUR),
  },
  {
    id: "00008120-003E4F5A6B7C8D04",
    username: "sam",
    platform: "ios",
    serial_number: "DX3H8K2LQW",
    model: "iPhone14,5",
    device_name: "Sam's iPhone",
    os_version: "17.7.2",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(39 * DAY),
    last_seen_at: ago(2 * DAY + 4 * HOUR),
  },
  {
    id: "00008130-004F5A6B7C8D9E05",
    username: "jordan",
    platform: "macos",
    serial_number: "C02YJ3RTLVDM",
    model: "Mac15,7",
    device_name: "Jordan's MacBook Pro 16-inch (studio, second floor desk)",
    os_version: "15.1",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(28 * DAY),
    last_seen_at: ago(9 * DAY),
  },
  {
    id: "00008140-0050A6B7C8D9E0F6",
    username: "priya",
    platform: "ipados",
    serial_number: "H9QW4N2XKT",
    model: "iPad14,6",
    device_name: "Priya's iPad Pro",
    os_version: "18.0.1",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(20 * DAY),
    last_seen_at: ago(40 * MIN),
  },
  {
    id: "00008150-0061B7C8D9E0F107",
    username: "priya",
    platform: "ios",
    serial_number: "J3MZ8P5RVC",
    model: "iPhone16,1",
    device_name: "Priya's iPhone",
    os_version: "18.1",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(20 * DAY),
    last_seen_at: ago(6 * HOUR),
  },
  {
    id: "00008160-0072C8D9E0F1A208",
    username: "tomasz",
    platform: "macos",
    serial_number: "C02ZD8LKQ6L4",
    model: "Mac14,15",
    device_name: "Studio Mac",
    os_version: "14.7.1",
    status: "pending",
    user_channel_id: "",
    enrolled_at: ago(13 * DAY),
    last_seen_at: ago(13 * DAY),
  },
  {
    id: "00008170-0083D9E0F1A2B309",
    username: "tomasz",
    platform: "ios",
    serial_number: "K7TB2Q9WHD",
    model: "iPhone13,2",
    device_name: "TK iPhone",
    os_version: "17.6",
    status: "enrolled",
    user_channel_id: "",
    enrolled_at: ago(13 * DAY),
    last_seen_at: ago(3 * DAY),
  },
];

const mailTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>com.example.openmdm.personal-mail</string>
  <key>PayloadUUID</key><string>{{ uuid "root" }}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadDisplayName</key><string>Personal mail</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadIdentifier</key><string>com.example.openmdm.personal-mail.account</string>
      <key>PayloadUUID</key><string>{{ uuid "mail" }}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>EmailAddress</key><string>{{ .User.Email }}</string>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerHostName</key><string>imap.fastmail.example.com</string>
      <key>IncomingMailServerUsername</key><string>{{ .User.Email }}</string>
      <key>IncomingPassword</key><string>{{ secret "fastmail_app_password" }}</string>
    </dict>
  </array>
</dict>
</plist>
`;

const wifiTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>com.example.openmdm.home-wifi</string>
  <key>PayloadUUID</key><string>{{ uuid "root" }}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.wifi.managed</string>
      <key>PayloadIdentifier</key><string>com.example.openmdm.home-wifi.net</string>
      <key>PayloadUUID</key><string>{{ uuid "wifi" }}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>SSID_STR</key><string>Example House</string>
      <key>EncryptionType</key><string>WPA2</string>
      <key>Password</key><string>{{ globalSecret "wifi_psk" }}</string>
    </dict>
  </array>
</dict>
</plist>
`;

const fileVaultTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>com.example.openmdm.disk-encryption</string>
  <key>PayloadUUID</key><string>{{ uuid "root" }}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.MCX.FileVault2</string>
      <key>PayloadIdentifier</key><string>com.example.openmdm.disk-encryption.fv</string>
      <key>PayloadUUID</key><string>{{ uuid "fv" }}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>Enable</key><string>On</string>
      <key>Defer</key><true/>
    </dict>
  </array>
</dict>
</plist>
`;

/** A small valid-looking template, for profiles whose content does not matter here. */
const tpl = (id: string, type: string, extra = "") => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>com.example.openmdm.${id}</string>
  <key>PayloadUUID</key><string>{{ uuid "root" }}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>${type}</string>
      <key>PayloadIdentifier</key><string>com.example.openmdm.${id}.payload</string>
      <key>PayloadUUID</key><string>{{ uuid "payload" }}</string>
      <key>PayloadVersion</key><integer>1</integer>
${extra}
    </dict>
  </array>
</dict>
</plist>
`;

const profiles: Profile[] = [
  {
    id: "personal-mail",
    name: "Personal mail",
    description: "Fastmail mail, calendars and contacts",
    platforms: ["macos", "ios", "ipados"],
    macos_channel: "user",
    assignment: { everyone: true, users: [], groups: [] },
    template: mailTemplate,
    source: "file",
    updated_at: ago(30 * DAY),
  },
  {
    id: "home-wifi",
    name: "Home Wi-Fi",
    description: "Joins the house network",
    platforms: ["macos", "ios", "ipados"],
    macos_channel: "device",
    assignment: { everyone: false, users: [], groups: ["family"] },
    template: wifiTemplate,
    source: "ui",
    updated_at: ago(12 * DAY),
  },
  {
    id: "disk-encryption",
    name: "Disk encryption",
    description: "Turns on FileVault and escrows the recovery key",
    platforms: ["macos"],
    macos_channel: "device",
    assignment: { everyone: false, users: ["alex", "sam"], groups: [] },
    template: fileVaultTemplate,
    source: "ui",
    updated_at: ago(6 * DAY),
  },
  {
    id: "contractor-restrictions",
    name: "Restrictions for contractors and other short-term staff on shared devices",
    description:
      "Turns off AirDrop, the camera roll upload, iCloud Drive and Siri suggestions on iPhones and iPads, and requires a six-digit passcode that is checked every hour. Reviewed each quarter.",
    platforms: ["ios", "ipados"],
    macos_channel: "device",
    assignment: { everyone: false, users: [], groups: ["contractors"] },
    template: tpl("contractor-restrictions", "com.apple.applicationaccess", "      <key>allowAirDrop</key><false/>\n      <key>allowCloudDocumentSync</key><false/>"),
    source: "file",
    updated_at: ago(45 * DAY),
  },
  {
    id: "corporate-vpn",
    name: "Corporate VPN",
    description: "",
    platforms: ["macos", "ios"],
    macos_channel: "device",
    assignment: { everyone: false, users: ["alex", "sam", "jordan", "priya"], groups: ["design"] },
    template: tpl("corporate-vpn", "com.apple.vpn.managed", '      <key>VPNType</key><string>IKEv2</string>\n      <key>SharedSecret</key><string>{{ secret "vpn_psk" }}</string>'),
    source: "ui",
    updated_at: ago(3 * DAY),
  },
  {
    id: "guest-kiosk",
    name: "Guest kiosk",
    description: "Single-app mode for the hall iPad",
    platforms: ["ipados"],
    macos_channel: "device",
    assignment: { everyone: false, users: [], groups: [] },
    template: tpl("guest-kiosk", "com.apple.app.lock", "      <key>App</key><dict><key>Identifier</key><string>com.apple.mobilesafari</string></dict>"),
    source: "ui",
    updated_at: ago(2 * HOUR),
  },
];

const deviceProfiles = new Map<string, DeviceProfile>();
const dpKey = (d: string, p: string) => d + "|" + p;
function seedDP(deviceId: string, profileId: string, state: ProfileState, detail = "", channel: "device" | "user" = "device") {
  deviceProfiles.set(dpKey(deviceId, profileId), {
    device_id: deviceId,
    profile_id: profileId,
    state,
    channel,
    identifier: "com.example.openmdm." + profileId,
    content_hash: "",
    command_uuid: uuid(),
    detail,
    updated_at: ago(2 * HOUR),
  });
}

const userSecrets = new Map<string, Set<string>>([
  ["alex", new Set(["fastmail_app_password", "vpn_psk"])],
  ["sam", new Set()],
  ["jordan", new Set(["fastmail_app_password"])],
  ["priya", new Set(["fastmail_app_password", "vpn_psk"])],
  ["tomasz", new Set()],
]);
const globalSecretKeys = new Set<string>(["wifi_psk"]);

let commands: CommandRecord[] = [];
function addCommand(deviceId: string, requestType: string, status: CommandRecord["status"], detail = "", profileId = "", channel: "device" | "user" = "device", agoMs = 0) {
  const c: CommandRecord = {
    uuid: uuid(),
    device_id: deviceId,
    channel,
    request_type: requestType,
    profile_id: profileId,
    status,
    detail,
    created_at: ago(agoMs),
    updated_at: ago(Math.max(0, agoMs - 20_000)),
  };
  commands.unshift(c);
  return c;
}

let events: Event[] = [];
let eventId = 100;
function addEvent(actor: string, kind: string, subject: string, detail = "", agoMs = 0) {
  events.push({ id: ++eventId, at: ago(agoMs), actor, kind, subject, detail });
}

let enrollments: Enrollment[] = [];

let pushOn = true;
let pushExpiry = ahead(22 * DAY);
/** A pending CSR; email is empty until it has been sent for countersigning. */
let pushRequestState: { email: string; requested_at: string } | null = null;
let viewer = "alex";
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((f) => f());

// ---------------------------------------------------------------- logic

function templateInfo(p: Profile): TemplateInfo {
  const user = new Set<string>();
  const glob = new Set<string>();
  for (const m of p.template.matchAll(/\{\{\s*(secret|secretData)\s+"([a-z0-9_]+)"\s*\}\}/g)) user.add(m[2]);
  for (const m of p.template.matchAll(/\{\{\s*(globalSecret|globalSecretData)\s+"([a-z0-9_]+)"\s*\}\}/g)) glob.add(m[2]);
  const types = new Set<string>();
  for (const m of p.template.matchAll(/<key>PayloadType<\/key>\s*<string>([^<]+)<\/string>/g)) types.add(m[1]);
  const id = /<key>PayloadIdentifier<\/key>\s*<string>([^<]+)<\/string>/.exec(p.template);
  return {
    identifier: id ? id[1] : "",
    user_secrets: [...user].sort(),
    global_secrets: [...glob].sort(),
    payload_types: [...types].sort(),
  };
}

function validate(p: Profile): TemplateInfo {
  if (!/^[a-z0-9-]+$/.test(p.id)) throw new ApiError(400, "The ID may only use lower-case letters, digits and hyphens.");
  if (!p.name.trim()) throw new ApiError(400, "A profile needs a name.");
  if (p.platforms.length === 0) throw new ApiError(400, "Choose at least one platform.");
  const opens = (p.template.match(/\{\{/g) || []).length;
  const closes = (p.template.match(/\}\}/g) || []).length;
  if (opens !== closes) throw new ApiError(400, "template: unclosed action: a {{ has no matching }}");
  const info = templateInfo(p);
  if (!p.template.includes("<plist")) throw new ApiError(400, "template: this is not a property list (no <plist> element).");
  if (!info.identifier) throw new ApiError(400, "template: the top-level PayloadIdentifier is missing.");
  if (!/<key>PayloadUUID<\/key>/.test(p.template)) throw new ApiError(400, "template: the top-level PayloadUUID is missing.");
  return info;
}

function userOf(name: string) {
  return users.find((u) => u.username === name) || null;
}

function wants(p: Profile, d: Device): { wanted: boolean; reason: string } {
  if (!p.platforms.includes(d.platform)) return { wanted: false, reason: `platform ${d.platform} is not listed` };
  const u = userOf(d.username);
  const a = p.assignment;
  if (a.everyone) return { wanted: true, reason: "assigned to everyone" };
  if (u && a.users.includes(u.username)) return { wanted: true, reason: `assigned to ${u.username}` };
  if (u) {
    const g = u.groups.find((x) => a.groups.includes(x));
    if (g) return { wanted: true, reason: `assigned to the group ${g}` };
  }
  if (!u) return { wanted: false, reason: "the device has no owner, so there is no one to assign to" };
  return { wanted: false, reason: `not assigned to ${u.username}` };
}

function missingFor(p: Profile, d: Device): string[] {
  const info = templateInfo(p);
  const miss: string[] = [];
  const u = userOf(d.username);
  if (info.user_secrets.length > 0 || /\.User\./.test(p.template)) {
    if (!u) return ["an owner"];
  }
  for (const k of info.user_secrets) if (!userSecrets.get(d.username)?.has(k)) miss.push(`secret "${k}"`);
  for (const k of info.global_secrets) if (!globalSecretKeys.has(k)) miss.push(`global secret "${k}"`);
  return miss;
}

function channelFor(p: Profile, d: Device) {
  return d.platform === "macos" ? p.macos_channel : "device";
}

/** Makes every device match the profiles, like the real reconciler, with a short delay for installs. */
function reconcile() {
  for (const d of devices) {
    if (d.status === "unenrolled") continue;
    for (const p of profiles) {
      const key = dpKey(d.id, p.id);
      const cur = deviceProfiles.get(key);
      const w = wants(p, d);
      if (!w.wanted) {
        if (cur && cur.state !== "removing") {
          cur.state = "removing";
          cur.detail = "";
          cur.updated_at = new Date().toISOString();
          addCommand(d.id, "RemoveProfile", "queued", "", p.id, cur.channel);
          setTimeout(() => {
            deviceProfiles.delete(key);
            notify();
          }, 1500);
        }
        continue;
      }
      const miss = missingFor(p, d);
      if (miss.length > 0) {
        deviceProfiles.set(key, {
          device_id: d.id,
          profile_id: p.id,
          state: "blocked",
          channel: channelFor(p, d),
          identifier: "com.example.openmdm." + p.id,
          content_hash: "",
          command_uuid: "",
          detail: "Waiting for " + miss.join(", ") + (d.username ? ` (${d.username})` : ""),
          updated_at: new Date().toISOString(),
        });
        continue;
      }
      if (!cur || cur.state === "blocked" || cur.state === "removing") {
        const cmd = addCommand(d.id, "InstallProfile", "queued", "", p.id, channelFor(p, d));
        deviceProfiles.set(key, {
          device_id: d.id,
          profile_id: p.id,
          state: "sent",
          channel: channelFor(p, d),
          identifier: "com.example.openmdm." + p.id,
          content_hash: "",
          command_uuid: cmd.uuid,
          detail: "",
          updated_at: new Date().toISOString(),
        });
        setTimeout(() => {
          const now = deviceProfiles.get(key);
          if (now && now.state === "sent") {
            now.state = "installed";
            now.updated_at = new Date().toISOString();
            cmd.status = "acknowledged";
            cmd.updated_at = new Date().toISOString();
            addEvent("device:" + d.id, "profile.installed", `${p.id} on ${d.device_name}`);
            notify();
          }
        }, 1800);
      }
    }
  }
}

function seed() {
  const long1 =
    "The device refused the profile: FileVault payload is not allowed because a personal recovery key is already escrowed (MCProfileErrorDomain 4001).";
  const long2 =
    "Installation failed: the passcode policy conflicts with a policy already on the device (a payload from another management source requires an alphanumeric passcode). Remove the other policy, then sync again. (MCProfileErrorDomain 4000)";
  // [device index, profile id] -> state, detail; anything wanted and not listed is installed, or blocked if a secret is missing.
  const over: Record<string, [ProfileState, string]> = {
    "2|disk-encryption": ["failed", long1],
    "6|contractor-restrictions": ["failed", long2],
    "5|home-wifi": ["pending", ""],
    "7|corporate-vpn": ["sent", ""],
    "8|personal-mail": ["pending", ""],
  };
  devices.forEach((d, i) => {
    for (const p of profiles) {
      if (!wants(p, d).wanted) continue;
      const miss = missingFor(p, d);
      const o = over[i + "|" + p.id];
      const ch = channelFor(p, d);
      if (miss.length) {
        deviceProfiles.set(dpKey(d.id, p.id), {
          device_id: d.id,
          profile_id: p.id,
          state: "blocked",
          channel: ch,
          identifier: "com.example.openmdm." + p.id,
          content_hash: "",
          command_uuid: "",
          detail: "Waiting for " + miss.join(", ") + (d.username ? ` (${d.username})` : ""),
          updated_at: ago(2 * DAY),
        });
      } else if (o) seedDP(d.id, p.id, o[0], o[1], ch);
      else seedDP(d.id, p.id, "installed", "", ch);
    }
  });

  const [mac, phone, smac] = [devices[0], devices[1], devices[2]];
  addCommand(mac.id, "InstallProfile", "acknowledged", "", "personal-mail", "user", 30 * DAY);
  addCommand(mac.id, "InstallProfile", "acknowledged", "", "disk-encryption", "device", 6 * DAY);
  addCommand(mac.id, "DeviceInformation", "acknowledged", "", "", "device", 3 * HOUR);
  addCommand(phone.id, "InstallProfile", "acknowledged", "", "home-wifi", "device", 12 * DAY);
  addCommand(smac.id, "InstallProfile", "error",
    "The device refused the profile: FileVault payload is not allowed because a personal recovery key is already escrowed (MCProfileErrorDomain 4001).",
    "disk-encryption", "device", 6 * DAY);
  addCommand(smac.id, "InstallProfile", "acknowledged", "", "home-wifi", "device", 12 * DAY);
  addCommand(smac.id, "DeviceLock", "notnow", "", "", "device", 3 * DAY);

  addEvent("system", "server.started", "openmdm", "version 0.1.0", 20 * DAY);
  addEvent("alex", "user.login", "alex", "", 5 * MIN);
  addEvent("device:" + mac.id, "device.enrolled", mac.device_name, "owner alex", 80 * DAY);
  addEvent("device:" + phone.id, "device.enrolled", phone.device_name, "owner alex", 75 * DAY);
  addEvent("sam", "device.enrolled", "Sam's MacBook Air", "owner sam", 40 * DAY);
  addEvent("sam", "device.enrolled", "Sam's iPhone", "owner sam", 39 * DAY);
  addEvent("alex", "profile.saved", "disk-encryption", "created", 6 * DAY);
  addEvent("device:" + smac.id, "profile.failed", "disk-encryption on Sam's MacBook Air", "FileVault payload is not allowed (4001)", 6 * DAY);
  addEvent("alex", "secret.set", "global/wifi_psk", "", 12 * DAY);
  addEvent("alex", "secret.set", "alex/fastmail_app_password", "", 30 * DAY);
  addEvent("alex", "enrollment.created", "sam", "", 41 * DAY);
  addEvent("alex", "enrollment.created", "sam", "", 3 * HOUR);
  addEvent("system", "profile.blocked", "personal-mail on Sam's iPhone", 'secret "fastmail_app_password" is not set', 2 * DAY);

  enrollments = [
    {
      token: "tok-waiting",
      username: "sam",
      created_by: "alex",
      created_at: ago(20 * MIN),
      expires_at: ahead(40 * MIN),
      downloaded_at: null,
      used_at: null,
    },
    {
      token: "tok-downloaded",
      username: "alex",
      created_by: "alex",
      created_at: ago(30 * MIN),
      expires_at: ahead(30 * MIN),
      downloaded_at: ago(25 * MIN),
      used_at: null,
    },
    {
      token: "tok-used",
      username: "sam",
      created_by: "alex",
      created_at: ago(41 * DAY),
      expires_at: ago(41 * DAY - HOUR),
      downloaded_at: ago(41 * DAY - 5 * MIN),
      used_at: ago(41 * DAY - 8 * MIN),
    },
    {
      token: "tok-expired",
      username: "sam",
      created_by: "sam",
      created_at: ago(3 * HOUR),
      expires_at: ago(2 * HOUR),
      downloaded_at: null,
      used_at: null,
    },
  ];
}
seed();

// ---------------------------------------------------------------- access

function me(): User {
  return userOf(viewer)!;
}
const isAdmin = () => me().role === "admin";
function needAdmin() {
  if (!isAdmin()) throw new ApiError(403, "Only an administrator may do that.");
}
function needSelfOrAdmin(username: string) {
  if (!isAdmin() && username !== me().username) throw new ApiError(403, "You may only manage your own secrets.");
}
function visibleDevice(id: string): Device {
  const d = devices.find((x) => x.id === id);
  if (!d || (!isAdmin() && d.username !== me().username)) throw new ApiError(404, "That device was not found.");
  return d;
}
function checkKey(key: string) {
  if (!/^[a-z0-9_]+$/.test(key)) throw new ApiError(400, "A key may only use lower-case letters, digits and underscores.");
}

function planFor(d: Device): PlanEntry[] {
  const out: PlanEntry[] = [];
  for (const p of profiles) {
    const w = wants(p, d);
    const dp = deviceProfiles.get(dpKey(d.id, p.id));
    if (!w.wanted && !dp) {
      // Platform mismatches are shown so that "why not" is answerable.
      out.push({ profile_id: p.id, name: p.name, wanted: false, reason: w.reason, state: "", channel: channelFor(p, d), detail: "" });
      continue;
    }
    out.push({
      profile_id: p.id,
      name: p.name,
      wanted: w.wanted,
      reason: w.reason,
      state: dp ? dp.state : "pending",
      channel: dp ? dp.channel : channelFor(p, d),
      detail: dp ? dp.detail : "",
    });
  }
  return out;
}

function secretList(keys: Set<string>, scope: "user" | "global", username: string): SecretEntry[] {
  const used = new Map<string, Set<string>>();
  const needed = new Set<string>();
  for (const p of profiles) {
    const info = templateInfo(p);
    const ks = scope === "user" ? info.user_secrets : info.global_secrets;
    let applies = scope === "global";
    if (scope === "user") {
      const u = userOf(username);
      applies = !!u && (p.assignment.everyone || p.assignment.users.includes(username) || u.groups.some((g) => p.assignment.groups.includes(g)));
    }
    for (const k of ks) {
      if (!used.has(k)) used.set(k, new Set());
      used.get(k)!.add(p.id);
      if (applies) needed.add(k);
    }
  }
  const all = new Set<string>([...keys, ...needed]);
  return [...all]
    .sort()
    .map((k) => ({ key: k, set: keys.has(k), used_by: [...(used.get(k) || [])].sort() }));
}

const counts = (profileId: string) => {
  const c: Record<string, number> = { installed: 0, pending: 0, blocked: 0, failed: 0 };
  for (const dp of deviceProfiles.values()) if (dp.profile_id === profileId) c[dp.state] = (c[dp.state] || 0) + 1;
  return c;
};

// ---------------------------------------------------------------- api

export const mockControls: MockControls = {
  viewer: () => viewer,
  setViewer: (u) => {
    viewer = u;
    notify();
  },
  pushConfigured: () => pushOn,
  setPushConfigured: (on) => {
    pushOn = on;
    notify();
  },
  subscribe: (fn) => {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
};

const pushInfo = (): PushInfo =>
  pushOn
    ? { configured: true, topic: "com.apple.mgmt.External.7c1e5b2a-3d4f-4a6b-8c9d-0e1f2a3b4c5d", not_after: pushExpiry }
    : { configured: false, topic: "", not_after: "0001-01-01T00:00:00Z" };

const fakeCsr = "-----BEGIN CERTIFICATE REQUEST-----\nTW9jayBDU1IgZm9yIHRoZSBPcGVuTURNIGRlbW8uCg==\n-----END CERTIFICATE REQUEST-----\n";
const fakePem = "-----BEGIN CERTIFICATE-----\nTW9jayBDQSBjZXJ0aWZpY2F0ZSBmb3IgdGhlIE9wZW5NRE0gZGVtby4=\n-----END CERTIFICATE-----\n";

export const mockApi: Api = {
  mock: true,
  caPemHref: "data:application/x-pem-file;charset=utf-8," + encodeURIComponent(fakePem),

  async me() {
    await delay();
    return { user: clone(me()), push: pushInfo(), public_url: "https://mdm.example.com", version: "0.1.0-mock" };
  },

  async users() {
    await delay();
    needAdmin();
    return clone(users);
  },
  async user(username) {
    await delay();
    needSelfOrAdmin(username);
    const u = userOf(username);
    if (!u) throw new ApiError(404, "That person was not found.");
    return { user: clone(u), devices: clone(devices.filter((d) => d.username === username)) };
  },

  async userSecrets(username) {
    await delay();
    needSelfOrAdmin(username);
    if (!userOf(username)) throw new ApiError(404, "That person was not found.");
    return secretList(userSecrets.get(username) || new Set(), "user", username);
  },
  async setUserSecret(username, key, v) {
    await delay(250);
    needSelfOrAdmin(username);
    checkKey(key);
    if (!v.value) throw new ApiError(400, "A secret needs a value.");
    if (!userSecrets.has(username)) userSecrets.set(username, new Set());
    if (!userOf(username)) users.push({ username, email: `${username}@example.com`, name: username, groups: [], role: "user", created_at: ago(0), last_login_at: "0001-01-01T00:00:00Z" });
    userSecrets.get(username)!.add(key);
    addEvent(me().username, "secret.set", `${username}/${key}`);
    reconcile();
    notify();
  },
  async deleteUserSecret(username, key) {
    await delay();
    needSelfOrAdmin(username);
    userSecrets.get(username)?.delete(key);
    addEvent(me().username, "secret.deleted", `${username}/${key}`);
    reconcile();
    notify();
  },
  async globalSecrets() {
    await delay();
    needAdmin();
    return secretList(globalSecretKeys, "global", "");
  },
  async setGlobalSecret(key, v) {
    await delay(250);
    needAdmin();
    checkKey(key);
    if (!v.value) throw new ApiError(400, "A secret needs a value.");
    globalSecretKeys.add(key);
    addEvent(me().username, "secret.set", `global/${key}`);
    reconcile();
    notify();
  },
  async deleteGlobalSecret(key) {
    await delay();
    needAdmin();
    globalSecretKeys.delete(key);
    addEvent(me().username, "secret.deleted", `global/${key}`);
    reconcile();
    notify();
  },

  async devices() {
    await delay();
    return clone(isAdmin() ? devices : devices.filter((d) => d.username === me().username));
  },
  async device(id) {
    await delay();
    const d = visibleDevice(id);
    return {
      device: clone(d),
      owner: clone(userOf(d.username)),
      profiles: planFor(d),
      commands: clone(commands.filter((c) => c.device_id === id).slice(0, 50)),
    };
  },
  async setOwner(id, username) {
    await delay();
    needAdmin();
    const d = visibleDevice(id);
    if (username && !userOf(username)) throw new ApiError(400, "That person does not exist yet.");
    d.username = username;
    addEvent(me().username, "device.owner", d.device_name, username ? `owner ${username}` : "owner cleared");
    reconcile();
    notify();
  },
  async sync(id) {
    await delay();
    const d = visibleDevice(id);
    addCommand(d.id, "DeviceInformation", "queued");
    addEvent(me().username, "device.sync", d.device_name);
    reconcile();
    d.last_seen_at = ago(0);
  },
  async lock(id, pin, message) {
    await delay();
    const d = visibleDevice(id);
    if (d.platform === "macos" && !/^\d{6}$/.test(pin)) throw new ApiError(400, "A Mac needs a six-digit PIN to lock.");
    const c = addCommand(d.id, "DeviceLock", "queued", message ? "message: " + message : "");
    addEvent(me().username, "device.lock", d.device_name);
    return { command_uuid: c.uuid };
  },
  async erase(id, confirm) {
    await delay();
    needAdmin();
    const d = visibleDevice(id);
    if (confirm !== d.serial_number) throw new ApiError(400, "The serial number does not match this device.");
    const c = addCommand(d.id, "EraseDevice", "queued");
    addEvent(me().username, "device.erase", d.device_name);
    return { command_uuid: c.uuid };
  },
  async removeDevice(id) {
    await delay();
    needAdmin();
    const d = visibleDevice(id);
    devices.splice(devices.indexOf(d), 1);
    for (const k of [...deviceProfiles.keys()]) if (k.startsWith(id + "|")) deviceProfiles.delete(k);
    commands = commands.filter((c) => c.device_id !== id);
    addEvent(me().username, "device.removed", d.device_name);
  },

  async profiles() {
    await delay();
    needAdmin();
    return profiles.map((p) => ({ ...clone(p), template: "", info: templateInfo(p), counts: counts(p.id) }));
  },
  async profile(id) {
    await delay();
    needAdmin();
    const p = profiles.find((x) => x.id === id);
    if (!p) throw new ApiError(404, "That profile was not found.");
    const rows = [...deviceProfiles.values()]
      .filter((dp) => dp.profile_id === id)
      .map((dp) => ({ device: clone(devices.find((d) => d.id === dp.device_id)!), state: clone(dp) }))
      .filter((r) => r.device);
    return { profile: clone(p), info: templateInfo(p), devices: rows };
  },
  async saveProfile(p) {
    await delay(250);
    needAdmin();
    const info = validate(p);
    const existing = profiles.find((x) => x.id === p.id);
    if (existing && existing.source === "file") throw new ApiError(409, "That profile comes from a file and cannot be changed here.");
    const next: Profile = { ...clone(p), source: "ui", updated_at: ago(0) };
    if (existing) profiles[profiles.indexOf(existing)] = next;
    else profiles.push(next);
    addEvent(me().username, "profile.saved", p.id, existing ? "updated" : "created");
    reconcile();
    notify();
    return { profile: clone(next), info };
  },
  async deleteProfile(id) {
    await delay();
    needAdmin();
    const p = profiles.find((x) => x.id === id);
    if (!p) throw new ApiError(404, "That profile was not found.");
    if (p.source === "file") throw new ApiError(409, "That profile comes from a file and cannot be deleted here.");
    profiles.splice(profiles.indexOf(p), 1);
    addEvent(me().username, "profile.deleted", id);
    reconcile();
    notify();
  },
  async validateProfile(p) {
    await delay();
    needAdmin();
    return validate(p);
  },

  async createEnrollment(username) {
    await delay(250);
    const target = username || me().username;
    if (target !== me().username) needAdmin();
    if (!/^[a-z0-9._-]+$/.test(target)) throw new ApiError(400, "A username may only use lower-case letters, digits, dots, hyphens and underscores.");
    if (!userOf(target)) {
      users.push({ username: target, email: `${target}@example.com`, name: target, groups: [], role: "user", created_at: ago(0), last_login_at: "0001-01-01T00:00:00Z" });
      userSecrets.set(target, new Set());
    }
    const token = uuid().replace(/-/g, "");
    const e: Enrollment = {
      token,
      username: target,
      created_by: me().username,
      created_at: ago(0),
      expires_at: ahead(HOUR),
      downloaded_at: null,
      used_at: null,
    };
    enrollments.unshift(e);
    addEvent(me().username, "enrollment.created", target);
    notify();
    return { enrollment: clone(e), url: `https://mdm.example.com/enroll/${token}` };
  },
  async enrollments() {
    await delay();
    return clone(isAdmin() ? enrollments : enrollments.filter((e) => e.username === me().username));
  },

  async settings() {
    await delay();
    needAdmin();
    return {
      push: pushInfo(),
      ca: {
        subject: "CN=Example OpenMDM CA, O=Example Household",
        not_after: ahead(9 * 365 * DAY),
        sha256: "4F:1A:9C:0B:7D:22:E8:53:A1:6C:90:3E:BB:14:D7:08:5A:C2:61:F9:3B:8E:70:D4:19:A6:2C:E5:47:80:FD:12",
      },
      secrets: { backend: "openbao", healthy: true, error: "" },
      public_url: "https://mdm.example.com",
      organization: "Example Household",
    };
  },
  async setPushCertificate(cert, key) {
    await delay(300);
    needAdmin();
    if (!cert.includes("BEGIN CERTIFICATE")) throw new ApiError(400, "The certificate is not a PEM certificate.");
    if (key === undefined || key === "") {
      if (!pushRequestState) throw new ApiError(400, "There is no pending request, so there is no key to pair this certificate with. Send a request first, or upload the key as well.");
      if (cert.includes("MISMATCH")) throw new ApiError(400, "The certificate does not match the key made for the pending request.");
      pushRequestState = null;
    } else if (!key.includes("PRIVATE KEY")) throw new ApiError(400, "The key is not a PEM private key.");
    pushOn = true;
    pushExpiry = ahead(365 * DAY);
    addEvent(me().username, "settings.push_certificate", "apns");
    notify();
    return pushInfo();
  },
  async pushRequest(): Promise<PushRequest> {
    await delay();
    needAdmin();
    return pushRequestState ? { pending: true, ...pushRequestState } : { pending: false };
  },
  async generatePushCsr(): Promise<PushCsr> {
    await delay(400);
    needAdmin();
    pushRequestState = { email: "", requested_at: ago(0) };
    addEvent(me().username, "settings.push_csr", "apns");
    return { filename: "openmdm-push.csr", csr_pem: fakeCsr, request: { pending: true, ...pushRequestState } };
  },
  async pushCsr(): Promise<PushCsr> {
    await delay();
    needAdmin();
    if (!pushRequestState) throw new ApiError(404, "No request is pending.");
    return { filename: "openmdm-push.csr", csr_pem: fakeCsr, request: { pending: true, ...pushRequestState } };
  },
  async requestPushCertificate(email): Promise<PushRequest> {
    await delay(500);
    needAdmin();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ApiError(400, "That is not an email address.");
    if (!pushRequestState) pushRequestState = { email: "", requested_at: ago(0) };
    if (/@(gmail|googlemail|outlook|hotmail|yahoo|icloud|proton|aol)\./i.test(email))
      throw new ApiError(502, "mdmcert.download refused the request: free-mail addresses are not accepted. Use an address at your own domain.");
    // The pending CSR is used (one is made if there is none); a refusal above leaves it pending.
    pushRequestState = { email, requested_at: pushRequestState?.requested_at ?? ago(0) };
    addEvent(me().username, "settings.push_request", email);
    return { pending: true, ...pushRequestState };
  },
  async decryptPushRequest(encrypted) {
    await delay(400);
    needAdmin();
    if (!pushRequestState?.email) throw new ApiError(400, "No request has been sent for countersigning.");
    if (!encrypted.trim() || encrypted.includes("BAD")) throw new ApiError(400, "That cannot be decrypted with the key of the pending request. Is it the file emailed for this request?");
    return { filename: "push-certificate-request.plist.b64", content: "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHBsaXN0Pk1vY2sgcmVxdWVzdDwvcGxpc3Q+" };
  },
  async cancelPushRequest() {
    await delay();
    needAdmin();
    pushRequestState = null;
  },

  async events(limit = 200) {
    await delay();
    needAdmin();
    return clone([...events].sort((a, b) => b.at.localeCompare(a.at) || b.id - a.id).slice(0, limit));
  },

  async logout() {
    await delay();
  },
};
