import type { Device, PlanEntry, Platform, ProfileState, Assignment } from "../api";

export function isZero(iso: string | null | undefined): boolean {
  return !iso || iso.startsWith("0001-");
}

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "always" });

export function relTime(iso: string | null | undefined, now = Date.now()): string {
  if (isZero(iso)) return "never";
  const t = new Date(iso as string).getTime();
  if (Number.isNaN(t)) return "unknown";
  const s = Math.round((t - now) / 1000);
  const abs = Math.abs(s);
  if (abs < 45) return s <= 0 ? "just now" : "in a few seconds";
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["minute", 60],
    ["hour", 3600],
    ["day", 86400],
    ["month", 86400 * 30],
    ["year", 86400 * 365],
  ];
  let unit: Intl.RelativeTimeFormatUnit = "minute";
  let size = 60;
  for (const [u, sz] of units) {
    if (abs >= sz) {
      unit = u;
      size = sz;
    }
  }
  return rtf.format(Math.round(s / size), unit);
}

export function absTime(iso: string | null | undefined): string {
  if (isZero(iso)) return "never";
  const d = new Date(iso as string);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

export function absDate(iso: string | null | undefined): string {
  if (isZero(iso)) return "unknown";
  return new Date(iso as string).toLocaleDateString(undefined, { dateStyle: "medium" });
}

export function daysUntil(iso: string): number {
  return (new Date(iso).getTime() - Date.now()) / 86_400_000;
}

export const platformLabel: Record<Platform, string> = { macos: "Mac", ios: "iPhone", ipados: "iPad" };
/** The order platforms are always listed in. */
export const platformOrder: Platform[] = ["macos", "ios", "ipados"];
export const platformName = (p: string) => (platformLabel as Record<string, string>)[p] ?? p;

export const stateLabel: Record<ProfileState, string> = {
  installed: "Installed",
  pending: "Pending",
  sent: "Sent",
  blocked: "Blocked",
  failed: "Failed",
  removing: "Removing",
};

/** Most urgent first, so that a problem is the first thing in a summary. */
export const stateOrder: ProfileState[] = ["failed", "blocked", "pending", "sent", "removing", "installed"];

export function summariseStates(entries: Pick<PlanEntry, "state">[]): string {
  const c = new Map<string, number>();
  for (const e of entries) if (e.state) c.set(e.state, (c.get(e.state) || 0) + 1);
  const parts = stateOrder.filter((s) => c.has(s)).map((s) => `${c.get(s)} ${s}`);
  return parts.length ? parts.join(" · ") : "No profiles";
}

export function describeAssignment(a: Assignment): string {
  const parts: string[] = [];
  if (a.everyone) parts.push("Everyone");
  if (a.users?.length) parts.push(a.users.join(", "));
  if (a.groups?.length) parts.push((a.groups.length === 1 ? "group " : "groups ") + a.groups.join(", "));
  return parts.length ? parts.join("; plus ") : "Nobody";
}

export function ownerName(d: Device): string {
  return d.username || "No owner";
}

export function plural(n: number, one: string, many = one + "s"): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function readFileAsText(f: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(new Error("The file could not be read."));
    r.readAsText(f);
  });
}

/** Reads a file as base64 without the data: prefix. */
export function readFileAsBase64(f: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const s = String(r.result);
      resolve(s.slice(s.indexOf(",") + 1));
    };
    r.onerror = () => reject(new Error("The file could not be read."));
    r.readAsDataURL(f);
  });
}
