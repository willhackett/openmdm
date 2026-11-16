import { useEffect, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import { api, mockControls } from "./api";
import { Link, match, usePath } from "./lib/router";
import { MeContext } from "./lib/me";
import { useLoad } from "./lib/hooks";
import { Async, Empty, ErrorBox, Loading, Toasts, toast } from "./components/ui";
import { DevicesScreen } from "./screens/Devices";
import { DeviceScreen } from "./screens/Device";
import { PeopleScreen, PersonScreen } from "./screens/People";
import { SecretsScreen } from "./screens/Secrets";
import { ProfilesScreen } from "./screens/Profiles";
import { ProfileScreen } from "./screens/Profile";
import { ProfileEditScreen } from "./screens/ProfileEdit";
import { EnrolScreen } from "./screens/Enrol";
import { SettingsScreen } from "./screens/Settings";
import { AuditScreen } from "./screens/Audit";

interface NavItem {
  href: string;
  label: string;
  prefix: string;
}

const adminNav: NavItem[] = [
  { href: "/devices", label: "Devices", prefix: "/devices" },
  { href: "/people", label: "People", prefix: "/people" },
  { href: "/secrets", label: "Secrets", prefix: "/secrets" },
  { href: "/profiles", label: "Profiles", prefix: "/profiles" },
  { href: "/enrol", label: "Enrol a device", prefix: "/enrol" },
  { href: "/settings", label: "Settings", prefix: "/settings" },
  { href: "/audit", label: "Audit log", prefix: "/audit" },
];

const userNav: NavItem[] = [
  { href: "/devices", label: "My devices", prefix: "/devices" },
  { href: "/secrets", label: "My secrets", prefix: "/secrets" },
  { href: "/enrol", label: "Enrol a device", prefix: "/enrol" },
];

function NotFound({ restricted }: { restricted?: boolean }) {
  return (
    <Empty>
      <p>
        <strong>{restricted ? "That page is for administrators." : "There is nothing at this address."}</strong>
      </p>
      <p>
        <Link href="/devices">Go to devices</Link>
      </p>
    </Empty>
  );
}

function Routes({ isAdmin }: { isAdmin: boolean }) {
  const path = usePath();
  let p: Record<string, string> | null;
  if (path === "/" || path === "/devices") return <DevicesScreen />;
  if ((p = match("/devices/:id", path))) return <DeviceScreen id={p.id} />;
  if (path === "/secrets") return <SecretsScreen />;
  if (path === "/enrol") return <EnrolScreen />;
  const adminOnly = () => {
    if (!isAdmin) return <NotFound restricted />;
    if (path === "/people") return <PeopleScreen />;
    if ((p = match("/people/:username", path))) return <PersonScreen username={p.username} />;
    if (path === "/profiles") return <ProfilesScreen />;
    if (path === "/profiles/new") return <ProfileEditScreen />;
    if ((p = match("/profiles/:id/edit", path))) return <ProfileEditScreen id={p.id} />;
    if ((p = match("/profiles/:id", path))) return <ProfileScreen id={p.id} />;
    if (path === "/settings") return <SettingsScreen />;
    if (path === "/audit") return <AuditScreen />;
    return <NotFound />;
  };
  return adminOnly();
}

function MockBar({ onChange }: { onChange: () => void }) {
  const c = mockControls!;
  const [, force] = useState(0);
  useEffect(() => c.subscribe(() => force((n) => n + 1)), []);
  return (
    <div class="mockbar" role="region" aria-label="Mock data controls">
      <span>
        <strong>Mock data.</strong> Nothing here reaches a server.
      </span>
      <label>
        View as{" "}
        <select
          value={c.viewer()}
          onChange={(e) => {
            c.setViewer((e.target as HTMLSelectElement).value);
            onChange();
          }}
        >
          <option value="alex">alex (admin)</option>
          <option value="sam">sam (user)</option>
        </select>
      </label>
      <label class="check">
        <input
          type="checkbox"
          checked={c.pushConfigured()}
          onChange={(e) => {
            c.setPushConfigured((e.target as HTMLInputElement).checked);
            onChange();
          }}
        />{" "}
        Push certificate configured
      </label>
    </div>
  );
}

function Shell({ children, nav, name, onSignOut }: { children: ComponentChildren; nav: NavItem[]; name: string; onSignOut: () => void }) {
  const path = usePath();
  return (
    <div class="shell">
      <a class="skip" href="#main">
        Skip to content
      </a>
      <header class="topbar">
        <Link class="brand" href="/devices">
          OpenMDM
        </Link>
        <div class="who">
          <span>{name}</span>
          <button type="button" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </header>
      <nav class="nav" aria-label="Main">
        <ul>
          {nav.map((n) => {
            const current = path === n.href || path.startsWith(n.prefix + "/") || (n.href === "/devices" && path === "/");
            return (
              <li key={n.href}>
                <Link href={n.href} aria-current={current ? "page" : undefined}>
                  {n.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      <main id="main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}

export function App() {
  const [epoch, setEpoch] = useState(0);
  const me = useLoad(() => api.me(), [epoch]);
  const path = usePath();

  useEffect(() => {
    const names: [string, string][] = [
      ["/devices", "Devices"],
      ["/people", "People"],
      ["/secrets", "Secrets"],
      ["/profiles", "Profiles"],
      ["/enrol", "Enrol a device"],
      ["/settings", "Settings"],
      ["/audit", "Audit log"],
    ];
    const hit = names.find(([p]) => path === p || path.startsWith(p + "/"));
    document.title = (hit ? hit[1] + " - " : "") + "OpenMDM";
  }, [path]);

  const signOut = async () => {
    try {
      await api.logout();
    } catch {
      // Leaving anyway.
    }
    if (api.mock) toast("Signed out. In mock mode you stay here.");
    else location.assign("/");
  };

  return (
    <>
      {mockControls && <MockBar onChange={() => setEpoch((n) => n + 1)} />}
      {me.error ? (
        <div class="plain">
          <ErrorBox error={me.error} onRetry={me.reload} />
        </div>
      ) : me.data === null ? (
        <div class="plain">
          <Loading what="Signing you in" />
        </div>
      ) : (
        <MeContext.Provider value={{ me: me.data, isAdmin: me.data.user.role === "admin", refresh: me.reload }}>
          <Shell nav={me.data.user.role === "admin" ? adminNav : userNav} name={me.data.user.name || me.data.user.username} onSignOut={signOut}>
            <Async l={me} render={() => <Routes key={epoch} isAdmin={me.data!.user.role === "admin"} />} />
          </Shell>
        </MeContext.Provider>
      )}
      <Toasts />
    </>
  );
}
