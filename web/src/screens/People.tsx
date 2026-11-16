import { useEffect, useState } from "preact/hooks";
import { api } from "../api";
import { Link } from "../lib/router";
import { pool, useLoad } from "../lib/hooks";
import { plural, platformName } from "../lib/format";
import { Async, Empty, Facts, PageHeader, Section, StatusBadge, TableWrap, Time } from "../components/ui";
import { SecretsPanel } from "../components/SecretsPanel";

export function PeopleScreen() {
  const l = useLoad(async () => {
    const [users, devices] = await Promise.all([api.users(), api.devices()]);
    return { users, devices };
  }, []);
  // How many secrets each person still has to supply is read per person, in the background.
  const [needed, setNeeded] = useState<Record<string, number | "error">>({});
  useEffect(() => {
    if (!l.data) return;
    let stop = false;
    setNeeded({});
    pool(
      l.data.users,
      4,
      async (u) => {
        try {
          const s = await api.userSecrets(u.username);
          if (!stop) setNeeded((n) => ({ ...n, [u.username]: s.filter((x) => !x.set).length }));
        } catch {
          if (!stop) setNeeded((n) => ({ ...n, [u.username]: "error" }));
        }
      },
      () => stop,
    );
    return () => {
      stop = true;
    };
  }, [l.data]);

  const need = (u: string) => {
    const n = needed[u];
    if (n === undefined) return <span class="muted">Loading…</span>;
    if (n === "error") return <span class="muted">Not available</span>;
    return n === 0 ? <span class="muted">None</span> : <span class="summary-bad">{n} to supply</span>;
  };

  return (
    <>
      <PageHeader title="People" sub="People appear here once they have signed in, or once an enrolment or a secret has been made for them." />
      <Async
        l={l}
        what="Loading people"
        render={({ users, devices }) => {
          if (users.length === 0) return <Empty>No one has signed in yet.</Empty>;
          const count = (u: string) => devices.filter((d) => d.username === u).length;
          return (
            <>
              <div class="only-wide">
                <TableWrap label="People">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Person</th>
                        <th scope="col">Role</th>
                        <th scope="col">Devices</th>
                        <th scope="col">Secrets still needed</th>
                        <th scope="col">Last sign-in</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((u) => (
                        <tr key={u.username}>
                          <th scope="row">
                            <Link href={`/people/${encodeURIComponent(u.username)}`}>{u.name || u.username}</Link>
                            <div class="muted small">{u.username}</div>
                          </th>
                          <td>{u.role === "admin" ? "Administrator" : "User"}</td>
                          <td>{count(u.username)}</td>
                          <td>{need(u.username)}</td>
                          <td>
                            <Time iso={u.last_login_at} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              </div>
              <ul class="cards only-narrow">
                {users.map((u) => (
                  <li key={u.username} class="card">
                    <div class="card-title">
                      <Link href={`/people/${encodeURIComponent(u.username)}`}>{u.name || u.username}</Link>
                      <span class="tag">{u.role === "admin" ? "Administrator" : "User"}</span>
                    </div>
                    <p class="muted">{u.username}</p>
                    <p>{plural(count(u.username), "device")}</p>
                    <p>Secrets still needed: {need(u.username)}</p>
                  </li>
                ))}
              </ul>
            </>
          );
        }}
      />
    </>
  );
}

export function PersonScreen({ username }: { username: string }) {
  const l = useLoad(() => api.user(username), [username]);
  return (
    <>
      <p class="crumb">
        <Link href="/people">People</Link>
      </p>
      <Async
        l={l}
        what="Loading person"
        render={({ user, devices }) => (
          <>
            <PageHeader title={user.name || user.username} sub={user.email} />
            <Section title="Details" id="h-details">
              <Facts
                items={[
                  ["Username", <code>{user.username}</code>],
                  ["Role", user.role === "admin" ? "Administrator" : "User"],
                  ["Groups", user.groups.length ? user.groups.join(", ") : <span class="muted">None</span>],
                  ["Last sign-in", <Time iso={user.last_login_at} />],
                  ["First seen", <Time iso={user.created_at} />],
                ]}
              />
            </Section>
            <Section title="Devices" id="h-devices" actions={<Link class="button" href="/enrol">Enrol a device</Link>}>
              {devices.length === 0 ? (
                <p class="muted">This person has no devices.</p>
              ) : (
                <ul class="cards">
                  {devices.map((d) => (
                    <li key={d.id} class="card">
                      <div class="card-title">
                        <Link href={`/devices/${encodeURIComponent(d.id)}`}>{d.device_name || d.serial_number}</Link>
                        <StatusBadge status={d.status} />
                      </div>
                      <p class="muted">
                        {platformName(d.platform)} · {d.model} · {d.os_version} · seen <Time iso={d.last_seen_at} />
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
            <Section title="Secrets" id="h-secrets">
              <SecretsPanel key={user.username} scope={{ kind: "user", username: user.username }} canAdd={true} linkProfiles={true} />
            </Section>
          </>
        )}
      />
    </>
  );
}
