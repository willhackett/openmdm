import { useEffect, useState } from "preact/hooks";
import { api } from "../api";
import type { Device, PlanEntry } from "../api";
import { Link } from "../lib/router";
import { pool, useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { platformName, summariseStates } from "../lib/format";
import { Async, Empty, PageHeader, StatusBadge, TableWrap, Time } from "../components/ui";

/** The device list has no profile states, so each device's plan is read in the background. */
function useSummaries(devices: Device[] | null) {
  const [sums, setSums] = useState<Record<string, PlanEntry[] | "error">>({});
  useEffect(() => {
    if (!devices) return;
    let stop = false;
    setSums({});
    pool(
      devices,
      4,
      async (d) => {
        try {
          const r = await api.device(d.id);
          if (!stop) setSums((s) => ({ ...s, [d.id]: r.profiles }));
        } catch {
          if (!stop) setSums((s) => ({ ...s, [d.id]: "error" }));
        }
      },
      () => stop,
    );
    return () => {
      stop = true;
    };
  }, [devices]);
  return sums;
}

function Summary({ plan }: { plan: PlanEntry[] | "error" | undefined }) {
  if (plan === undefined) return <span class="muted">Loading…</span>;
  if (plan === "error") return <span class="muted">Not available</span>;
  const text = summariseStates(plan);
  const bad = plan.some((p) => p.state === "failed" || p.state === "blocked");
  return <span class={bad ? "summary-bad" : ""}>{text}</span>;
}

export function DevicesScreen() {
  const { isAdmin } = useMe();
  const l = useLoad(() => api.devices(), []);
  const sums = useSummaries(l.data);
  const [q, setQ] = useState("");

  return (
    <>
      <PageHeader title={isAdmin ? "Devices" : "My devices"}>
        <Link class="button primary" href="/enrol">
          Enrol a device
        </Link>
        <button type="button" onClick={l.reload}>
          Refresh
        </button>
      </PageHeader>
      <Async
        l={l}
        what="Loading devices"
        render={(all) => {
          const needle = q.trim().toLowerCase();
          const devices = needle
            ? all.filter((d) => [d.device_name, d.username, d.model, d.serial_number, platformName(d.platform)].some((v) => v.toLowerCase().includes(needle)))
            : all;
          if (all.length === 0)
            return (
              <Empty>
                <p>
                  <strong>No devices yet.</strong>
                </p>
                <p>
                  <Link href="/enrol">Enrol a device</Link> to see it here.
                </p>
              </Empty>
            );
          return (
            <>
              <div class="toolbar">
                <label for="dev-filter" class="sr-only">
                  Filter devices
                </label>
                <input id="dev-filter" type="search" placeholder="Filter by name, owner or model" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
                <span class="muted">
                  {devices.length} of {all.length}
                </span>
              </div>
              {devices.length === 0 ? (
                <Empty>No device matches that filter.</Empty>
              ) : (
                <>
                  <div class="only-wide">
                    <TableWrap label="Devices">
                      <table>
                        <thead>
                          <tr>
                            <th scope="col">Name</th>
                            {isAdmin && <th scope="col">Owner</th>}
                            <th scope="col">Platform</th>
                            <th scope="col">Model</th>
                            <th scope="col">OS version</th>
                            <th scope="col">Status</th>
                            <th scope="col">Last seen</th>
                            <th scope="col">Profiles</th>
                          </tr>
                        </thead>
                        <tbody>
                          {devices.map((d) => (
                            <tr key={d.id}>
                              <th scope="row">
                                <Link href={`/devices/${encodeURIComponent(d.id)}`}>{d.device_name || d.serial_number}</Link>
                              </th>
                              {isAdmin && <td>{d.username ? <Link href={`/people/${encodeURIComponent(d.username)}`}>{d.username}</Link> : <span class="muted">No owner</span>}</td>}
                              <td>{platformName(d.platform)}</td>
                              <td>{d.model}</td>
                              <td>{d.os_version}</td>
                              <td>
                                <StatusBadge status={d.status} />
                              </td>
                              <td>
                                <Time iso={d.last_seen_at} />
                              </td>
                              <td>
                                <Summary plan={sums[d.id]} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </TableWrap>
                  </div>
                  <ul class="cards only-narrow">
                    {devices.map((d) => (
                      <li key={d.id} class="card">
                        <div class="card-title">
                          <Link href={`/devices/${encodeURIComponent(d.id)}`}>{d.device_name || d.serial_number}</Link>
                          <StatusBadge status={d.status} />
                        </div>
                        <p class="muted">
                          {platformName(d.platform)} · {d.model} · {d.os_version}
                        </p>
                        {isAdmin && (
                          <p>
                            Owner: {d.username ? <Link href={`/people/${encodeURIComponent(d.username)}`}>{d.username}</Link> : <span class="muted">none</span>}
                          </p>
                        )}
                        <p>
                          Last seen <Time iso={d.last_seen_at} />
                        </p>
                        <p>
                          Profiles: <Summary plan={sums[d.id]} />
                        </p>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          );
        }}
      />
    </>
  );
}
