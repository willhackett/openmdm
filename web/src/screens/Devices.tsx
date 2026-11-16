import { useEffect, useState } from "preact/hooks";
import { api } from "../api";
import type { Device, PlanEntry, ProfileState } from "../api";
import { Link } from "../lib/router";
import { pool, useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { platformName } from "../lib/format";
import { Async, DataTable, Empty, PageHeader, Primary, StateChips, StatusBadge, Time } from "../components/ui";
import type { Col } from "../components/ui";

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
  const counts: Partial<Record<ProfileState, number>> = {};
  for (const p of plan) if (p.state) counts[p.state] = (counts[p.state] ?? 0) + 1;
  return <StateChips counts={counts} none="No profiles" />;
}

export function DevicesScreen() {
  const { me, isAdmin } = useMe();
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
      {isAdmin && !me.push.configured && (
        <div class="banner banner-warn" role="alert">
          <strong>No push certificate.</strong> Devices cannot be woken until there is one. <Link href="/settings#push-certificate">Get a push certificate</Link>
        </div>
      )}
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
                <DataTable
                  label="Devices"
                  min={64}
                  rows={devices}
                  rowKey={(d) => d.id}
                  cols={[
                    {
                      head: "Name",
                      primary: true,
                      render: (d) => (
                        <Primary sub={`${d.model} · ${d.os_version}`} title={d.device_name}>
                          <Link href={`/devices/${encodeURIComponent(d.id)}`}>{d.device_name || d.serial_number}</Link>
                        </Primary>
                      ),
                    },
                    ...(isAdmin
                      ? ([{ head: "Owner", w: "7.5rem", render: (d: Device) => (d.username ? <Link href={`/people/${encodeURIComponent(d.username)}`}>{d.username}</Link> : <span class="muted">No owner</span>) }] as Col<Device>[])
                      : []),
                    { head: "Platform", w: "6rem", render: (d) => <span class="tag">{platformName(d.platform)}</span> },
                    { head: "Status", w: "7.5rem", render: (d) => <StatusBadge status={d.status} /> },
                    { head: "Last seen", w: "8.5rem", nowrap: true, render: (d) => <Time iso={d.last_seen_at} /> },
                    { head: "Profiles", w: "13rem", render: (d) => <Summary plan={sums[d.id]} /> },
                  ]}
                />
              )}
            </>
          );
        }}
      />
    </>
  );
}
