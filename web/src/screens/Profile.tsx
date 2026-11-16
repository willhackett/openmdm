import { useState } from "preact/hooks";
import { api } from "../api";
import type { ProfileDetail } from "../api";
import { Link, navigate } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { describeAssignment, platformName } from "../lib/format";
import { Async, ConfirmDialog, Facts, PageHeader, Section, StateBadge, TableWrap, Time, toast } from "../components/ui";
import { SourceMark } from "./Profiles";

function View({ d }: { d: ProfileDetail }) {
  const { profile: p, info } = d;
  const [confirm, setConfirm] = useState(false);
  const del = useAction();
  const editable = p.source !== "file";
  const secretList = (keys: string[]) =>
    keys.length === 0 ? <span class="muted">None</span> : keys.map((k, i) => <span key={k}>{i > 0 && ", "}<code>{k}</code></span>);

  return (
    <>
      <PageHeader title={p.name} sub={p.description}>
        {editable ? (
          <>
            <Link class="button primary" href={`/profiles/${encodeURIComponent(p.id)}/edit`}>
              Edit
            </Link>
            <button type="button" class="danger" onClick={() => setConfirm(true)}>
              Delete…
            </button>
          </>
        ) : (
          <SourceMark source={p.source} />
        )}
      </PageHeader>

      <Section title="Details" id="h-details">
        <Facts
          items={[
            ["ID", <code>{p.id}</code>],
            ["Platforms", p.platforms.map(platformName).join(", ")],
            ["Mac channel", p.platforms.includes("macos") ? (p.macos_channel === "user" ? "User channel" : "Device channel") : "Not for Mac"],
            ["Assigned to", describeAssignment(p.assignment)],
            ["Source", p.source === "file" ? "A file in the profiles directory (read-only)" : "Made in this UI"],
            ["Updated", <Time iso={p.updated_at} />],
            ["Payload identifier", <code class="wrap">{info.identifier}</code>],
            ["Payload types", info.payload_types.length ? info.payload_types.map((t, i) => <span key={t}>{i > 0 && ", "}<code>{t}</code></span>) : <span class="muted">None</span>],
          ]}
        />
      </Section>

      <Section title="Secrets it names" id="h-secrets">
        <Facts
          items={[
            ["Each person's own", secretList(info.user_secrets)],
            ["Global", secretList(info.global_secrets)],
          ]}
        />
        <p class="hint">
          A device waits (blocked) until every secret here is set. <Link href="/secrets">Manage secrets</Link>.
        </p>
      </Section>

      <Section title="On devices" id="h-devices">
        {d.devices.length === 0 ? (
          <p class="muted">This profile is not on any device.</p>
        ) : (
          <TableWrap label="Profile state per device">
            <table>
              <thead>
                <tr>
                  <th scope="col">Device</th>
                  <th scope="col">Owner</th>
                  <th scope="col">State</th>
                  <th scope="col">Channel</th>
                  <th scope="col">Detail</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {d.devices.map(({ device, state }) => (
                  <tr key={device.id}>
                    <th scope="row">
                      <Link href={`/devices/${encodeURIComponent(device.id)}`}>{device.device_name || device.serial_number}</Link>
                    </th>
                    <td>{device.username ? <Link href={`/people/${encodeURIComponent(device.username)}`}>{device.username}</Link> : <span class="muted">No owner</span>}</td>
                    <td>
                      <StateBadge state={state.state} />
                    </td>
                    <td>{device.platform === "macos" ? (state.channel === "user" ? "User" : "Device") : <span class="muted">Device</span>}</td>
                    <td class="detail-cell">{state.detail || <span class="muted">none</span>}</td>
                    <td>
                      <Time iso={state.updated_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Section>

      <Section title="Template" id="h-template">
        <pre class="code" tabIndex={0} aria-label="Profile template">
          {p.template}
        </pre>
      </Section>

      {confirm && (
        <ConfirmDialog
          title={`Delete ${p.name}`}
          confirmLabel="Delete profile"
          busy={del.busy}
          error={del.error}
          onClose={() => setConfirm(false)}
          onConfirm={async () => {
            const ok = await del.run(async () => {
              await api.deleteProfile(p.id);
              return true;
            });
            if (ok) {
              toast(`Profile ${p.name} deleted.`);
              navigate("/profiles");
            }
          }}
        >
          <p>It will be removed from every device that has it. This cannot be undone.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

export function ProfileScreen({ id }: { id: string }) {
  const l = useLoad(() => api.profile(id), [id]);
  return (
    <>
      <p class="crumb">
        <Link href="/profiles">Profiles</Link>
      </p>
      <Async l={l} what="Loading profile" render={(d) => <View d={d} />} />
    </>
  );
}
