import { useState } from "preact/hooks";
import { api } from "../api";
import type { ProfileDetail } from "../api";
import { Link, navigate } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { describeAssignment } from "../lib/format";
import { Async, ConfirmDialog, CopyButton, DataTable, Facts, PageHeader, PlatformTags, Primary, Section, StateBadge, Time, toast } from "../components/ui";
import type { Col } from "../components/ui";
import { SourceMark } from "./Profiles";

type Row = ProfileDetail["devices"][number];

const deviceCols: Col<Row>[] = [
  {
    head: "Device",
    primary: true,
    w: "15rem",
    render: ({ device }) => (
      <Primary sub={`${device.model} · ${device.os_version}`} title={device.device_name}>
        <Link href={`/devices/${encodeURIComponent(device.id)}`}>{device.device_name || device.serial_number}</Link>
      </Primary>
    ),
  },
  { head: "Owner", w: "7rem", render: ({ device }) => (device.username ? <Link href={`/people/${encodeURIComponent(device.username)}`}>{device.username}</Link> : <span class="muted">No owner</span>) },
  { head: "State", w: "8rem", render: ({ state }) => <StateBadge state={state.state} /> },
  { head: "Channel", w: "5.5rem", render: ({ device, state }) => (device.platform === "macos" ? (state.channel === "user" ? "User" : "Device") : null) },
  { head: "Detail", render: ({ state }) => (state.detail ? <span class="cell-detail">{state.detail}</span> : null) },
  { head: "Updated", w: "7.5rem", nowrap: true, render: ({ state }) => <Time iso={state.updated_at} /> },
];

function TemplateView({ text }: { text: string }) {
  const lines = text.replace(/\n$/, "").split("\n");
  return (
    <div class="tpl">
      <div class="tpl-bar">
        <span class="muted small">{lines.length} lines</span>
        <CopyButton text={text} label="Copy template" />
      </div>
      <pre class="tpl-code" tabIndex={0} aria-label="Profile template">
        <code>
          {lines.map((l, i) => (
            <span key={i} class="ln">
              {l || " "}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}

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
            ["Platforms", <PlatformTags platforms={p.platforms} />],
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
          <DataTable label="Profile state per device" cols={deviceCols} rows={d.devices} rowKey={(r) => r.device.id} min={56} />
        )}
      </Section>

      <Section title="Template" id="h-template">
        <TemplateView text={p.template} />
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
