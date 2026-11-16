import { useState } from "preact/hooks";
import { api } from "../api";
import type { Device, DeviceDetail } from "../api";
import { Link, navigate } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { platformName } from "../lib/format";
import { Async, CommandBadge, ConfirmDialog, Facts, Modal, PageHeader, Section, StateBadge, StatusBadge, TableWrap, Time, toast } from "../components/ui";

function OwnerEditor({ device, onDone }: { device: Device; onDone: () => void }) {
  const users = useLoad(() => api.users(), []);
  const [value, setValue] = useState(device.username);
  const a = useAction();
  const save = async (username: string) => {
    const ok = await a.run(async () => {
      await api.setOwner(device.id, username);
      return true;
    });
    if (ok) {
      toast(username ? `Owner set to ${username}.` : "Owner cleared.");
      onDone();
    }
  };
  return (
    <div class="owner-edit">
      <label for="owner-select">Change owner</label>
      <div class="row">
        <select id="owner-select" value={value} onChange={(e) => setValue((e.target as HTMLSelectElement).value)} disabled={users.data === null}>
          <option value="">No owner</option>
          {(users.data ?? []).map((u) => (
            <option key={u.username} value={u.username}>
              {u.name ? `${u.name} (${u.username})` : u.username}
            </option>
          ))}
        </select>
        <button type="button" onClick={() => save(value)} disabled={a.busy || value === device.username}>
          Save owner
        </button>
        <button type="button" onClick={() => save("")} disabled={a.busy || !device.username}>
          Clear owner
        </button>
      </div>
      {users.error && <p class="form-error">Could not load people: {users.error.message}</p>}
      {a.error && (
        <p class="form-error" role="alert">
          {a.error}
        </p>
      )}
    </div>
  );
}

function LockDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  const mac = device.platform === "macos";
  const [pin, setPin] = useState("");
  const [message, setMessage] = useState("");
  const a = useAction();
  const valid = !mac || /^\d{6}$/.test(pin);
  const submit = async () => {
    const ok = await a.run(async () => {
      await api.lock(device.id, mac ? pin : "", message.trim());
      return true;
    });
    setPin("");
    if (ok) {
      toast("Lock command queued.");
      onClose();
    }
  };
  return (
    <Modal title={`Lock ${device.device_name}`} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (valid && !a.busy) submit();
        }}
      >
        {mac ? (
          <div class="field">
            <label for="lock-pin">Six-digit PIN</label>
            <input
              id="lock-pin"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              maxLength={6}
              pattern="[0-9]{6}"
              value={pin}
              onInput={(e) => setPin((e.target as HTMLInputElement).value.replace(/\D/g, ""))}
              aria-describedby="lock-pin-help"
              required
            />
            <p id="lock-pin-help" class="hint">
              Whoever unlocks the Mac needs this PIN. It is sent to the Mac and is not stored here.
            </p>
          </div>
        ) : (
          <p class="hint">An iPhone or iPad locks without a PIN. It asks for its own passcode.</p>
        )}
        <div class="field">
          <label for="lock-msg">Message on the lock screen (optional)</label>
          <input id="lock-msg" type="text" value={message} maxLength={200} onInput={(e) => setMessage((e.target as HTMLInputElement).value)} />
        </div>
        {a.error && (
          <p class="form-error" role="alert">
            {a.error}
          </p>
        )}
        <div class="modal-actions">
          <button type="button" onClick={onClose} disabled={a.busy}>
            Cancel
          </button>
          <button type="submit" class="primary" disabled={a.busy || !valid}>
            {a.busy ? "Working…" : "Lock device"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EraseDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  const [typed, setTyped] = useState("");
  const a = useAction();
  return (
    <ConfirmDialog
      title={`Erase ${device.device_name}`}
      confirmLabel="Erase device"
      busy={a.busy}
      error={a.error}
      disabled={typed !== device.serial_number}
      onClose={onClose}
      onConfirm={async () => {
        const ok = await a.run(async () => {
          await api.erase(device.id, typed);
          return true;
        });
        if (ok) {
          toast("Erase command queued.");
          onClose();
        }
      }}
    >
      <p>
        This wipes everything on the device the next time it checks in. It cannot be undone.
      </p>
      <div class="field">
        <label for="erase-serial">
          Type the serial number <code>{device.serial_number}</code> to confirm
        </label>
        <input id="erase-serial" type="text" autoComplete="off" autoCapitalize="off" spellcheck={false} value={typed} onInput={(e) => setTyped((e.target as HTMLInputElement).value)} />
      </div>
    </ConfirmDialog>
  );
}

function RemoveDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  const a = useAction();
  return (
    <ConfirmDialog
      title={`Remove ${device.device_name} from management`}
      confirmLabel="Remove from management"
      busy={a.busy}
      error={a.error}
      onClose={onClose}
      onConfirm={async () => {
        const ok = await a.run(async () => {
          await api.removeDevice(device.id);
          return true;
        });
        if (ok) {
          toast("The device was removed from management.");
          navigate("/devices");
        }
      }}
    >
      <p>
        OpenMDM removes its management profile from the device if it can still reach it, which also removes every profile OpenMDM installed. Then it forgets the device. To manage it again, enrol it again.
      </p>
    </ConfirmDialog>
  );
}

type Dialog = "" | "lock" | "erase" | "remove";

function View({ d, reload }: { d: DeviceDetail; reload: () => void }) {
  const { isAdmin } = useMe();
  const [dialog, setDialog] = useState<Dialog>("");
  const sync = useAction();
  const device = d.device;
  const mac = device.platform === "macos";

  return (
    <>
      <PageHeader title={device.device_name || device.serial_number} sub={`${platformName(device.platform)} · ${device.model}`}>
        <button
          type="button"
          class="primary"
          disabled={sync.busy}
          onClick={async () => {
            const ok = await sync.run(async () => {
              await api.sync(device.id);
              return true;
            });
            if (ok) {
              toast("Sync requested. The device is being woken.");
              reload();
            }
          }}
        >
          {sync.busy ? "Syncing…" : "Sync now"}
        </button>
        <button type="button" onClick={() => setDialog("lock")}>
          Lock…
        </button>
        {isAdmin && (
          <button type="button" class="danger" onClick={() => setDialog("erase")}>
            Erase…
          </button>
        )}
        {isAdmin && (
          <button type="button" class="danger" onClick={() => setDialog("remove")}>
            Remove from management…
          </button>
        )}
        <button type="button" onClick={reload}>
          Refresh
        </button>
      </PageHeader>
      {sync.error && (
        <p class="form-error" role="alert">
          {sync.error}
        </p>
      )}

      <Section title="Device" id="h-facts">
        <Facts
          items={[
            ["Status", <StatusBadge status={device.status} />],
            ["Platform", platformName(device.platform)],
            ["Model", device.model],
            ["OS version", device.os_version],
            ["Serial number", <code>{device.serial_number}</code>],
            ["Identifier (UDID)", <code class="wrap">{device.id}</code>],
            ["Enrolled", <Time iso={device.enrolled_at} />],
            ["Last seen", <Time iso={device.last_seen_at} />],
            ...(mac ? ([["Mac user channel", device.user_channel_id ? "Available" : "Not yet: nobody has logged in since enrolling"]] as [string, string][]) : []),
          ]}
        />
      </Section>

      <Section title="Owner" id="h-owner">
        {d.owner ? (
          <p>
            {isAdmin ? <Link href={`/people/${encodeURIComponent(d.owner.username)}`}>{d.owner.name || d.owner.username}</Link> : d.owner.name || d.owner.username} ({d.owner.email})
          </p>
        ) : (
          <p class="muted">This device has no owner. Profiles that need a person stay blocked until it has one.</p>
        )}
        {isAdmin && <OwnerEditor key={device.username} device={device} onDone={reload} />}
      </Section>

      <Section title="Profiles" id="h-profiles">
        {d.profiles.length === 0 ? (
          <p class="muted">No profile applies to this device.</p>
        ) : (
          <ul class="plan">
            {d.profiles.map((p) => (
              <li key={p.profile_id} class={`plan-item${p.wanted ? "" : " unwanted"}`}>
                <div class="plan-head">
                  <strong>{isAdmin ? <Link href={`/profiles/${encodeURIComponent(p.profile_id)}`}>{p.name}</Link> : p.name}</strong>
                  <StateBadge state={p.state} />
                  {mac && p.wanted && <span class="tag">{p.channel === "user" ? "User channel" : "Device channel"}</span>}
                </div>
                <p class="reason">
                  {p.wanted ? "Wanted" : "Not wanted"}: {p.reason}
                </p>
                {p.detail && <p class={`detail${p.state === "failed" ? " detail-failed" : ""}`}>{p.detail}</p>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Recent commands" id="h-commands">
        {d.commands.length === 0 ? (
          <p class="muted">No commands have been sent to this device.</p>
        ) : (
          <TableWrap label="Recent commands">
            <table>
              <thead>
                <tr>
                  <th scope="col">Command</th>
                  <th scope="col">Profile</th>
                  <th scope="col">Status</th>
                  <th scope="col">Sent</th>
                  <th scope="col">Error or detail</th>
                </tr>
              </thead>
              <tbody>
                {d.commands.map((c) => (
                  <tr key={c.uuid}>
                    <th scope="row">
                      {c.request_type}
                      {mac && <span class="muted"> ({c.channel})</span>}
                    </th>
                    <td>{c.profile_id || <span class="muted">none</span>}</td>
                    <td>
                      <CommandBadge status={c.status} />
                    </td>
                    <td>
                      <Time iso={c.created_at} />
                    </td>
                    <td class="detail-cell">{c.detail || <span class="muted">none</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Section>

      {dialog === "lock" && <LockDialog device={device} onClose={() => { setDialog(""); reload(); }} />}
      {dialog === "erase" && <EraseDialog device={device} onClose={() => { setDialog(""); reload(); }} />}
      {dialog === "remove" && <RemoveDialog device={device} onClose={() => setDialog("")} />}
    </>
  );
}

export function DeviceScreen({ id }: { id: string }) {
  const l = useLoad(() => api.device(id), [id]);
  return (
    <>
      <p class="crumb">
        <Link href="/devices">Devices</Link>
      </p>
      <Async l={l} what="Loading device" render={(d) => <View d={d} reload={l.reload} />} />
    </>
  );
}
