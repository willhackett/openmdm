import { useState } from "preact/hooks";
import { api } from "../api";
import type { SecretEntry } from "../api";
import { Link } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { readFileAsBase64 } from "../lib/format";
import { useMe } from "../lib/me";
import { Async, ConfirmDialog, DataTable, Empty, Modal, toast } from "./ui";

export type Scope = { kind: "user"; username: string } | { kind: "global" };

const KEY_RE = /^[a-z0-9_]+$/;

function SetDialog({
  scope,
  existingKey,
  onClose,
  onSaved,
}: {
  scope: Scope;
  /** Set when replacing or supplying a known key; empty when adding a new one. */
  existingKey: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const adding = existingKey === "";
  const [key, setKey] = useState(existingKey);
  const [mode, setMode] = useState<"text" | "file">("text");
  const [value, setValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const a = useAction();
  const keyOk = KEY_RE.test(key);
  const haveValue = mode === "text" ? value.length > 0 : file !== null;
  const canSave = keyOk && haveValue && !a.busy;

  const submit = async () => {
    const ok = await a.run(async () => {
      let body;
      if (mode === "file") body = { value: await readFileAsBase64(file!), encoding: "base64" as const };
      else body = { value };
      if (scope.kind === "user") await api.setUserSecret(scope.username, key, body);
      else await api.setGlobalSecret(key, body);
      return true;
    });
    // The value never stays in the page, saved or not.
    setValue("");
    setFile(null);
    if (ok) {
      toast(`Secret ${key} saved.`);
      onSaved();
      onClose();
    }
  };

  return (
    <Modal title={adding ? "Add a secret" : `Set ${existingKey}`} onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSave) submit();
        }}
      >
        {adding && (
          <div class="field">
            <label for="secret-key">Key</label>
            <input
              id="secret-key"
              type="text"
              value={key}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              aria-invalid={key !== "" && !keyOk}
              aria-describedby="secret-key-help"
              onInput={(e) => setKey((e.target as HTMLInputElement).value)}
            />
            <p id="secret-key-help" class={key !== "" && !keyOk ? "form-error" : "hint"}>
              {key !== "" && !keyOk ? "Use only lower-case letters, digits and underscores (a-z, 0-9, _)." : "Lower-case letters, digits and underscores. A profile names it as secret \"key\"."}
            </p>
          </div>
        )}
        <fieldset class="field">
          <legend>Kind of value</legend>
          <label class="check">
            <input type="radio" name="kind" checked={mode === "text"} onChange={() => setMode("text")} /> Text or password
          </label>
          <label class="check">
            <input type="radio" name="kind" checked={mode === "file"} onChange={() => setMode("file")} /> Certificate or other file
          </label>
        </fieldset>
        {mode === "text" ? (
          <div class="field">
            <label for="secret-value">Value</label>
            <input id="secret-value" type="password" autoComplete="new-password" value={value} onInput={(e) => setValue((e.target as HTMLInputElement).value)} />
          </div>
        ) : (
          <div class="field">
            <label for="secret-file">Choose a file</label>
            <input id="secret-file" type="file" onChange={(e) => setFile((e.target as HTMLInputElement).files?.[0] ?? null)} />
            <p class="hint">The file is read in your browser and sent as base64. Use this for a .p12 or other certificate.</p>
          </div>
        )}
        <p class="hint">Values are stored in OpenBao. You can replace a value later, but it can never be read back.</p>
        {a.error && (
          <p class="form-error" role="alert">
            {a.error}
          </p>
        )}
        <div class="modal-actions">
          <button type="button" onClick={onClose} disabled={a.busy}>
            Cancel
          </button>
          <button type="submit" class="primary" disabled={!canSave}>
            {a.busy ? "Saving…" : "Save secret"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function SecretsPanel({ scope, canAdd, linkProfiles }: { scope: Scope; canAdd: boolean; linkProfiles: boolean }) {
  const l = useLoad(() => (scope.kind === "user" ? api.userSecrets(scope.username) : api.globalSecrets()), [scope.kind, scope.kind === "user" ? scope.username : ""]);
  const [setting, setSetting] = useState<string | null>(null); // "" means a new key
  const [deleting, setDeleting] = useState<SecretEntry | null>(null);
  const del = useAction();
  const { me } = useMe();
  // Profile ids are what the API gives; an administrator can see their names.
  const names = useLoad(async () => (linkProfiles ? Object.fromEntries((await api.profiles()).map((p) => [p.id, p.name])) : {}), [linkProfiles]);
  const nameOf = (id: string) => (names.data as Record<string, string> | null)?.[id] ?? id;
  const whose = scope.kind === "global" ? "every device whose profiles use it" : scope.username === me.user.username ? "your devices" : "that person's devices";
  const usedBy = (s: SecretEntry) =>
    s.used_by.map((p, i) => (
      <span key={p}>
        {i > 0 && ", "}
        {linkProfiles ? <Link href={`/profiles/${encodeURIComponent(p)}`}>{nameOf(p)}</Link> : nameOf(p)}
      </span>
    ));

  return (
    <div class="secrets">
      <p class="hint intro">When a value is set, the profiles waiting on it are sent to {whose}. Values are never shown again.</p>
      {canAdd && (
        <p>
          <button type="button" onClick={() => setSetting("")}>
            Add a secret
          </button>
        </p>
      )}
      <Async
        l={l}
        what="Loading secrets"
        render={(list) => {
          // Keys a profile needs and that are not set come first.
          const sorted = [...list].sort((x, y) => Number(x.set) - Number(y.set) || x.key.localeCompare(y.key));
          if (sorted.length === 0)
            return (
              <Empty>
                <p>No secrets are set{scope.kind === "user" ? " and no profile asks for one." : "."}</p>
              </Empty>
            );
          return (
            <DataTable
              label="Secrets"
              min={40}
              rows={sorted}
              rowKey={(s) => s.key}
              rowClass={(s) => (s.set ? "" : "row-needed")}
              cols={[
                { head: "Key", primary: true, w: "14rem", render: (s) => <div class="cell-name"><code>{s.key}</code></div> },
                {
                  head: "Status",
                  render: (s) =>
                    s.set ? (
                      <>
                        <span class="status-set">Set</span>
                        {s.used_by.length > 0 && <div class="cell-sub">Used by {usedBy(s)}</div>}
                      </>
                    ) : (
                      <span class="status-needed">
                        {s.used_by.length > 0 ? <>Needed by {usedBy(s)}</> : "Not used by a profile"} <span class="muted">&middot; not set yet</span>
                      </span>
                    ),
                },
                {
                  head: "Actions",
                  srHead: true,
                  end: true,
                  w: "11.5rem",
                  render: (s) => (
                    <span class="row-actions">
                      <button type="button" class={s.set ? "" : "primary"} onClick={() => setSetting(s.key)}>
                        {s.set ? "Replace" : "Set"}
                        <span class="sr-only"> {s.key}</span>
                      </button>
                      {s.set && (
                        <button type="button" class="danger" onClick={() => setDeleting(s)}>
                          Delete<span class="sr-only"> {s.key}</span>
                        </button>
                      )}
                    </span>
                  ),
                },
              ]}
            />
          );
        }}
      />
      {setting !== null && <SetDialog scope={scope} existingKey={setting} onClose={() => setSetting(null)} onSaved={l.reload} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.key}`}
          confirmLabel="Delete secret"
          busy={del.busy}
          error={del.error}
          onClose={() => {
            del.setError("");
            setDeleting(null);
          }}
          onConfirm={async () => {
            const k = deleting.key;
            const ok = await del.run(async () => {
              if (scope.kind === "user") await api.deleteUserSecret(scope.username, k);
              else await api.deleteGlobalSecret(k);
              return true;
            });
            if (ok) {
              toast(`Secret ${k} deleted.`);
              setDeleting(null);
              l.reload();
            }
          }}
        >
          <p>
            Any profile that uses <code>{deleting.key}</code>
            {deleting.used_by.length ? ` (${deleting.used_by.map(nameOf).join(", ")})` : ""} will be blocked on the devices it reaches until a new value is set.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}
