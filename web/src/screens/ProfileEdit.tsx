import { useState } from "preact/hooks";
import { api } from "../api";
import type { Channel, Platform, Profile, TemplateInfo } from "../api";
import { Link, navigate } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { readFileAsText } from "../lib/format";
import { Async, Empty, PageHeader, toast } from "../components/ui";

const PLATFORMS: Platform[] = ["macos", "ios", "ipados"];
const ID_RE = /^[a-z0-9-]+$/;

const blank: Profile = {
  id: "",
  name: "",
  description: "",
  platforms: ["macos", "ios", "ipados"],
  macos_channel: "device",
  assignment: { everyone: true, users: [], groups: [] },
  template: "",
  source: "ui",
  updated_at: "",
};

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/\.[a-z]+$/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

function InfoView({ info }: { info: TemplateInfo }) {
  const list = (xs: string[]) => (xs.length ? xs.map((x, i) => <span key={x}>{i > 0 && ", "}<code>{x}</code></span>) : <span class="muted">none</span>);
  return (
    <div class="valid" role="status">
      <p>
        <strong>The template is valid.</strong>
      </p>
      <dl class="facts compact">
        <div>
          <dt>Payload identifier</dt>
          <dd>
            <code class="wrap">{info.identifier}</code>
          </dd>
        </div>
        <div>
          <dt>Names these secrets (each person's own)</dt>
          <dd>{list(info.user_secrets)}</dd>
        </div>
        <div>
          <dt>Names these global secrets</dt>
          <dd>{list(info.global_secrets)}</dd>
        </div>
        <div>
          <dt>Payload types</dt>
          <dd>{list(info.payload_types)}</dd>
        </div>
      </dl>
    </div>
  );
}

function Form({ initial, isNew }: { initial: Profile; isNew: boolean }) {
  const users = useLoad(() => api.users(), []);
  const [id, setId] = useState(initial.id);
  const [name, setName] = useState(initial.name);
  const [description, setDescription] = useState(initial.description);
  const [platforms, setPlatforms] = useState<Platform[]>(initial.platforms);
  const [channel, setChannel] = useState<Channel>(initial.macos_channel || "device");
  const [everyone, setEveryone] = useState(initial.assignment.everyone);
  const [chosenUsers, setChosenUsers] = useState<string[]>(initial.assignment.users ?? []);
  const [groupsText, setGroupsText] = useState((initial.assignment.groups ?? []).join(", "));
  const [template, setTemplate] = useState(initial.template);
  const [info, setInfo] = useState<TemplateInfo | null>(null);
  const [validationError, setValidationError] = useState("");
  const [fileError, setFileError] = useState("");
  const validate = useAction();
  const save = useAction();

  const groups = groupsText
    .split(/[,\n]/)
    .map((g) => g.trim())
    .filter(Boolean);
  const idOk = ID_RE.test(id);

  const build = (): Profile => ({
    ...initial,
    id,
    name: name.trim(),
    description: description.trim(),
    platforms,
    macos_channel: channel,
    assignment: everyone ? { everyone: true, users: [], groups: [] } : { everyone: false, users: chosenUsers, groups },
    template,
    source: "ui",
  });

  const changed = () => {
    setInfo(null);
    setValidationError("");
  };

  const toggle = <T,>(list: T[], v: T, on: boolean) => (on ? [...list.filter((x) => x !== v), v] : list.filter((x) => x !== v));

  const knownUsers = new Set((users.data ?? []).map((u) => u.username));
  const userChoices = [...(users.data ?? []).map((u) => ({ username: u.username, label: u.name ? `${u.name} (${u.username})` : u.username })), ...chosenUsers.filter((u) => !knownUsers.has(u)).map((u) => ({ username: u, label: u }))];

  const pickFile = async (f: File | undefined) => {
    setFileError("");
    if (!f) return;
    try {
      const text = await readFileAsText(f);
      setTemplate(text);
      changed();
      if (isNew && !id) setId(slug(f.name));
      if (!name) setName(f.name.replace(/\.[a-z]+$/i, ""));
    } catch (e) {
      setFileError(e instanceof Error ? e.message : "The file could not be read.");
    }
  };

  const problems: string[] = [];
  if (!idOk) problems.push("The ID needs lower-case letters, digits and hyphens.");
  if (!name.trim()) problems.push("Give the profile a name.");
  if (platforms.length === 0) problems.push("Choose at least one platform.");
  if (!template.trim()) problems.push("The template is empty.");

  return (
    <form
      class="profile-form"
      onSubmit={async (e) => {
        e.preventDefault();
        if (problems.length) return;
        const r = await save.run(() => api.saveProfile(build()));
        if (r) {
          toast(`Profile ${r.profile.name} saved.`);
          navigate(`/profiles/${encodeURIComponent(r.profile.id)}`);
        }
      }}
    >
      <div class="field">
        <label for="p-name">Name</label>
        <input id="p-name" type="text" value={name} onInput={(e) => setName((e.target as HTMLInputElement).value)} required />
      </div>
      <div class="field">
        <label for="p-id">ID</label>
        <input
          id="p-id"
          type="text"
          value={id}
          readOnly={!isNew}
          autoCapitalize="off"
          spellcheck={false}
          aria-invalid={id !== "" && !idOk}
          aria-describedby="p-id-help"
          onInput={(e) => setId((e.target as HTMLInputElement).value)}
          required
        />
        <p id="p-id-help" class={id !== "" && !idOk ? "form-error" : "hint"}>
          {isNew ? "Lower-case letters, digits and hyphens. It cannot be changed later." : "The ID cannot be changed."}
        </p>
      </div>
      <div class="field">
        <label for="p-desc">Description</label>
        <input id="p-desc" type="text" value={description} onInput={(e) => setDescription((e.target as HTMLInputElement).value)} />
      </div>

      <fieldset class="field">
        <legend>Platforms</legend>
        {PLATFORMS.map((p) => (
          <label key={p} class="check">
            <input
              type="checkbox"
              checked={platforms.includes(p)}
              onChange={(e) => {
                setPlatforms(toggle(platforms, p, (e.target as HTMLInputElement).checked));
                changed();
              }}
            />{" "}
            {p === "macos" ? "Mac" : p === "ios" ? "iPhone" : "iPad"} <span class="muted small">({p})</span>
          </label>
        ))}
      </fieldset>

      <div class="field">
        <label for="p-channel">Mac channel</label>
        <select id="p-channel" value={channel} disabled={!platforms.includes("macos")} onChange={(e) => setChannel((e.target as HTMLSelectElement).value as Channel)} aria-describedby="p-channel-help">
          <option value="device">Device (the whole machine)</option>
          <option value="user">User (the logged-in person)</option>
        </select>
        <p id="p-channel-help" class="hint">
          Mail accounts and personal certificates need the user channel. iPhone and iPad always use the device channel.
        </p>
      </div>

      <fieldset class="field">
        <legend>Who gets it</legend>
        <label class="check">
          <input type="radio" name="assign" checked={everyone} onChange={() => setEveryone(true)} /> Everyone
        </label>
        <label class="check">
          <input type="radio" name="assign" checked={!everyone} onChange={() => setEveryone(false)} /> Chosen people and groups
        </label>
        {!everyone && (
          <div class="assign-detail">
            <p class="legend-sub">People</p>
            {users.error ? (
              <p class="form-error">Could not load people: {users.error.message}</p>
            ) : users.data === null ? (
              <p class="muted">Loading people…</p>
            ) : (
              <div class="checks">
                {userChoices.map((u) => (
                  <label key={u.username} class="check">
                    <input type="checkbox" checked={chosenUsers.includes(u.username)} onChange={(e) => setChosenUsers(toggle(chosenUsers, u.username, (e.target as HTMLInputElement).checked))} /> {u.label}
                  </label>
                ))}
              </div>
            )}
            <div class="field">
              <label for="p-groups">Groups (from the identity provider), separated by commas</label>
              <input id="p-groups" type="text" value={groupsText} autoCapitalize="off" spellcheck={false} onInput={(e) => setGroupsText((e.target as HTMLInputElement).value)} placeholder="family, staff" />
            </div>
            {chosenUsers.length === 0 && groups.length === 0 && <p class="hint">With no one chosen, the profile goes to nobody.</p>}
          </div>
        )}
      </fieldset>

      <div class="field">
        <div class="label-row">
          <label for="p-template">Template</label>
          <input
            id="p-file"
            class="sr-only-file"
            type="file"
            accept=".mobileconfig,.plist,.xml,text/xml"
            onChange={(e) => {
              const input = e.target as HTMLInputElement;
              pickFile(input.files?.[0]);
              input.value = "";
            }}
          />
          <label class="button small" for="p-file">
            Start from a .mobileconfig file
          </label>
        </div>
        <textarea
          id="p-template"
          class="code editor"
          rows={22}
          spellcheck={false}
          autoCapitalize="off"
          wrap="off"
          value={template}
          onInput={(e) => {
            setTemplate((e.target as HTMLTextAreaElement).value);
            changed();
          }}
          aria-describedby="p-template-help"
        />
        <p id="p-template-help" class="hint">
          A property list with template actions such as <code>{'{{ .User.Email }}'}</code> or <code>{'{{ secret "key" }}'}</code>. The top-level PayloadIdentifier must be a constant.
        </p>
        {fileError && <p class="form-error">{fileError}</p>}
      </div>

      <div class="validate">
        <button
          type="button"
          disabled={validate.busy || !template.trim()}
          onClick={async () => {
            setInfo(null);
            setValidationError("");
            const r = await validate.run(() => api.validateProfile(build()));
            if (r) setInfo(r);
            else setValidationError("failed");
          }}
        >
          {validate.busy ? "Checking…" : "Validate"}
        </button>
        {info && <InfoView info={info} />}
        {validationError && validate.error && (
          <p class="form-error mono" role="alert">
            {validate.error}
          </p>
        )}
      </div>

      {save.error && (
        <p class="form-error mono" role="alert">
          {save.error}
        </p>
      )}
      {problems.length > 0 && (id !== "" || name !== "" || template !== "") && (
        <ul class="hint problems">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      <div class="form-actions">
        <button type="submit" class="primary" disabled={save.busy || problems.length > 0}>
          {save.busy ? "Saving…" : "Save profile"}
        </button>
        <Link class="button" href={isNew ? "/profiles" : `/profiles/${encodeURIComponent(initial.id)}`}>
          Cancel
        </Link>
      </div>
    </form>
  );
}

export function ProfileEditScreen({ id }: { id?: string }) {
  const l = useLoad(async () => (id ? (await api.profile(id)).profile : blank), [id]);
  return (
    <>
      <p class="crumb">
        <Link href="/profiles">Profiles</Link>
      </p>
      <PageHeader title={id ? "Edit profile" : "New profile"} />
      <Async
        l={l}
        what="Loading profile"
        render={(p) =>
          p.source === "file" ? (
            <Empty>
              <p>
                <strong>This profile comes from a file and is read-only.</strong> Change the file in the profiles directory instead.
              </p>
              <p>
                <Link href={`/profiles/${encodeURIComponent(p.id)}`}>Back to the profile</Link>
              </p>
            </Empty>
          ) : (
            <Form key={p.id || "new"} initial={p} isNew={!id} />
          )
        }
      />
    </>
  );
}
