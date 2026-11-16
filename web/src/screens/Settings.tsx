import { useState } from "preact/hooks";
import { api } from "../api";
import type { PushInfo, Settings } from "../api";
import { useAction, useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { absTime, daysUntil, isZero, readFileAsText } from "../lib/format";
import { Async, Facts, PageHeader, Section, Time, toast } from "../components/ui";

interface Pem {
  text: string;
  /** Set when the text came from a file, in which case it is not shown. */
  fileName: string;
}

function PemInput({ id, label, accept, value, onChange, hideContent }: { id: string; label: string; accept: string; value: Pem; onChange: (v: Pem) => void; hideContent: boolean }) {
  const [mode, setMode] = useState<"file" | "paste">("file");
  const [err, setErr] = useState("");
  return (
    <fieldset class="field pem">
      <legend>{label}</legend>
      <div class="row">
        <label class="check">
          <input type="radio" name={id + "-mode"} checked={mode === "file"} onChange={() => setMode("file")} /> Choose a file
        </label>
        <label class="check">
          <input type="radio" name={id + "-mode"} checked={mode === "paste"} onChange={() => setMode("paste")} /> Paste PEM
        </label>
      </div>
      {mode === "file" ? (
        <div>
          <label for={id + "-file"} class="sr-only">
            {label} file
          </label>
          <input
            id={id + "-file"}
            type="file"
            accept={accept}
            onChange={async (e) => {
              const f = (e.target as HTMLInputElement).files?.[0];
              setErr("");
              if (!f) return onChange({ text: "", fileName: "" });
              try {
                onChange({ text: await readFileAsText(f), fileName: f.name });
              } catch (x) {
                setErr(x instanceof Error ? x.message : "The file could not be read.");
              }
            }}
          />
          {value.fileName && <p class="hint">Loaded {value.fileName}{hideContent ? ". Its content is not shown." : "."}</p>}
        </div>
      ) : (
        <div>
          <label for={id + "-text"} class="sr-only">
            {label} as PEM text
          </label>
          <textarea
            id={id + "-text"}
            class="code"
            rows={6}
            spellcheck={false}
            autoComplete="off"
            wrap="off"
            value={value.fileName ? "" : value.text}
            placeholder={value.fileName ? `Using ${value.fileName}. Typing here replaces it.` : "-----BEGIN ...-----"}
            onInput={(e) => onChange({ text: (e.target as HTMLTextAreaElement).value, fileName: "" })}
          />
        </div>
      )}
      {err && <p class="form-error">{err}</p>}
    </fieldset>
  );
}

function PushForm({ onSaved }: { onSaved: (p: PushInfo) => void }) {
  const [cert, setCert] = useState<Pem>({ text: "", fileName: "" });
  const [key, setKey] = useState<Pem>({ text: "", fileName: "" });
  const a = useAction();
  const ready = cert.text.includes("BEGIN CERTIFICATE") && /BEGIN [A-Z ]*PRIVATE KEY/.test(key.text);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        if (!ready) return;
        const r = await a.run(() => api.setPushCertificate(cert.text, key.text));
        // The key never stays in the page.
        setKey({ text: "", fileName: "" });
        if (r) {
          setCert({ text: "", fileName: "" });
          toast("Push certificate saved.");
          onSaved(r);
        }
      }}
    >
      <PemInput id="push-cert" label="Certificate (PEM)" accept=".pem,.crt,.cer" value={cert} onChange={setCert} hideContent={false} />
      <PemInput id="push-key" label="Private key (PEM)" accept=".pem,.key" value={key} onChange={setKey} hideContent={true} />
      {(cert.text || key.text) && !ready && <p class="hint">Both a certificate (BEGIN CERTIFICATE) and a private key (BEGIN PRIVATE KEY) are needed.</p>}
      {a.error && (
        <p class="form-error" role="alert">
          {a.error}
        </p>
      )}
      <button type="submit" class="primary" disabled={!ready || a.busy}>
        {a.busy ? "Saving…" : "Save push certificate"}
      </button>
    </form>
  );
}

function PushStatus({ push }: { push: PushInfo }) {
  if (!push.configured)
    return (
      <div class="banner banner-warn" role="alert">
        <strong>No push certificate.</strong> Devices cannot be woken, so enrolment will not work until one is saved below.
      </div>
    );
  const days = daysUntil(push.not_after);
  return (
    <>
      {days < 0 ? (
        <div class="banner banner-error" role="alert">
          <strong>The push certificate has expired.</strong> Devices cannot be reached until a renewed one is saved.
        </div>
      ) : days <= 30 ? (
        <div class="banner banner-warn" role="alert">
          <strong>The push certificate expires in {Math.max(1, Math.ceil(days))} {Math.ceil(days) === 1 ? "day" : "days"}.</strong> Renew it and upload the new one below.
        </div>
      ) : null}
      <Facts
        items={[
          ["Topic", <code class="wrap">{push.topic}</code>],
          [
            "Expires",
            <>
              <Time iso={push.not_after} /> <span class="muted">({absTime(push.not_after)})</span>
            </>,
          ],
        ]}
      />
    </>
  );
}

function View({ s, reload }: { s: Settings; reload: () => void }) {
  const me = useMe();
  return (
    <>
      <Section title="Push certificate (APNs)" id="h-push">
        <PushStatus push={s.push} />
        <h3>{s.push.configured ? "Replace the certificate" : "Upload a certificate"}</h3>
        <PushForm
          onSaved={() => {
            reload();
            me.refresh();
          }}
        />
      </Section>

      <Section title="Certificate authority" id="h-ca">
        <Facts
          items={[
            ["Subject", <code class="wrap">{s.ca.subject}</code>],
            ["SHA-256 fingerprint", <code class="wrap">{s.ca.sha256}</code>],
            ["Expires", isZero(s.ca.not_after) ? "Unknown" : <><Time iso={s.ca.not_after} /> <span class="muted">({absTime(s.ca.not_after)})</span></>],
          ]}
        />
        <p>
          <a class="button" href={api.caPemHref} download="openmdm-ca.pem">
            Download the CA certificate (PEM)
          </a>
        </p>
      </Section>

      <Section title="Secret store" id="h-secrets">
        <Facts
          items={[
            ["Backend", s.secrets.backend],
            ["Status", s.secrets.healthy ? <span class="badge badge-installed">Healthy</span> : <span class="badge badge-failed">Not healthy</span>],
          ]}
        />
        {!s.secrets.healthy && (
          <p class="form-error mono" role="alert">
            {s.secrets.error || "The secret store cannot be reached."}
          </p>
        )}
      </Section>

      <Section title="Server" id="h-server">
        <Facts
          items={[
            ["Public URL", <code class="wrap">{s.public_url}</code>],
            ["Organization", s.organization || <span class="muted">Not set</span>],
            ["Version", me.me.version || "Unknown"],
          ]}
        />
        <p class="hint">The public URL and organization come from the server's configuration file and cannot be changed here.</p>
      </Section>
    </>
  );
}

export function SettingsScreen() {
  const l = useLoad(() => api.settings(), []);
  return (
    <>
      <PageHeader title="Settings" />
      <Async l={l} what="Loading settings" render={(s) => <View s={s} reload={l.reload} />} />
    </>
  );
}
