import { useEffect, useRef, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import { api } from "../api";
import type { PushInfo, PushRequest } from "../api";
import { useAction, useLoad } from "../lib/hooks";
import { absDate, daysUntil, readFileAsText } from "../lib/format";
import { Async, Facts, Time, toast } from "../components/ui";

interface Pem {
  text: string;
  /** Set when the text came from a file. */
  fileName: string;
}
const empty: Pem = { text: "", fileName: "" };

/** Choose a file or paste its text. */
export function TextOrFile({
  id,
  label,
  accept,
  value,
  onChange,
  hideContent,
  placeholder,
}: {
  id: string;
  label: string;
  accept: string;
  value: Pem;
  onChange: (v: Pem) => void;
  hideContent?: boolean;
  placeholder: string;
}) {
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
          <input type="radio" name={id + "-mode"} checked={mode === "paste"} onChange={() => setMode("paste")} /> Paste the text
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
              if (!f) return onChange(empty);
              try {
                onChange({ text: await readFileAsText(f), fileName: f.name });
              } catch (x) {
                setErr(x instanceof Error ? x.message : "The file could not be read.");
              }
            }}
          />
          {value.fileName && (
            <p class="hint">
              Loaded {value.fileName}
              {hideContent ? ". Its content is not shown." : "."}
            </p>
          )}
        </div>
      ) : (
        <div>
          <label for={id + "-text"} class="sr-only">
            {label} as text
          </label>
          <textarea
            id={id + "-text"}
            class="code"
            rows={5}
            spellcheck={false}
            autoComplete="off"
            wrap="off"
            value={value.fileName ? "" : value.text}
            placeholder={value.fileName ? `Using ${value.fileName}. Typing here replaces it.` : placeholder}
            onInput={(e) => onChange({ text: (e.target as HTMLTextAreaElement).value, fileName: "" })}
          />
        </div>
      )}
      {err && <p class="form-error">{err}</p>}
    </fieldset>
  );
}

/** The two-field upload for someone who already has a certificate and its key. */
function KeyPairForm({ onSaved }: { onSaved: (p: PushInfo) => void }) {
  const [cert, setCert] = useState<Pem>(empty);
  const [key, setKey] = useState<Pem>(empty);
  const a = useAction();
  const ready = cert.text.includes("BEGIN CERTIFICATE") && /BEGIN [A-Z ]*PRIVATE KEY/.test(key.text);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        if (!ready) return;
        const r = await a.run(() => api.setPushCertificate(cert.text, key.text));
        // The key never stays in the page.
        setKey(empty);
        if (r) {
          setCert(empty);
          toast("Push certificate saved.");
          onSaved(r);
        }
      }}
    >
      <TextOrFile id="push-cert" label="Certificate (PEM)" accept=".pem,.crt,.cer" value={cert} onChange={setCert} placeholder="-----BEGIN CERTIFICATE-----" />
      <TextOrFile id="push-key" label="Private key (PEM)" accept=".pem,.key" value={key} onChange={setKey} hideContent placeholder="-----BEGIN PRIVATE KEY-----" />
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

type StepState = "done" | "current" | "waiting";

function Step({ n, title, state, children }: { n: number; title: string; state: StepState; children?: ComponentChildren }) {
  return (
    <li class={`step step-${state}`} aria-current={state === "current" ? "step" : undefined}>
      <span class="step-mark" aria-hidden="true">
        {state === "done" ? "✓" : n}
      </span>
      <div class="step-body">
        <h3>
          {title}
          <span class="step-state">{state === "done" ? "Done" : state === "current" ? "Now" : "Waiting"}</span>
        </h3>
        {children}
      </div>
    </li>
  );
}

function download(filename: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Err({ text }: { text: string }) {
  return text ? (
    <p class="form-error" role="alert">
      {text}
    </p>
  ) : null;
}

function Flow({ req, reloadReq, onSaved, onCancel, renewing }: { req: PushRequest; reloadReq: () => void; onSaved: (p: PushInfo) => void; onCancel?: () => void; renewing: boolean }) {
  const [email, setEmail] = useState("");
  const [encrypted, setEncrypted] = useState<Pem>(empty);
  const [out, setOut] = useState<{ filename: string; content: string } | null>(null);
  const [cert, setCert] = useState<Pem>(empty);
  const gen = useAction();
  const again = useAction();
  const reset = useAction();
  const send = useAction();
  const dec = useAction();
  const up = useAction();
  const pending = req.pending;
  const sent = pending && !!req.email;
  const s1: StepState = pending ? "done" : "current";
  const s2: StepState = !pending ? "waiting" : out ? "done" : "current";
  const s3: StepState = !pending ? "waiting" : out ? "current" : "waiting";

  return (
    <ol class="steps">
      <Step n={1} title="Generate a signing request" state={s1}>
        <p>
          OpenMDM makes a new key and a signing request (CSR) for it. The private key stays on the server, sealed.
          {renewing && " The current certificate keeps working until the new one is uploaded."}
        </p>
        {pending ? (
          <>
            <p>
              Request made <Time iso={req.requested_at} />.
            </p>
            <Err text={again.error || reset.error} />
            <div class="row">
              <button
                type="button"
                disabled={again.busy}
                onClick={async () => {
                  const r = await again.run(() => api.pushCsr());
                  if (r) download(r.filename, r.csr_pem);
                }}
              >
                Download again
              </button>
              <button
                type="button"
                disabled={reset.busy}
                onClick={async () => {
                  const ok = await reset.run(async () => {
                    await api.cancelPushRequest();
                    return true;
                  });
                  if (ok) {
                    setOut(null);
                    reloadReq();
                  }
                }}
              >
                Start again
              </button>
            </div>
          </>
        ) : (
          <>
            <Err text={gen.error} />
            <div class="row">
              <button
                type="button"
                class="primary"
                disabled={gen.busy}
                onClick={async () => {
                  const r = await gen.run(() => api.generatePushCsr());
                  if (r) {
                    download(r.filename, r.csr_pem);
                    toast(`${r.filename} downloaded.`);
                    reloadReq();
                  }
                }}
              >
                {gen.busy ? "Generating…" : "Generate CSR"}
              </button>
              {onCancel && (
                <button type="button" onClick={onCancel} disabled={gen.busy}>
                  Cancel
                </button>
              )}
            </div>
          </>
        )}
      </Step>

      <Step n={2} title="Get it signed by Apple" state={s2}>
        {!pending ? (
          <p class="muted">Once you have the request, you take it to Apple.</p>
        ) : (
          <>
            <p>
              Open{" "}
              <a href="https://identity.apple.com/pushcert" target="_blank" rel="noopener noreferrer">
                https://identity.apple.com/pushcert
              </a>{" "}
              in a new tab and sign in with an Apple ID. Upload the request, then download the <code>.pem</code> Apple gives you and bring it to step 3.
            </p>
            <p>
              <strong>Use the same Apple ID every year</strong> to renew. A different one cannot renew the certificate.
            </p>
            <details class="have-cert fallback">
              <summary>Apple rejected the CSR</summary>
              <div class="have-cert-body">
                <p>
                  Apple's portal is documented as accepting only requests countersigned by an MDM vendor. The free service mdmcert.download can countersign this same CSR.
                </p>
                {!sent ? (
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      const r = await send.run(() => api.requestPushCertificate(email.trim()));
                      if (r) reloadReq();
                    }}
                  >
                    <div class="field">
                      <label for="push-email">Email address (required)</label>
                      <input id="push-email" type="email" required autoComplete="email" value={email} aria-describedby="push-email-help" onInput={(e) => setEmail((e.target as HTMLInputElement).value)} />
                      <p id="push-email-help" class="hint">
                        Use a company address: the service refuses free-mail ones such as Gmail or Outlook. This address is sent to mdmcert.download, which emails you a file.
                      </p>
                    </div>
                    <Err text={send.error} />
                    <button type="submit" disabled={send.busy || !email.trim()}>
                      {send.busy ? "Sending…" : "Send for countersigning"}
                    </button>
                  </form>
                ) : (
                  <form
                    onSubmit={async (e) => {
                      e.preventDefault();
                      if (!encrypted.text.trim()) return;
                      const r = await dec.run(() => api.decryptPushRequest(encrypted.text));
                      if (r) {
                        setOut(r);
                        download(r.filename, r.content);
                      }
                    }}
                  >
                    <p>
                      Sent for countersigning for <strong>{req.email}</strong> <span class="muted">(<Time iso={req.requested_at} />)</span>. When the email arrives, choose its file here.
                    </p>
                    <TextOrFile id="push-enc" label="The file mdmcert.download emailed (.p7)" accept=".p7,.p7b,.txt,.b64" value={encrypted} onChange={setEncrypted} placeholder="Paste the text of the emailed file" />
                    <Err text={dec.error} />
                    <button type="submit" disabled={dec.busy || !encrypted.text.trim()}>
                      {dec.busy ? "Decrypting…" : "Decrypt"}
                    </button>
                    {out && (
                      <div class="note step-note">
                        <p>
                          <button type="button" onClick={() => download(out.filename, out.content)}>
                            Download {out.filename}
                          </button>
                        </p>
                        <p>Upload this file at Apple's portal instead of the plain CSR.</p>
                      </div>
                    )}
                  </form>
                )}
              </div>
            </details>
          </>
        )}
      </Step>

      <Step n={3} title="Upload the certificate" state={s3}>
        {!pending ? (
          <p class="muted">The certificate Apple gives you goes here.</p>
        ) : (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              if (!cert.text.includes("BEGIN CERTIFICATE")) return;
              const r = await up.run(() => api.setPushCertificate(cert.text));
              if (r) {
                setCert(empty);
                toast("Push certificate saved.");
                onSaved(r);
              }
            }}
          >
            <TextOrFile id="push-pem" label="The .pem Apple gave you" accept=".pem,.crt,.cer" value={cert} onChange={setCert} placeholder="-----BEGIN CERTIFICATE-----" />
            {cert.text && !cert.text.includes("BEGIN CERTIFICATE") && <p class="hint">That does not look like a certificate (it should contain BEGIN CERTIFICATE).</p>}
            <Err text={up.error} />
            <button type="submit" class="primary" disabled={up.busy || !cert.text.includes("BEGIN CERTIFICATE")}>
              {up.busy ? "Saving…" : "Save push certificate"}
            </button>
          </form>
        )}
      </Step>
    </ol>
  );
}

export function PushCertificate({ push, onChanged }: { push: PushInfo; onChanged: () => void }) {
  const l = useLoad(() => api.pushRequest(), []);
  const [renewing, setRenewing] = useState(false);
  const [saved, setSaved] = useState<PushInfo | null>(null);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (location.hash === "#push-certificate") root.current?.scrollIntoView({ block: "start" });
  }, []);

  const shown = saved ?? push;
  const days = push.configured ? daysUntil(push.not_after) : 0;
  const left = Math.ceil(days);
  const showFlow = !push.configured || renewing;

  const onSaved = (p: PushInfo) => {
    setSaved(p);
    setRenewing(false);
    l.reload();
    onChanged();
  };

  return (
    <div ref={root}>
      {saved && (
        <div class="valid" role="status">
          <strong>Push certificate saved.</strong>
          <Facts
            items={[
              ["Topic", <code class="wrap">{saved.topic}</code>],
              ["Expires", <Time iso={saved.not_after} />],
            ]}
          />
        </div>
      )}
      {push.configured && !saved && (
        <>
          {days < 0 ? (
            <div class="banner banner-error" role="alert">
              <strong>The push certificate has expired.</strong> Devices cannot be reached until a renewed one is saved.
            </div>
          ) : days <= 30 ? (
            <div class="banner banner-warn" role="alert">
              <strong>The push certificate expires in {Math.max(1, left)} {left === 1 ? "day" : "days"}.</strong> Renew it with the same Apple ID that made it.
            </div>
          ) : null}
          <Facts
            items={[
              ["Topic", <code class="wrap">{shown.topic}</code>],
              [
                "Expires",
                <>
                  {absDate(shown.not_after)} <span class="muted">({days < 0 ? "expired" : `${left} ${left === 1 ? "day" : "days"} left`})</span>
                </>,
              ],
            ]}
          />
        </>
      )}
      {push.configured && !renewing && (
        <p>
          <button type="button" class={days <= 30 ? "primary" : ""} onClick={() => setRenewing(true)}>
            Renew
          </button>{" "}
          <span class="hint">The current certificate keeps working until a new one is uploaded.</span>
        </p>
      )}
      {!push.configured && (
        <div class="banner banner-warn" role="alert">
          <strong>No push certificate yet.</strong> Devices cannot be woken, so enrolment will not work until you have one. Three steps get you one.
        </div>
      )}
      {showFlow && (
        <Async
          l={l}
          what="Checking for a pending request"
          render={(req) => <Flow req={req} reloadReq={l.reload} onSaved={onSaved} onCancel={renewing ? () => setRenewing(false) : undefined} renewing={renewing} />}
        />
      )}
      <details class="have-cert">
        <summary>I already have a certificate and its key</summary>
        <div class="have-cert-body">
          <KeyPairForm onSaved={onSaved} />
        </div>
      </details>
    </div>
  );
}
