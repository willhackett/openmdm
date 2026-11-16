import { useState } from "preact/hooks";
import { api } from "../api";
import type { Enrollment } from "../api";
import { Link } from "../lib/router";
import { useAction, useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { Async, CopyButton, Empty, PageHeader, Section, TableWrap, Time } from "../components/ui";
import { Qr } from "../components/Qr";

const NAME_RE = /^[a-z0-9._-]+$/;

export function enrollmentState(e: Enrollment, now = Date.now()): { label: string; cls: string } {
  if (e.used_at) return { label: "Used", cls: "installed" };
  if (e.downloaded_at) return { label: "Downloaded", cls: "sent" };
  if (new Date(e.expires_at).getTime() < now) return { label: "Expired", cls: "removing" };
  return { label: "Waiting", cls: "pending" };
}

function Result({ url, enrollment, username }: { url: string; enrollment: Enrollment; username: string }) {
  return (
    <section class="result" aria-labelledby="h-result">
      <h2 id="h-result">Enrolment link for {username}</h2>
      <div class="result-grid">
        <div>
          <p class="link-box">
            <a href={url} class="wrap">
              {url}
            </a>
          </p>
          <p class="row">
            <CopyButton text={url} label="Copy link" />
          </p>
          <p>
            It works once and expires <Time iso={enrollment.expires_at} />.
          </p>
        </div>
        <figure class="qr-figure">
          <Qr text={url} label={`QR code for the enrolment link for ${username}`} />
          <figcaption class="hint">Point a phone's camera at this code.</figcaption>
        </figure>
      </div>
      <div class="instructions">
        <h3>On an iPhone or iPad</h3>
        <ol>
          <li>Open the link in Safari, or scan the QR code with the camera.</li>
          <li>Tap Allow when asked to download a configuration profile.</li>
          <li>Open Settings. Tap "Profile Downloaded" near the top, then Install, and enter the passcode if asked.</li>
          <li>Tap Install again and confirm. The device enrols in a minute or so.</li>
        </ol>
        <h3>On a Mac</h3>
        <ol>
          <li>Open the link in Safari on the Mac. The profile downloads.</li>
          <li>Open System Settings. Choose General, then Device Management (on older macOS: Privacy &amp; Security, then Profiles).</li>
          <li>Double-click the downloaded profile, choose Install, and enter the Mac's password.</li>
          <li>Log in to the Mac as the person it is for, so that user profiles such as mail can install.</li>
        </ol>
      </div>
    </section>
  );
}

function EnrolmentList() {
  const l = useLoad(() => api.enrollments(), []);
  return (
    <Section
      title="Enrolments"
      id="h-enrolments"
      actions={
        <button type="button" onClick={l.reload}>
          Refresh
        </button>
      }
    >
      <Async
        l={l}
        what="Loading enrolments"
        render={(list) =>
          list.length === 0 ? (
            <Empty>No enrolments have been made.</Empty>
          ) : (
            <TableWrap label="Enrolments">
              <table>
                <thead>
                  <tr>
                    <th scope="col">For</th>
                    <th scope="col">State</th>
                    <th scope="col">Made by</th>
                    <th scope="col">Made</th>
                    <th scope="col">Expires</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((e) => {
                    const s = enrollmentState(e);
                    return (
                      <tr key={e.token}>
                        <th scope="row">
                          <Link href={`/people/${encodeURIComponent(e.username)}`}>{e.username}</Link>
                        </th>
                        <td>
                          <span class={`badge badge-${s.cls}`}>{s.label}</span>
                        </td>
                        <td>{e.created_by}</td>
                        <td>
                          <Time iso={e.created_at} />
                        </td>
                        <td>
                          <Time iso={e.expires_at} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </TableWrap>
          )
        }
      />
    </Section>
  );
}

export function EnrolScreen() {
  const { me, isAdmin } = useMe();
  const users = useLoad(async () => (isAdmin ? await api.users() : []), [isAdmin]);
  const [who, setWho] = useState(isAdmin ? me.user.username : "");
  const [result, setResult] = useState<{ url: string; enrollment: Enrollment } | null>(null);
  const a = useAction();
  const target = isAdmin ? who.trim() : me.user.username;
  const nameOk = NAME_RE.test(target);
  const known = (users.data ?? []).some((u) => u.username === target);

  return (
    <>
      <PageHeader title="Enrol a device" sub="Make a one-time link that sets up an iPhone, iPad or Mac for one person." />
      {!me.push.configured && (
        <div class="banner banner-warn" role="alert">
          <strong>Enrolment will not work yet.</strong> The push certificate has not been set up, so devices cannot be reached after they enrol.{" "}
          {isAdmin ? <Link href="/settings">Go to Settings</Link> : "Ask an administrator to set it up."}
        </div>
      )}
      <form
        class="enrol-form"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!nameOk) return;
          setResult(null);
          const r = await a.run(() => api.createEnrollment(isAdmin ? target : undefined));
          if (r) setResult({ url: r.url, enrollment: r.enrollment });
        }}
      >
        {isAdmin ? (
          <div class="field">
            <label for="enrol-who">Who is the device for?</label>
            <input
              id="enrol-who"
              type="text"
              list="enrol-people"
              value={who}
              autoComplete="off"
              autoCapitalize="off"
              spellcheck={false}
              aria-invalid={who !== "" && !nameOk}
              aria-describedby="enrol-who-help"
              onInput={(e) => setWho((e.target as HTMLInputElement).value)}
            />
            <datalist id="enrol-people">
              {(users.data ?? []).map((u) => (
                <option key={u.username} value={u.username}>
                  {u.name}
                </option>
              ))}
            </datalist>
            <p id="enrol-who-help" class={who !== "" && !nameOk ? "form-error" : "hint"}>
              {who !== "" && !nameOk
                ? "Use lower-case letters, digits, dots, hyphens and underscores."
                : target && !known && users.data
                  ? `${target} is not known yet. They will be added when the enrolment is made.`
                  : "Choose a person, or type a new username."}
            </p>
          </div>
        ) : (
          <p>
            This enrolment is for you (<strong>{me.user.username}</strong>).
          </p>
        )}
        <button type="submit" class="primary" disabled={a.busy || !nameOk}>
          {a.busy ? "Creating…" : "Create enrolment link"}
        </button>
        {a.error && (
          <p class="form-error" role="alert">
            {a.error}
          </p>
        )}
      </form>
      {result && <Result url={result.url} enrollment={result.enrollment} username={target} />}
      {isAdmin && <EnrolmentList key={result?.enrollment.token ?? "none"} />}
    </>
  );
}
