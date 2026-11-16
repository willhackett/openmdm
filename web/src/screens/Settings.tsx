import { api } from "../api";
import type { Settings } from "../api";
import { useLoad } from "../lib/hooks";
import { useMe } from "../lib/me";
import { absTime, isZero } from "../lib/format";
import { Async, Facts, PageHeader, Section, Time } from "../components/ui";
import { PushCertificate } from "./PushFlow";

function View({ s, reload }: { s: Settings; reload: () => void }) {
  const me = useMe();
  return (
    <>
      <Section title="Push certificate (APNs)" id="push-certificate">
        <PushCertificate
          push={s.push}
          onChanged={() => {
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
