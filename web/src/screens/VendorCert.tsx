import { useState } from "preact/hooks";
import { api } from "../api";
import type { VendorCertificate } from "../api";
import { useAction } from "../lib/hooks";
import { absDate, daysUntil, readFileAsBase64 } from "../lib/format";
import { ConfirmDialog, Facts, toast } from "../components/ui";
import { TextOrFile } from "./PushFlow";
import type { ComponentChildren } from "preact";

export const VENDOR_HELP_URL = "https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate";

/** A certificate file may be PEM text or a binary DER .cer; DER goes to the server as base64. */
async function readCertificateFile(f: File): Promise<string> {
  const bytes = new Uint8Array(await f.arrayBuffer());
  const head = new TextDecoder().decode(bytes.subarray(0, 10));
  if (head.startsWith("-----BEGIN")) return new TextDecoder().decode(bytes);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

const empty = { text: "", fileName: "" };

/** The upload form: a .p12 and its password, or a certificate file and a private key file. */
export function VendorForm({ onSaved, onCancel, replacing }: { onSaved: (warning: string) => void; onCancel?: () => void; replacing?: boolean }) {
  const [way, setWay] = useState<"p12" | "pem">("p12");
  const [p12, setP12] = useState({ b64: "", name: "" });
  const [password, setPassword] = useState("");
  const [cert, setCert] = useState(empty);
  const [key, setKey] = useState(empty);
  const [fileErr, setFileErr] = useState("");
  const a = useAction();
  const ready = way === "p12" ? !!p12.b64 : !!cert.text.trim() && /BEGIN [A-Z ]*PRIVATE KEY/.test(key.text);

  return (
    <form
      class="vendor-form"
      onSubmit={async (e) => {
        e.preventDefault();
        if (!ready) return;
        const r = await a.run(() => api.setVendorCertificate(way === "p12" ? { p12: p12.b64, password } : { certificate_pem: cert.text, key_pem: key.text }));
        // Neither the key nor the password stays in the page.
        setKey(empty);
        setPassword("");
        if (r) {
          setP12({ b64: "", name: "" });
          setCert(empty);
          toast(replacing ? "Vendor certificate replaced." : "Vendor certificate saved.");
          onSaved(r.warning ?? "");
        }
      }}
    >
      <fieldset class="field">
        <legend>What you exported</legend>
        <label class="check">
          <input type="radio" name="vendor-way" checked={way === "p12"} onChange={() => setWay("p12")} /> A .p12 file and its password
        </label>
        <label class="check">
          <input type="radio" name="vendor-way" checked={way === "pem"} onChange={() => setWay("pem")} /> A certificate file and a private key file
        </label>
      </fieldset>
      {way === "p12" ? (
        <>
          <div class="field">
            <label for="vendor-p12">The .p12 file (as exported from Keychain Access)</label>
            <input
              id="vendor-p12"
              type="file"
              accept=".p12,.pfx"
              onChange={async (e) => {
                const f = (e.target as HTMLInputElement).files?.[0];
                setFileErr("");
                if (!f) return setP12({ b64: "", name: "" });
                try {
                  setP12({ b64: await readFileAsBase64(f), name: f.name });
                } catch (x) {
                  setFileErr(x instanceof Error ? x.message : "The file could not be read.");
                }
              }}
            />
            {fileErr && <p class="form-error">{fileErr}</p>}
          </div>
          <div class="field">
            <label for="vendor-password">Password of the .p12 file</label>
            <input id="vendor-password" type="password" autoComplete="off" value={password} onInput={(e) => setPassword((e.target as HTMLInputElement).value)} />
            <p class="hint">Chosen when you exported it. It is used once to open the file and is not kept.</p>
          </div>
        </>
      ) : (
        <>
          <TextOrFile id="vendor-cert" label="Certificate (.cer or PEM)" accept=".cer,.crt,.pem" value={cert} onChange={setCert} placeholder="-----BEGIN CERTIFICATE-----" read={readCertificateFile} />
          <TextOrFile id="vendor-key" label="Private key (PEM, RSA, no passphrase)" accept=".pem,.key" value={key} onChange={setKey} hideContent placeholder="-----BEGIN PRIVATE KEY-----" />
        </>
      )}
      {a.error && (
        <p class="form-error" role="alert">
          {a.error}
        </p>
      )}
      <div class="row">
        <button type="submit" class="primary" disabled={!ready || a.busy}>
          {a.busy ? "Saving…" : replacing ? "Replace the vendor certificate" : "Save the vendor certificate"}
        </button>
        {onCancel && (
          <button type="button" onClick={onCancel} disabled={a.busy}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

export function vendorExpired(v: VendorCertificate): boolean {
  return !!v.configured && !!v.not_after && daysUntil(v.not_after) < 0;
}

/**
 * The vendor certificate as it stands, with replacing and removing it. `extra`
 * goes between the facts and those buttons (the Sign button, in the push flow).
 */
export function VendorManage({ vendor, reload, extra, addLabel }: { vendor: VendorCertificate; reload: () => void; extra?: ComponentChildren; addLabel?: string }) {
  const [replacing, setReplacing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [warning, setWarning] = useState("");
  const del = useAction();

  if (!vendor.configured) {
    return replacing || !addLabel ? (
      <>
        <VendorForm
          onSaved={(w) => {
            setWarning(w);
            setReplacing(false);
            reload();
          }}
          onCancel={addLabel ? () => setReplacing(false) : undefined}
        />
      </>
    ) : (
      <p>
        <button type="button" onClick={() => setReplacing(true)}>
          {addLabel}
        </button>
      </p>
    );
  }

  const expired = vendorExpired(vendor);
  const days = Math.ceil(daysUntil(vendor.not_after ?? ""));
  return (
    <>
      <Facts
        items={[
          ["Subject", <code class="wrap">{vendor.subject}</code>],
          [
            "Expires",
            <>
              {absDate(vendor.not_after)} <span class="muted">({expired ? "expired" : `${days} ${days === 1 ? "day" : "days"} left`})</span>
            </>,
          ],
          ["SHA-256 fingerprint", <code class="wrap">{vendor.sha256}</code>],
        ]}
      />
      {expired && (
        <div class="banner banner-error" role="alert">
          <strong>The vendor certificate has expired.</strong> Replace it with a new one from the developer portal before signing.
        </div>
      )}
      {warning && (
        <div class="banner banner-warn" role="status">
          <strong>Check this certificate.</strong> {warning}
        </div>
      )}
      {extra}
      {replacing ? (
        <VendorForm
          replacing
          onSaved={(w) => {
            setWarning(w);
            setReplacing(false);
            reload();
          }}
          onCancel={() => setReplacing(false)}
        />
      ) : (
        <div class="row">
          <button type="button" onClick={() => setReplacing(true)}>
            Replace
          </button>
          <button type="button" class="danger" onClick={() => setRemoving(true)}>
            Remove
          </button>
        </div>
      )}
      {removing && (
        <ConfirmDialog
          title="Remove the vendor certificate?"
          confirmLabel="Remove it"
          busy={del.busy}
          error={del.error}
          onClose={() => setRemoving(false)}
          onConfirm={async () => {
            const ok = await del.run(async () => {
              await api.deleteVendorCertificate();
              return true;
            });
            if (ok) {
              setRemoving(false);
              setWarning("");
              toast("Vendor certificate removed.");
              reload();
            }
          }}
        >
          <p>
            OpenMDM forgets the certificate and its private key. Requests already signed stay valid, but you cannot sign new ones until you add a certificate again.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
