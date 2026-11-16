import { useState } from "preact/hooks";
import { useMe } from "../lib/me";
import { PageHeader } from "../components/ui";
import { SecretsPanel } from "../components/SecretsPanel";

export function SecretsScreen() {
  const { me, isAdmin } = useMe();
  const [tab, setTab] = useState<"mine" | "global">("mine");
  return (
    <>
      <PageHeader title={isAdmin ? "Secrets" : "My secrets"} sub={isAdmin ? undefined : "Values some of your profiles need, such as a mail password."} />
      {isAdmin && (
        <div class="tabs" role="tablist" aria-label="Whose secrets">
          <button type="button" role="tab" id="tab-mine" aria-selected={tab === "mine"} aria-controls="panel-secrets" onClick={() => setTab("mine")}>
            Mine ({me.user.username})
          </button>
          <button type="button" role="tab" id="tab-global" aria-selected={tab === "global"} aria-controls="panel-secrets" onClick={() => setTab("global")}>
            Global
          </button>
        </div>
      )}
      <div id="panel-secrets" role={isAdmin ? "tabpanel" : undefined} aria-labelledby={isAdmin ? (tab === "mine" ? "tab-mine" : "tab-global") : undefined}>
        {tab === "mine" ? (
          <SecretsPanel key={"u-" + me.user.username} scope={{ kind: "user", username: me.user.username }} canAdd={isAdmin} linkProfiles={isAdmin} />
        ) : (
          <>
            <p class="hint">Global secrets are shared by every person's profiles, for example a Wi-Fi password.</p>
            <SecretsPanel key="global" scope={{ kind: "global" }} canAdd={true} linkProfiles={true} />
          </>
        )}
      </div>
    </>
  );
}
