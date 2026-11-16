import { api } from "../api";
import type { ProfileCounts, ProfileListItem } from "../api";
import { Link } from "../lib/router";
import { useLoad } from "../lib/hooks";
import { Assignees, Async, DataTable, Empty, PageHeader, PlatformTags, Primary } from "../components/ui";
import type { Col } from "../components/ui";

/** Pending, sent and being removed all mean "on its way". */
const inProgress = (c: ProfileCounts) => (c.pending ?? 0) + (c.sent ?? 0) + (c.removing ?? 0);

function Fig({ n, kind }: { n: number; kind?: "failed" | "blocked" }) {
  return <span class={n === 0 ? "fig fig-zero" : `fig${kind ? " fig-" + kind : ""}`}>{n}</span>;
}

const cols: Col<ProfileListItem>[] = [
  {
    head: "Name",
    primary: true,
    render: (p) => (
      <Primary
        sub={
          p.source === "file" || p.description ? (
            <>
              {p.source === "file" && <SourceMark source={p.source} />} {p.description}
            </>
          ) : undefined
        }
        title={p.name}
      >
        <Link href={`/profiles/${encodeURIComponent(p.id)}`}>{p.name}</Link>
      </Primary>
    ),
  },
  { head: "Platforms", w: "10rem", render: (p) => <PlatformTags platforms={p.platforms} /> },
  { head: "Mac channel", w: "6.5rem", nowrap: true, render: (p) => (p.platforms.includes("macos") ? (p.macos_channel === "user" ? "User" : "Device") : null) },
  { head: "Assigned to", w: "11rem", render: (p) => <Assignees a={p.assignment} /> },
  { head: "Failed", w: "4.5rem", num: true, render: (p) => <Fig n={p.counts.failed ?? 0} kind="failed" />, hideCard: (p) => !(p.counts.failed ?? 0) },
  { head: "Blocked", w: "5rem", num: true, render: (p) => <Fig n={p.counts.blocked ?? 0} kind="blocked" />, hideCard: (p) => !(p.counts.blocked ?? 0) },
  { head: "In progress", w: "6.5rem", num: true, render: (p) => <Fig n={inProgress(p.counts)} />, hideCard: (p) => !inProgress(p.counts) },
  { head: "Installed", w: "5.75rem", num: true, render: (p) => <Fig n={p.counts.installed ?? 0} />, hideCard: (p) => !(p.counts.installed ?? 0) },
];

export function SourceMark({ source }: { source: string }) {
  return source === "file" ? <span class="tag" title="Loaded from the profiles directory. Change the file to change the profile.">From file</span> : null;
}

export function ProfilesScreen() {
  const l = useLoad(() => api.profiles(), []);
  return (
    <>
      <PageHeader title="Profiles">
        <Link class="button primary" href="/profiles/new">
          New profile
        </Link>
        <button type="button" onClick={l.reload}>
          Refresh
        </button>
      </PageHeader>
      <Async
        l={l}
        what="Loading profiles"
        render={(list) =>
          list.length === 0 ? (
            <Empty>
              <p>
                <strong>No profiles yet.</strong>
              </p>
              <p>
                <Link href="/profiles/new">Create one</Link>, or put files in the profiles directory.
              </p>
            </Empty>
          ) : (
            <DataTable label="Profiles" cols={cols} rows={list} rowKey={(p) => p.id} min={57} />
          )
        }
      />
    </>
  );
}
