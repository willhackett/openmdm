import { api } from "../api";
import type { ProfileCounts } from "../api";
import { Link } from "../lib/router";
import { useLoad } from "../lib/hooks";
import { describeAssignment, platformName, stateOrder } from "../lib/format";
import { Async, Empty, PageHeader, StateBadge, TableWrap } from "../components/ui";

export function CountBadges({ counts }: { counts: ProfileCounts }) {
  const shown = stateOrder.filter((s) => (counts[s] ?? 0) > 0);
  if (shown.length === 0) return <span class="muted">On no device</span>;
  return (
    <span class="count-badges">
      {shown.map((s) => (
        <span key={s} class="count">
          <strong>{counts[s]}</strong> <StateBadge state={s} />
        </span>
      ))}
    </span>
  );
}

export function SourceMark({ source }: { source: string }) {
  return source === "file" ? <span class="tag" title="Loaded from the profiles directory. Change the file to change the profile.">From file, read-only</span> : null;
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
            <>
              <div class="only-wide">
                <TableWrap label="Profiles">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Platforms</th>
                        <th scope="col">Mac channel</th>
                        <th scope="col">Assigned to</th>
                        <th scope="col">On devices</th>
                      </tr>
                    </thead>
                    <tbody>
                      {list.map((p) => (
                        <tr key={p.id}>
                          <th scope="row">
                            <Link href={`/profiles/${encodeURIComponent(p.id)}`}>{p.name}</Link> <SourceMark source={p.source} />
                            {p.description && <div class="muted small">{p.description}</div>}
                          </th>
                          <td>{p.platforms.map(platformName).join(", ")}</td>
                          <td>{p.platforms.includes("macos") ? (p.macos_channel === "user" ? "User" : "Device") : <span class="muted">Not for Mac</span>}</td>
                          <td>{describeAssignment(p.assignment)}</td>
                          <td>
                            <CountBadges counts={p.counts} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              </div>
              <ul class="cards only-narrow">
                {list.map((p) => (
                  <li key={p.id} class="card">
                    <div class="card-title">
                      <Link href={`/profiles/${encodeURIComponent(p.id)}`}>{p.name}</Link>
                      <SourceMark source={p.source} />
                    </div>
                    {p.description && <p class="muted">{p.description}</p>}
                    <p>
                      {p.platforms.map(platformName).join(", ")}
                      {p.platforms.includes("macos") && ` · Mac channel: ${p.macos_channel === "user" ? "user" : "device"}`}
                    </p>
                    <p>Assigned to: {describeAssignment(p.assignment)}</p>
                    <p>
                      <CountBadges counts={p.counts} />
                    </p>
                  </li>
                ))}
              </ul>
            </>
          )
        }
      />
    </>
  );
}
