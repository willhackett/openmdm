import { api } from "../api";
import { useLoad } from "../lib/hooks";
import { absTime } from "../lib/format";
import { Async, Empty, PageHeader, TableWrap, Time } from "../components/ui";

export function AuditScreen() {
  const l = useLoad(() => api.events(200), []);
  return (
    <>
      <PageHeader title="Audit log" sub="The newest 200 events, newest first.">
        <button type="button" onClick={l.reload}>
          Refresh
        </button>
      </PageHeader>
      <Async
        l={l}
        what="Loading events"
        render={(events) =>
          events.length === 0 ? (
            <Empty>Nothing has been logged yet.</Empty>
          ) : (
            <TableWrap label="Audit log">
              <table class="audit">
                <thead>
                  <tr>
                    <th scope="col">Time</th>
                    <th scope="col">Actor</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Subject</th>
                    <th scope="col">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td class="nowrap">
                        <Time iso={e.at} />
                        <div class="muted small">{absTime(e.at)}</div>
                      </td>
                      <td>{e.actor}</td>
                      <td>
                        <code>{e.kind}</code>
                      </td>
                      <td class="detail-cell">{e.subject}</td>
                      <td class="detail-cell">{e.detail || <span class="muted">none</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )
        }
      />
    </>
  );
}
