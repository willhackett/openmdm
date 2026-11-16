import { api } from "../api";
import { useLoad } from "../lib/hooks";
import { absTime } from "../lib/format";
import { Async, DataTable, Empty, PageHeader, Time } from "../components/ui";

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
            <DataTable
              label="Audit log"
              min={58}
              rows={events}
              rowKey={(e) => String(e.id)}
              cols={[
                {
                  head: "Time",
                  w: "9.5rem",
                  nowrap: true,
                  render: (e) => (
                    <>
                      <Time iso={e.at} />
                      <div class="cell-sub">{absTime(e.at)}</div>
                    </>
                  ),
                },
                { head: "Actor", w: "9rem", render: (e) => e.actor },
                { head: "Kind", w: "11rem", render: (e) => <code>{e.kind}</code> },
                { head: "Subject", w: "14rem", render: (e) => e.subject },
                { head: "Detail", render: (e) => (e.detail ? <span class="cell-detail">{e.detail}</span> : null) },
              ]}
            />
          )
        }
      />
    </>
  );
}
