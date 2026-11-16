import { useEffect, useRef, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import type { Loaded } from "../lib/hooks";
import { ApiError } from "../api";
import { absTime, platformLabel, platformOrder, relTime, stateLabel, stateOrder } from "../lib/format";
import type { Assignment, CommandStatus, DeviceStatus, Platform, ProfileState } from "../api";

export function Time({ iso }: { iso: string | null | undefined }) {
  if (!iso || iso.startsWith("0001-")) return <span class="muted">never</span>;
  return (
    <time dateTime={iso} title={absTime(iso)}>
      {relTime(iso)}
    </time>
  );
}

export function StateBadge({ state }: { state: ProfileState | "" }) {
  if (!state) return <span class="badge badge-none">Not on device</span>;
  return <span class={`badge badge-${state}`}>{stateLabel[state] ?? state}</span>;
}

export function StatusBadge({ status }: { status: DeviceStatus | string }) {
  const label = status === "enrolled" ? "Enrolled" : status === "pending" ? "Pending" : status === "unenrolled" ? "Unenrolled" : status;
  const cls = status === "enrolled" ? "installed" : status === "pending" ? "pending" : "removing";
  return <span class={`badge badge-${cls}`}>{label}</span>;
}

export function CommandBadge({ status }: { status: CommandStatus | string }) {
  const map: Record<string, [string, string]> = {
    queued: ["Queued", "sent"],
    acknowledged: ["Acknowledged", "installed"],
    error: ["Error", "failed"],
    notnow: ["Not now", "pending"],
  };
  const [label, cls] = map[status] ?? [status, "none"];
  return <span class={`badge badge-${cls}`}>{label}</span>;
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return (
    <p class="loading" role="status">
      <span class="spinner" aria-hidden="true" /> {what}…
    </p>
  );
}

export function ErrorBox({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <div class="error-box" role="alert">
      <p>
        <strong>{forbidden ? "Not allowed." : "Something went wrong."}</strong> {error.message}
      </p>
      {onRetry && (
        <button type="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ComponentChildren }) {
  return <div class="empty">{children}</div>;
}

/** Shows loading and error states, and calls render once there is data. */
export function Async<T>({ l, what, render }: { l: Loaded<T>; what?: string; render: (data: T) => ComponentChildren }) {
  if (l.error) return <ErrorBox error={l.error} onRetry={l.reload} />;
  if (l.data === null) return <Loading what={what} />;
  return <>{render(l.data)}</>;
}

export function PageHeader({ title, children, sub }: { title: string; sub?: ComponentChildren; children?: ComponentChildren }) {
  return (
    <header class="page-header">
      <div>
        <h1>{title}</h1>
        {sub && <p class="sub">{sub}</p>}
      </div>
      {children && <div class="actions">{children}</div>}
    </header>
  );
}

export function Section({ title, children, actions, id }: { title: string; children: ComponentChildren; actions?: ComponentChildren; id?: string }) {
  return (
    <section class="section" aria-labelledby={id ? id : undefined}>
      <div class="section-head">
        <h2 id={id}>{title}</h2>
        {actions && <div class="actions">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function Facts({ items }: { items: [string, ComponentChildren][] }) {
  return (
    <dl class="facts">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A table that scrolls inside itself on a narrow screen. */
export function TableWrap({ children, label }: { children: ComponentChildren; label: string }) {
  return (
    <div class="table-wrap" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}

export interface Col<T> {
  /** Header text. */
  head: string;
  /** Hide the header text visually (for a column of buttons). */
  srHead?: boolean;
  /** A CSS width such as "7rem". Leave out for the one column that takes the rest. */
  w?: string;
  /** Numerals: right-aligned, tabular. */
  num?: boolean;
  /** The row's main cell: it is the title of the card on a phone. */
  primary?: boolean;
  nowrap?: boolean;
  /** Right-align (buttons). */
  end?: boolean;
  /** Leave this cell out of the card layout on a phone for this row. */
  hideCard?: (row: T) => boolean;
  render: (row: T) => ComponentChildren;
}

/**
 * The one table of the app. Columns have deliberate widths (fixed layout), the table has a
 * minimum width and scrolls inside its own container when the screen is narrower, and on a
 * phone every row becomes a card whose cells carry their column names.
 */
export function DataTable<T>({
  label,
  cols,
  rows,
  rowKey,
  min = 44,
  rowClass,
}: {
  label: string;
  cols: Col<T>[];
  rows: T[];
  rowKey: (r: T) => string;
  /** Minimum table width in rem. */
  min?: number;
  rowClass?: (r: T) => string;
}) {
  return (
    <TableWrap label={label}>
      <table class="dt" style={{ minWidth: `${min}rem` }}>
        <colgroup>
          {cols.map((c, i) => (
            <col key={i} style={c.w ? { width: c.w } : undefined} />
          ))}
        </colgroup>
        <thead>
          <tr>
            {cols.map((c, i) => (
              <th key={i} scope="col" class={`${c.num ? "num" : ""}${c.end ? " end" : ""}`}>
                {c.srHead ? <span class="sr-only">{c.head}</span> : c.head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)} class={rowClass?.(r)}>
              {cols.map((c, i) => {
                const v = c.render(r);
                const empty = v === null || v === undefined || v === false;
                const cls = `${c.num ? "num " : ""}${c.end ? "end " : ""}${c.nowrap ? "nowrap " : ""}${c.primary ? "primary " : ""}${empty || c.hideCard?.(r) ? "no-card" : ""}`;
                const content = empty ? <span class="dash" aria-label="none">&ndash;</span> : v;
                return c.primary ? (
                  <th key={i} scope="row" class={cls}>
                    {content}
                  </th>
                ) : (
                  <td key={i} class={cls} data-label={c.srHead ? undefined : c.head}>
                    {content}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}

/** A name with a quieter line beneath it, for the first column. */
export function Primary({ children, sub, title }: { children: ComponentChildren; sub?: ComponentChildren; title?: string }) {
  return (
    <div class="cell-primary">
      <div class="cell-name" title={title}>
        {children}
      </div>
      {sub ? <div class="cell-sub">{sub}</div> : null}
    </div>
  );
}

/** Platforms as small labels, always Mac, iPhone, iPad in that order. */
export function PlatformTags({ platforms }: { platforms: Platform[] }) {
  const list = platformOrder.filter((p) => platforms.includes(p));
  return (
    <span class="chips">
      {list.map((p) => (
        <span key={p} class="tag">
          {platformLabel[p]}
        </span>
      ))}
    </span>
  );
}

/** Who a profile is for, on at most two short lines; the title holds all of it. */
export function Assignees({ a }: { a: Assignment }) {
  const users = a.users ?? [];
  const groups = a.groups ?? [];
  const full = [a.everyone ? "Everyone" : "", users.length ? "People: " + users.join(", ") : "", groups.length ? "Groups: " + groups.join(", ") : ""].filter(Boolean).join("; ");
  if (!a.everyone && users.length === 0 && groups.length === 0) return <span class="muted">Nobody</span>;
  const short = (l: string[]) => (l.length <= 2 ? l.join(", ") : `${l.slice(0, 2).join(", ")} +${l.length - 2}`);
  return (
    <span class="assignees" title={full}>
      {a.everyone && <span class="tag tag-strong">Everyone</span>}
      {users.length > 0 && <span class="clip">{short(users)}</span>}
      {groups.length > 0 && (
        <span class="clip">
          <span class="muted">Group{groups.length > 1 ? "s" : ""}</span> {short(groups)}
        </span>
      )}
    </span>
  );
}

/** Non-zero state counts as labelled chips that never break in the middle; most urgent first. */
export function StateChips({ counts, none = "None" }: { counts: Partial<Record<ProfileState, number>>; none?: string }) {
  const shown = stateOrder.filter((s) => (counts[s] ?? 0) > 0);
  if (shown.length === 0) return <span class="muted">{none}</span>;
  return (
    <span class="chips">
      {shown.map((s) => (
        <span key={s} class={`chip chip-${s}`}>
          <strong>{counts[s]}</strong> {stateLabel[s].toLowerCase()}
        </span>
      ))}
    </span>
  );
}

// ---- dialogs

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ComponentChildren }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) d.showModal();
    return () => {
      if (d?.open) d.close();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      class="modal"
      aria-labelledby="modal-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      <div class="modal-body">
        <h2 id="modal-title">{title}</h2>
        {children}
      </div>
    </dialog>
  );
}

export function ConfirmDialog({
  title,
  confirmLabel,
  onConfirm,
  onClose,
  busy,
  error,
  children,
  disabled,
}: {
  title: string;
  confirmLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  busy?: boolean;
  error?: string;
  disabled?: boolean;
  children?: ComponentChildren;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <form
        method="dialog"
        onSubmit={(e) => {
          e.preventDefault();
          if (!busy && !disabled) onConfirm();
        }}
      >
        {children}
        {error && (
          <p class="form-error" role="alert">
            {error}
          </p>
        )}
        <div class="modal-actions">
          <button type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="submit" class="danger" disabled={busy || disabled}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ---- toasts

type Toast = { id: number; text: string; kind: "ok" | "error" };
let toasts: Toast[] = [];
let toastId = 0;
const toastListeners = new Set<() => void>();

export function toast(text: string, kind: "ok" | "error" = "ok") {
  const t = { id: ++toastId, text, kind };
  toasts = [...toasts, t];
  toastListeners.forEach((f) => f());
  setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id);
    toastListeners.forEach((f) => f());
  }, 6000);
}

export function Toasts() {
  const [, force] = useState(0);
  useEffect(() => {
    const f = () => force((n) => n + 1);
    toastListeners.add(f);
    return () => {
      toastListeners.delete(f);
    };
  }, []);
  return (
    <div class="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} class={`toast toast-${t.kind}`}>
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 2000);
        } catch {
          toast("Copying failed. Select the link and copy it by hand.", "error");
        }
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}
