import { useEffect, useState } from "preact/hooks";
import type { ComponentChildren, JSX } from "preact";

const listeners = new Set<() => void>();
const notify = () => listeners.forEach((f) => f());

window.addEventListener("popstate", notify);

export function navigate(to: string, replace = false) {
  if (to === location.pathname + location.search) return;
  if (replace) history.replaceState(null, "", to);
  else history.pushState(null, "", to);
  window.scrollTo(0, 0);
  notify();
}

export function usePath(): string {
  const [, force] = useState(0);
  useEffect(() => {
    const f = () => force((n) => n + 1);
    listeners.add(f);
    return () => {
      listeners.delete(f);
    };
  }, []);
  return location.pathname;
}

/** Matches "/devices/:id" against a path; returns the params or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const a = pattern.split("/").filter(Boolean);
  const b = path.split("/").filter(Boolean);
  if (a.length !== b.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < a.length; i++) {
    if (a[i].startsWith(":")) {
      try {
        params[a[i].slice(1)] = decodeURIComponent(b[i]);
      } catch {
        return null;
      }
    } else if (a[i] !== b[i]) return null;
  }
  return params;
}

interface LinkProps extends Omit<JSX.HTMLAttributes<HTMLAnchorElement>, "href"> {
  href: string;
  children?: ComponentChildren;
}

export function Link({ href, children, onClick, ...rest }: LinkProps) {
  return (
    <a
      {...rest}
      href={href}
      onClick={(e) => {
        onClick?.(e as never);
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        if (/^[a-z]+:/i.test(href) || (rest as { target?: string }).target === "_blank") return;
        e.preventDefault();
        navigate(href);
      }}
    >
      {children}
    </a>
  );
}
