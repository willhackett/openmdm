import { createContext } from "preact";
import { useContext } from "preact/hooks";
import type { Me } from "../api";

export interface MeCtx {
  me: Me;
  isAdmin: boolean;
  /** Re-reads /me (for example after the push certificate changes). */
  refresh: () => void;
}

export const MeContext = createContext<MeCtx | null>(null);

export function useMe(): MeCtx {
  const c = useContext(MeContext);
  if (!c) throw new Error("useMe outside the app shell");
  return c;
}
