import { useCallback, useEffect, useRef, useState } from "preact/hooks";

export interface Loaded<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

/** Loads on mount and whenever deps change; ignores answers that arrive late. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [state, setState] = useState<{ data: T | null; error: Error | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback((keep: boolean) => {
    const id = ++seq.current;
    setState((s) => ({ data: keep ? s.data : null, error: null, loading: true }));
    fnRef.current().then(
      (data) => {
        if (id === seq.current) setState({ data, error: null, loading: false });
      },
      (error) => {
        if (id === seq.current) setState({ data: null, error: error instanceof Error ? error : new Error(String(error)), loading: false });
      },
    );
  }, []);

  useEffect(() => {
    run(false);
    return () => {
      seq.current++;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { ...state, reload: () => run(true) };
}

/** Wraps a button action: tracks busy and the last error. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError("");
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}

/** Runs fn over items, a few at a time, calling each as it settles. */
export async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>, cancelled: () => boolean) {
  let i = 0;
  const worker = async () => {
    while (i < items.length && !cancelled()) {
      const item = items[i++];
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
}
