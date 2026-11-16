import { realApi } from "./client";
import type { Api } from "./types";
import type { MockControls } from "./mock";

export * from "./types";
export { ApiError } from "./client";

/** The client every screen uses. It is the mock once initApi() has chosen it. */
export let api: Api = realApi;
export let mockControls: MockControls | null = null;

export async function initApi(): Promise<void> {
  let useMock: boolean = import.meta.env.DEV;
  try {
    const q = new URLSearchParams(location.search).get("mock");
    if (q === "1") {
      useMock = true;
      sessionStorage.setItem("openmdm-mock", "1");
    } else if (q === "0") {
      useMock = false;
      sessionStorage.removeItem("openmdm-mock");
    } else if (sessionStorage.getItem("openmdm-mock") === "1") {
      useMock = true;
    }
  } catch {
    // Storage can be blocked; the query string alone decides then.
    useMock = useMock || new URLSearchParams(location.search).get("mock") === "1";
  }
  if (useMock) {
    const m = await import("./mock");
    api = m.mockApi;
    mockControls = m.mockControls;
  }
}
