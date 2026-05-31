/**
 * HTTP client for guardian dashboard requests.
 * Uses Tauri's native HTTP plugin in the desktop shell so disclaimer cookies
 * persist across requests (WebView fetch blocks cross-origin cookies).
 */

let tauriFetch: typeof fetch | null = null;

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function getFetch(): Promise<typeof fetch> {
  if (isTauriRuntime()) {
    if (!tauriFetch) {
      const mod = await import("@tauri-apps/plugin-http");
      tauriFetch = mod.fetch as typeof fetch;
    }
    return tauriFetch;
  }
  return fetch;
}

export async function guardianFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const fn = await getFetch();
  return fn(url, init);
}
