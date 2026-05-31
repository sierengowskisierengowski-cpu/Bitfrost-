/* Bridge to the Tauri runtime. In the browser preview these all no-op safely.
   In the packaged desktop app, `withGlobalTauri` exposes window.__TAURI__. */

type AnyTauri = any;

function tauri(): AnyTauri | null {
  if (typeof window === "undefined") return null;
  return (window as AnyTauri).__TAURI__ ?? null;
}

export const isTauri = (): boolean => !!tauri();

export async function minimizeWindow(): Promise<void> {
  const t = tauri();
  if (t) await t.window.getCurrentWindow().minimize();
}

export async function toggleMaximize(): Promise<void> {
  const t = tauri();
  if (!t) return;
  const w = t.window.getCurrentWindow();
  (await w.isMaximized()) ? await w.unmaximize() : await w.maximize();
}

export async function closeWindow(): Promise<void> {
  const t = tauri();
  if (t) await t.window.getCurrentWindow().close();
}

async function invokeGuardian<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T | null> {
  const t = tauri();
  if (!t) return null;
  try {
    return (await t.core.invoke(cmd, args)) as T;
  } catch {
    return null;
  }
}

export const startGuardian = () => invokeGuardian<boolean>("start_guardian");
export const stopGuardian = () => invokeGuardian<boolean>("stop_guardian");
export const guardianStatus = () => invokeGuardian<boolean>("guardian_status");
export const getGuardianPort = () => invokeGuardian<number>("get_guardian_port");

export async function openExternal(url: string): Promise<void> {
  const t = tauri();
  if (t?.shell?.open) {
    await t.shell.open(url);
  } else if (typeof window !== "undefined") {
    window.open(url, "_blank", "noopener,noreferrer");
  }
}
