const K = {
  setup: "bifrost.setupComplete",
  legal: "bifrost.legalAccepted",
  pw: "bifrost.passwordHash",
};

export const isSetupComplete = () => localStorage.getItem(K.setup) === "1";
export const setSetupComplete = (v = true) => localStorage.setItem(K.setup, v ? "1" : "0");

export const isLegalAccepted = () => localStorage.getItem(K.legal) === "1";
export const setLegalAccepted = (v = true) => localStorage.setItem(K.legal, v ? "1" : "0");

export const hasPassword = () => !!localStorage.getItem(K.pw);

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export async function setPassword(pw: string): Promise<void> {
  localStorage.setItem(K.pw, await sha256(pw));
}

export async function verifyPassword(pw: string): Promise<boolean> {
  if (!hasPassword()) return pw === "heimdall";
  return (await sha256(pw)) === localStorage.getItem(K.pw);
}

export function passwordStrength(pw: string): { score: number; label: string } {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  score = Math.min(4, score);
  const label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score];
  return { score, label };
}
