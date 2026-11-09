import { HttpError } from "./http";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new HttpError(500, "server_misconfigured", `${name} is not configured`);
  }
  return value;
}

/** Public origin of the deployment; also the connect-token issuer. No trailing slash. */
export function issuer(): string {
  const explicit = process.env.CONTROL_PLANE_URL;
  if (explicit) {
    return explicit.replace(/\/+$/, "");
  }
  const production = process.env.VERCEL_PROJECT_PRODUCTION_URL;
  if (production) {
    return `https://${production}`;
  }
  if (process.env.NODE_ENV !== "production") {
    return "http://localhost:3000";
  }
  throw new HttpError(500, "server_misconfigured", "CONTROL_PLANE_URL is not configured");
}

export function url(path: string): string {
  return `${issuer()}${path}`;
}

export function sessionSecret(): Uint8Array {
  const secret = required("SESSION_SECRET");
  if (secret.length < 32) {
    throw new HttpError(500, "server_misconfigured", "SESSION_SECRET must be at least 32 characters");
  }
  return new TextEncoder().encode(secret);
}

export function vercelOAuth(): { clientId: string; clientSecret: string } {
  return { clientId: required("VERCEL_CLIENT_ID"), clientSecret: required("VERCEL_CLIENT_SECRET") };
}

/** Private Ed25519 JWK (`{"kty":"OKP","crv":"Ed25519","x":…,"d":…}`) used to sign connect tokens. */
export function signingKeyJwk(): string {
  return required("CONNECT_TOKEN_SIGNING_KEY");
}

/** Optional JSON array of retired public JWKs that stay published during rotation. */
export function retiredVerifyKeys(): string | undefined {
  return process.env.CONNECT_TOKEN_RETIRED_KEYS || undefined;
}

/**
 * Optional comma-separated allow-list of Vercel identities (user ID, username, or email).
 * When unset, any Vercel user may sign in and manage only their own devices.
 */
export function allowedUsers(): string[] | undefined {
  const raw = process.env.ALLOWED_USERS;
  if (!raw) {
    return undefined;
  }
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export function secureCookies(): boolean {
  return issuer().startsWith("https://");
}
