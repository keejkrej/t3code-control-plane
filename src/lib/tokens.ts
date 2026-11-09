import { calculateJwkThumbprint, importJWK, SignJWT, type JWK } from "jose";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import * as config from "./config";
import { newId } from "./crypto";
import { HttpError } from "./http";
import { CONNECT_TOKEN_TTL_SECONDS, PROTOCOL_VERSION, SCOPE_READ, SCOPE_WRITE, type Scope } from "./protocol";

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  alg: "EdDSA";
  use: "sig";
}

export interface SigningKey {
  kid: string;
  privateJwk: JWK;
  publicJwk: PublicJwk;
}

export async function loadSigningKey(privateJwkJson: string): Promise<SigningKey> {
  let jwk: JWK;
  try {
    jwk = JSON.parse(privateJwkJson) as JWK;
  } catch {
    throw new HttpError(500, "server_misconfigured", "CONNECT_TOKEN_SIGNING_KEY is not valid JSON");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x || !jwk.d) {
    throw new HttpError(500, "server_misconfigured", "CONNECT_TOKEN_SIGNING_KEY must be a private Ed25519 OKP JWK");
  }
  const kid = await thumbprint(jwk.x);
  return {
    kid,
    privateJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d },
    publicJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid, alg: "EdDSA", use: "sig" },
  };
}

export function thumbprint(x: string): Promise<string> {
  return calculateJwkThumbprint({ kty: "OKP", crv: "Ed25519", x }, "sha256");
}

let cached: { source: string; key: Promise<SigningKey> } | undefined;

export function currentSigningKey(): Promise<SigningKey> {
  const source = config.signingKeyJwk();
  if (!cached || cached.source !== source) {
    cached = { source, key: loadSigningKey(source) };
  }
  return cached.key;
}

export async function publishedJwks(): Promise<{ keys: PublicJwk[] }> {
  const current = await currentSigningKey();
  const keys: PublicJwk[] = [current.publicJwk];
  const retired = config.retiredVerifyKeys();
  if (retired) {
    const parsed = JSON.parse(retired) as Array<{ x: string }>;
    for (const k of parsed) {
      const kid = await thumbprint(k.x);
      if (kid !== current.kid) {
        keys.push({ kty: "OKP", crv: "Ed25519", x: k.x, kid, alg: "EdDSA", use: "sig" });
      }
    }
  }
  return { keys };
}

export interface ConnectTokenInput {
  issuer: string;
  userId: string;
  deviceId: string;
  scopes: Scope[];
  revocationEpoch: number;
  now?: Date;
  jti?: string;
  ttlSeconds?: number;
}

export interface IssuedConnectToken {
  token: string;
  jti: string;
  scope: string;
  issuedAt: Date;
  expiresAt: Date;
}

export async function signConnectToken(key: SigningKey, input: ConnectTokenInput): Promise<IssuedConnectToken> {
  const iat = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const exp = iat + (input.ttlSeconds ?? CONNECT_TOKEN_TTL_SECONDS);
  const jti = input.jti ?? newId("ctk");
  const scope = input.scopes.join(" ");
  const privateKey = await importJWK(key.privateJwk, "EdDSA");
  const token = await new SignJWT({ scope, t3cp_epoch: input.revocationEpoch, t3cp_ver: PROTOCOL_VERSION })
    .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: key.kid })
    .setIssuer(input.issuer)
    .setSubject(input.userId)
    .setAudience(input.deviceId)
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(privateKey);
  return { token, jti, scope, issuedAt: new Date(iat * 1000), expiresAt: new Date(exp * 1000) };
}

// ---------------------------------------------------------------------------
// Reference device-side verifier. This mirrors PROTOCOL.md step by step and is deliberately written
// without a JWT library so the Go and Rust ports can follow it line for line.
// ---------------------------------------------------------------------------

export type VerifyErrorCode =
  | "invalid_token"
  | "token_expired"
  | "wrong_audience"
  | "stale_epoch"
  | "device_revoked"
  | "insufficient_scope";

export interface DeviceVerificationContext {
  issuer: string;
  deviceId: string;
  revocationEpoch: number;
  revoked?: boolean;
  jwks: { keys: Array<Partial<PublicJwk>> };
  /** Unix seconds. */
  now: number;
}

export type VerifyResult =
  | { ok: true; claims: Record<string, unknown>; scopes: string[] }
  | { ok: false; error: VerifyErrorCode; reason: string };

const LEEWAY_SECONDS = 30;
const MAX_LIFETIME_SECONDS = 900;

function fail(error: VerifyErrorCode, reason: string): VerifyResult {
  return { ok: false, error, reason };
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  try {
    const value: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);

export function verifyConnectToken(
  token: string,
  ctx: DeviceVerificationContext,
  required: Scope = SCOPE_READ,
): VerifyResult {
  // 1. Structure and header.
  const parts = token.split(".");
  if (parts.length !== 3) return fail("invalid_token", "malformed token");
  const [h, p, s] = parts as [string, string, string];
  const header = decodeSegment(h);
  if (!header) return fail("invalid_token", "malformed header");
  if (header.alg !== "EdDSA") return fail("invalid_token", "unsupported alg");
  if (header.typ !== undefined && header.typ !== "JWT") return fail("invalid_token", "unsupported typ");
  if (typeof header.kid !== "string") return fail("invalid_token", "missing kid");

  // 2. Key lookup.
  const jwk = ctx.jwks.keys.find((k) => k.kid === header.kid && k.kty === "OKP" && k.crv === "Ed25519");
  if (!jwk?.x) return fail("invalid_token", "unknown kid");

  // 3. Signature.
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return fail("invalid_token", "malformed signature");
  const sig = Buffer.from(s, "base64url");
  let valid = false;
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
    valid = sig.length === 64 && cryptoVerify(null, Buffer.from(`${h}.${p}`, "ascii"), key, sig);
  } catch {
    valid = false;
  }
  if (!valid) return fail("invalid_token", "bad signature");

  const claims = decodeSegment(p);
  if (!claims) return fail("invalid_token", "malformed payload");

  // 4. Issuer.
  if (claims.iss !== ctx.issuer) return fail("invalid_token", "wrong issuer");

  // 5. Audience.
  const aud = claims.aud;
  const audOk =
    aud === ctx.deviceId || (Array.isArray(aud) && aud.length === 1 && aud[0] === ctx.deviceId);
  if (!audOk) return fail("wrong_audience", "token is for another device");

  // 6. Time.
  const { exp, nbf, iat } = claims;
  if (!isInt(exp) || !isInt(nbf) || !isInt(iat)) return fail("invalid_token", "missing time claims");
  if (exp <= ctx.now - LEEWAY_SECONDS) return fail("token_expired", "token expired");
  if (nbf > ctx.now + LEEWAY_SECONDS) return fail("invalid_token", "token not yet valid");
  if (exp - iat > MAX_LIFETIME_SECONDS) return fail("invalid_token", "token lifetime too long");

  // 7. Version.
  if (claims.t3cp_ver !== PROTOCOL_VERSION) return fail("invalid_token", "unsupported protocol version");

  // 8. Revocation epoch.
  if (!isInt(claims.t3cp_epoch)) return fail("invalid_token", "missing epoch");
  if (claims.t3cp_epoch < ctx.revocationEpoch) return fail("stale_epoch", "token predates revocation");

  // 9. Device revocation.
  if (ctx.revoked) return fail("device_revoked", "device revoked");

  // 10. Scope.
  const scopes = typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : [];
  const allowed = required === SCOPE_READ ? scopes.includes(SCOPE_READ) || scopes.includes(SCOPE_WRITE) : scopes.includes(SCOPE_WRITE);
  if (!allowed) return fail("insufficient_scope", `requires ${required}`);

  return { ok: true, claims, scopes };
}
