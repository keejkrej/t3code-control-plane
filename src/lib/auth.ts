import { and, eq, gt, isNull } from "drizzle-orm";
import { jwtVerify, SignJWT } from "jose";
import { getDb } from "@/db";
import { clientTokens, users, type User } from "@/db/schema";
import * as config from "./config";
import { sha256Hex } from "./crypto";
import { bearerToken, errors, HttpError } from "./http";
import { CLIENT_TOKEN_PREFIX, SESSION_TTL_SECONDS, SUPPORTED_SCOPES, type Scope } from "./protocol";

export const SESSION_COOKIE = "t3cp_session";
export const OAUTH_COOKIE = "t3cp_oauth";

export type Principal =
  | { kind: "session"; user: User; scopes: Scope[] }
  | { kind: "client"; user: User; scopes: Scope[]; clientTokenId: string };

export async function createSessionToken(userId: string): Promise<string> {
  return new SignJWT({ typ: "session" })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(`${SESSION_TTL_SECONDS}s`)
    .sign(config.sessionSecret());
}

export function sessionCookie(value: string, maxAge = SESSION_TTL_SECONDS): string {
  const parts = [`${SESSION_COOKIE}=${value}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (config.secureCookies()) parts.push("Secure");
  return parts.join("; ");
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0 && part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return null;
}

/** Resolves the signed-in browser user from the session cookie, or null. */
export async function sessionUser(cookieValue: string | null | undefined): Promise<User | null> {
  if (!cookieValue) return null;
  let userId: string | undefined;
  try {
    const { payload } = await jwtVerify(cookieValue, config.sessionSecret(), { algorithms: ["HS256"] });
    if (payload.typ !== "session") return null;
    userId = payload.sub;
  } catch {
    return null;
  }
  if (!userId) return null;
  const db = await getDb();
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  return user ?? null;
}

/**
 * Rejects cross-site browser requests. Bearer-authenticated API calls are exempt because they can't be
 * forged by a third-party page.
 */
export function assertSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  const expected = new URL(request.url).origin;
  const allowed = new Set([expected, new URL(config.issuer()).origin]);
  if (origin) {
    if (!allowed.has(origin)) throw errors.forbidden("cross_origin", "cross-origin request rejected");
    return;
  }
  if (request.headers.get("sec-fetch-site") === "same-origin") return;
  throw errors.forbidden("cross_origin", "missing Origin header");
}

/**
 * Authenticates a request by client token (`Authorization: Bearer t3cpc_…`) or web session cookie.
 * Session-authenticated mutations must also pass `assertSameOrigin`.
 */
export async function authenticate(request: Request, opts: { mutation?: boolean } = {}): Promise<Principal> {
  const bearer = bearerToken(request);
  if (bearer) {
    if (!bearer.startsWith(CLIENT_TOKEN_PREFIX)) {
      throw errors.unauthorized("invalid_token", "unrecognized bearer token");
    }
    const db = await getDb();
    const now = new Date();
    const [row] = await db
      .select({ token: clientTokens, user: users })
      .from(clientTokens)
      .innerJoin(users, eq(users.id, clientTokens.userId))
      .where(
        and(eq(clientTokens.tokenHash, sha256Hex(bearer)), isNull(clientTokens.revokedAt), gt(clientTokens.expiresAt, now)),
      )
      .limit(1);
    if (!row) throw errors.unauthorized("invalid_token", "client token is invalid, expired, or revoked");
    // Best-effort usage tracking; at most one write per minute per token.
    if (!row.token.lastUsedAt || now.getTime() - row.token.lastUsedAt.getTime() > 60_000) {
      await db.update(clientTokens).set({ lastUsedAt: now }).where(eq(clientTokens.id, row.token.id));
    }
    return {
      kind: "client",
      user: row.user,
      scopes: row.token.scopes.filter((s): s is Scope => (SUPPORTED_SCOPES as readonly string[]).includes(s)),
      clientTokenId: row.token.id,
    };
  }
  const user = await sessionUser(readCookie(request, SESSION_COOKIE));
  if (!user) throw errors.unauthorized();
  if (opts.mutation) assertSameOrigin(request);
  return { kind: "session", user, scopes: [...SUPPORTED_SCOPES] };
}

/** Requires a browser session (used for approval endpoints, which must never accept API tokens). */
export async function requireSession(request: Request): Promise<User> {
  const user = await sessionUser(readCookie(request, SESSION_COOKIE));
  if (!user) throw new HttpError(401, "unauthorized", "sign in required");
  assertSameOrigin(request);
  return user;
}

export function userJson(user: User) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
    email: user.email,
    avatarUrl: user.avatarUrl,
  };
}
