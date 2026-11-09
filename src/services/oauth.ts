import { eq } from "drizzle-orm";
import { jwtVerify, SignJWT } from "jose";
import { createHash, randomBytes } from "node:crypto";
import { getDb } from "@/db";
import { users, type User } from "@/db/schema";
import { OAUTH_COOKIE } from "@/lib/auth";
import * as config from "@/lib/config";
import { newId } from "@/lib/crypto";
import { HttpError } from "@/lib/http";

const AUTHORIZE_URL = "https://vercel.com/oauth/authorize";
const TOKEN_URL = "https://api.vercel.com/login/oauth/token";
const USERINFO_URL = "https://api.vercel.com/login/oauth/userinfo";
const OAUTH_STATE_TTL_SECONDS = 600;

export function callbackUrl(): string {
  return config.url("/api/auth/callback");
}

/** Accepts only same-site relative paths, so `returnTo` can't become an open redirect. */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/";
  return value;
}

export async function beginLogin(returnTo: string | null): Promise<{ location: string; cookie: string }> {
  const { clientId } = config.vercelOAuth();
  const state = randomBytes(24).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const cookieValue = await new SignJWT({ state, verifier, returnTo: safeReturnTo(returnTo) })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(`${OAUTH_STATE_TTL_SECONDS}s`)
    .sign(config.sessionSecret());

  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: callbackUrl(),
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const parts = [`${OAUTH_COOKIE}=${cookieValue}`, "Path=/api/auth", "HttpOnly", "SameSite=Lax", `Max-Age=${OAUTH_STATE_TTL_SECONDS}`];
  if (config.secureCookies()) parts.push("Secure");
  return { location: `${AUTHORIZE_URL}?${params}`, cookie: parts.join("; ") };
}

interface VercelUserInfo {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  picture?: string;
}

export async function completeLogin(
  code: string,
  state: string,
  oauthCookie: string | null,
): Promise<{ user: User; returnTo: string }> {
  if (!oauthCookie) throw new HttpError(400, "invalid_state", "login session expired; try again");
  let stored: { state?: string; verifier?: string; returnTo?: string };
  try {
    stored = (await jwtVerify(oauthCookie, config.sessionSecret(), { algorithms: ["HS256"] })).payload as typeof stored;
  } catch {
    throw new HttpError(400, "invalid_state", "login session expired; try again");
  }
  if (!stored.state || stored.state !== state || !stored.verifier) {
    throw new HttpError(400, "invalid_state", "OAuth state mismatch");
  }

  const { clientId, clientSecret } = config.vercelOAuth();
  const tokenRes = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: callbackUrl(),
      code_verifier: stored.verifier,
    }),
  });
  if (!tokenRes.ok) {
    throw new HttpError(502, "oauth_failed", `Vercel token exchange failed (${tokenRes.status})`);
  }
  const tokens = (await tokenRes.json()) as { access_token?: string };
  if (!tokens.access_token) throw new HttpError(502, "oauth_failed", "Vercel returned no access token");

  const infoRes = await fetch(USERINFO_URL, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  if (!infoRes.ok) throw new HttpError(502, "oauth_failed", `Vercel userinfo failed (${infoRes.status})`);
  const info = (await infoRes.json()) as VercelUserInfo;
  if (!info.sub) throw new HttpError(502, "oauth_failed", "Vercel userinfo has no subject");

  const allow = config.allowedUsers();
  if (allow) {
    const identities = [info.sub, info.preferred_username, info.email].filter(Boolean).map((s) => s!.toLowerCase());
    if (!identities.some((id) => allow.includes(id))) {
      throw new HttpError(403, "user_not_allowed", "this Vercel account is not allowed on this control plane");
    }
  }

  return { user: await upsertVercelUser(info), returnTo: safeReturnTo(stored.returnTo) };
}

export async function upsertVercelUser(info: VercelUserInfo): Promise<User> {
  const db = await getDb();
  const values = {
    email: info.email ?? null,
    name: info.name ?? null,
    username: info.preferred_username ?? null,
    avatarUrl: info.picture ?? null,
  };
  const [user] = await db
    .insert(users)
    .values({ id: newId("usr"), vercelUserId: info.sub, ...values })
    .onConflictDoUpdate({ target: users.vercelUserId, set: { ...values, updatedAt: new Date() } })
    .returning();
  if (user) return user;
  const [existing] = await db.select().from(users).where(eq(users.vercelUserId, info.sub)).limit(1);
  return existing!;
}
