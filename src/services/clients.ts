import { and, eq, isNull, lt, or } from "drizzle-orm";
import type { z } from "zod";
import { getDb } from "@/db";
import { retryOnConflict } from "@/db/errors";
import { clientAuthorizations, clientTokens, type ClientAuthorization, type User } from "@/db/schema";
import type { Principal } from "@/lib/auth";
import * as config from "@/lib/config";
import { formatUserCode, generateUserCode, newId, newSecret, normalizeUserCode, sha256Hex } from "@/lib/crypto";
import { errors, HttpError } from "@/lib/http";
import {
  CLIENT_TOKEN_PREFIX,
  CLIENT_TOKEN_TTL_SECONDS,
  expandScopes,
  PAIRING_TTL_SECONDS,
  POLL_INTERVAL_SECONDS,
  SCOPE_READ,
  SCOPE_WRITE,
} from "@/lib/protocol";
import type { createClientAuthorizationSchema } from "@/lib/validation";

type AuthorizationView = "pending" | "approved" | "denied" | "expired" | "exchanged";

function authorizationStatus(a: ClientAuthorization, now: Date): AuthorizationView {
  if ((a.status === "pending" || a.status === "approved") && a.expiresAt <= now) return "expired";
  return a.status;
}

async function findByUserCode(raw: string): Promise<ClientAuthorization> {
  const code = normalizeUserCode(raw);
  if (!code) throw errors.notFound("unknown authorization code");
  const db = await getDb();
  const [row] = await db.select().from(clientAuthorizations).where(eq(clientAuthorizations.userCode, code)).limit(1);
  if (!row) throw errors.notFound("unknown authorization code");
  return row;
}

export async function createClientAuthorization(
  input: z.infer<typeof createClientAuthorizationSchema>,
  now = new Date(),
) {
  const db = await getDb();
  await db
    .delete(clientAuthorizations)
    .where(lt(clientAuthorizations.expiresAt, new Date(now.getTime() - 24 * 60 * 60 * 1000)));
  const deviceCode = newSecret();
  const scopes = expandScopes(input.scopes ?? [SCOPE_READ, SCOPE_WRITE]);
  const row = await retryOnConflict(async () => {
    const [inserted] = await db
      .insert(clientAuthorizations)
      .values({
        id: newId("cau"),
        userCode: generateUserCode(),
        deviceCodeHash: sha256Hex(deviceCode),
        clientName: input.clientName,
        clientKind: input.client.kind,
        clientVersion: input.client.version,
        scopes,
        expiresAt: new Date(now.getTime() + PAIRING_TTL_SECONDS * 1000),
        createdAt: now,
      })
      .returning();
    return inserted!;
  });
  const display = formatUserCode(row.userCode);
  return {
    authorizationId: row.id,
    deviceCode,
    userCode: display,
    verificationUri: config.url("/authorize"),
    verificationUriComplete: config.url(`/authorize?code=${display}`),
    expiresAt: row.expiresAt.toISOString(),
    interval: POLL_INTERVAL_SECONDS,
  };
}

export async function getClientAuthorization(raw: string, viewer: User | null, now = new Date()) {
  const row = await findByUserCode(raw);
  return {
    authorizationId: row.id,
    userCode: formatUserCode(row.userCode),
    status: authorizationStatus(row, now),
    expiresAt: row.expiresAt.toISOString(),
    ...(viewer
      ? { client: { name: row.clientName, kind: row.clientKind, version: row.clientVersion }, scopes: row.scopes }
      : {}),
  };
}

export async function decideClientAuthorization(raw: string, user: User, decision: "approve" | "deny", now = new Date()) {
  const row = await findByUserCode(raw);
  if (authorizationStatus(row, now) !== "pending") {
    throw new HttpError(409, "authorization_not_pending", `authorization is ${authorizationStatus(row, now)}`);
  }
  const db = await getDb();
  const [updated] = await db
    .update(clientAuthorizations)
    .set({ status: decision === "approve" ? "approved" : "denied", userId: user.id })
    .where(and(eq(clientAuthorizations.id, row.id), eq(clientAuthorizations.status, "pending")))
    .returning();
  if (!updated) throw new HttpError(409, "authorization_not_pending", "authorization was already decided");
  return { authorizationId: updated.id, status: authorizationStatus(updated, now) };
}

const pollError = (code: string, message: string) => new HttpError(400, code, message);

export async function exchangeClientToken(deviceCode: string, now = new Date()) {
  const db = await getDb();
  const [row] = await db
    .select()
    .from(clientAuthorizations)
    .where(eq(clientAuthorizations.deviceCodeHash, sha256Hex(deviceCode)))
    .limit(1);
  if (!row) throw pollError("expired_token", "unknown or expired device code");

  const minGap = new Date(now.getTime() - (POLL_INTERVAL_SECONDS - 1) * 1000);
  const [polled] = await db
    .update(clientAuthorizations)
    .set({ lastPolledAt: now })
    .where(
      and(
        eq(clientAuthorizations.id, row.id),
        or(isNull(clientAuthorizations.lastPolledAt), lt(clientAuthorizations.lastPolledAt, minGap)),
      ),
    )
    .returning({ id: clientAuthorizations.id });
  if (!polled) throw pollError("slow_down", "polling too fast");

  switch (authorizationStatus(row, now)) {
    case "pending":
      throw pollError("authorization_pending", "waiting for the user to approve");
    case "denied":
      throw pollError("access_denied", "the user denied this client");
    case "expired":
    case "exchanged":
      throw pollError("expired_token", "authorization expired or already used");
    case "approved":
      break;
  }

  const accessToken = newSecret(CLIENT_TOKEN_PREFIX);
  const expiresAt = new Date(now.getTime() + CLIENT_TOKEN_TTL_SECONDS * 1000);
  const token = await db.transaction(async (tx) => {
    const [claimed] = await tx
      .update(clientAuthorizations)
      .set({ status: "exchanged" })
      .where(and(eq(clientAuthorizations.id, row.id), eq(clientAuthorizations.status, "approved")))
      .returning();
    if (!claimed?.userId) return null;
    const [inserted] = await tx
      .insert(clientTokens)
      .values({
        id: newId("ctok"),
        userId: claimed.userId,
        tokenHash: sha256Hex(accessToken),
        name: claimed.clientName,
        clientKind: claimed.clientKind,
        clientVersion: claimed.clientVersion,
        scopes: claimed.scopes,
        createdAt: now,
        expiresAt,
      })
      .returning();
    return inserted ?? null;
  });
  if (!token) throw pollError("expired_token", "authorization already used");

  return {
    accessToken,
    tokenType: "Bearer",
    scope: token.scopes.join(" "),
    userId: token.userId,
    expiresAt: token.expiresAt.toISOString(),
  };
}

export async function revokeClientToken(principal: Principal, now = new Date()) {
  if (principal.kind !== "client") {
    throw errors.badRequest("only client tokens can be revoked through this endpoint");
  }
  const db = await getDb();
  await db
    .update(clientTokens)
    .set({ revokedAt: now })
    .where(and(eq(clientTokens.id, principal.clientTokenId), isNull(clientTokens.revokedAt)));
}
