import { and, desc, eq, sql } from "drizzle-orm";
import type { z } from "zod";
import { getDb } from "@/db";
import { connectTokenIssuances, devices, type Device } from "@/db/schema";
import type { Principal } from "@/lib/auth";
import * as config from "@/lib/config";
import { sha256Hex } from "@/lib/crypto";
import { errors, HttpError, iso } from "@/lib/http";
import {
  DEVICE_CREDENTIAL_PREFIX,
  expandScopes,
  HEARTBEAT_INTERVAL_SECONDS,
  ONLINE_WINDOW_SECONDS,
  SCOPE_READ,
  type Scope,
} from "@/lib/protocol";
import { currentSigningKey, signConnectToken } from "@/lib/tokens";
import type { heartbeatSchema } from "@/lib/validation";

/** Direct Tailscale URL for the device API: MagicDNS preferred, IP fallback, IPv6 bracketed. */
export function deviceEndpoint(d: Pick<Device, "magicDnsName" | "tailscaleIp" | "port">): string | null {
  const host = d.magicDnsName ? d.magicDnsName.replace(/\.$/, "") : d.tailscaleIp;
  if (!host) return null;
  return `http://${host.includes(":") ? `[${host}]` : host}:${d.port}`;
}

export function deviceJson(d: Device, now = new Date()) {
  const active = d.status === "active";
  return {
    id: d.id,
    name: d.name,
    hostname: d.hostname,
    platform: d.platform,
    arch: d.arch,
    client: { kind: d.clientKind, version: d.clientVersion },
    tailscale: { ip: d.tailscaleIp, magicDnsName: d.magicDnsName },
    port: d.port,
    endpoint: active ? deviceEndpoint(d) : null,
    capabilities: d.capabilities,
    publicKeyFingerprint: d.publicKeyFingerprint,
    status: d.status,
    online: active && d.lastSeenAt !== null && now.getTime() - d.lastSeenAt.getTime() <= ONLINE_WINDOW_SECONDS * 1000,
    revocationEpoch: d.revocationEpoch,
    createdAt: d.createdAt.toISOString(),
    lastSeenAt: iso(d.lastSeenAt),
    revokedAt: iso(d.revokedAt),
  };
}

export async function listDevices(userId: string, now = new Date()) {
  const db = await getDb();
  const rows = await db
    .select()
    .from(devices)
    .where(eq(devices.ownerUserId, userId))
    .orderBy(desc(devices.createdAt));
  return { devices: rows.map((d) => deviceJson(d, now)) };
}

async function ownedDevice(userId: string, deviceId: string): Promise<Device> {
  const db = await getDb();
  const [device] = await db
    .select()
    .from(devices)
    .where(and(eq(devices.id, deviceId), eq(devices.ownerUserId, userId)))
    .limit(1);
  if (!device) throw errors.notFound("unknown device");
  return device;
}

export async function getDevice(userId: string, deviceId: string, now = new Date()) {
  return deviceJson(await ownedDevice(userId, deviceId), now);
}

export async function heartbeat(
  deviceId: string,
  credential: string | null,
  body: z.infer<typeof heartbeatSchema>,
  now = new Date(),
) {
  if (!credential?.startsWith(DEVICE_CREDENTIAL_PREFIX)) {
    throw errors.unauthorized("invalid_credential", "device credential required");
  }
  const db = await getDb();
  const [device] = await db
    .select()
    .from(devices)
    .where(eq(devices.credentialHash, sha256Hex(credential)))
    .limit(1);
  if (!device || device.id !== deviceId) {
    throw errors.unauthorized("invalid_credential", "credential is not valid for this device");
  }
  if (device.status !== "active") {
    throw errors.forbidden("device_revoked", "device has been revoked; re-pair to continue");
  }

  const patch: Partial<typeof devices.$inferInsert> = { lastSeenAt: now };
  if (body.tailscale) {
    patch.tailscaleIp = body.tailscale.ip ?? null;
    patch.magicDnsName = body.tailscale.magicDnsName ?? null;
  }
  if (body.port !== undefined) patch.port = body.port;
  if (body.client) {
    patch.clientKind = body.client.kind;
    patch.clientVersion = body.client.version;
  }
  if (body.capabilities) patch.capabilities = body.capabilities;

  const [updated] = await db
    .update(devices)
    .set(patch)
    .where(and(eq(devices.id, device.id), eq(devices.status, "active")))
    .returning();
  if (!updated) throw errors.forbidden("device_revoked", "device has been revoked; re-pair to continue");

  return {
    deviceId: updated.id,
    status: updated.status,
    revocationEpoch: updated.revocationEpoch,
    issuer: config.issuer(),
    jwksUri: config.url("/.well-known/jwks.json"),
    heartbeatIntervalSeconds: HEARTBEAT_INTERVAL_SECONDS,
    serverTime: now.toISOString(),
  };
}

export async function revokeDevice(userId: string, deviceId: string, now = new Date()) {
  await ownedDevice(userId, deviceId);
  const db = await getDb();
  const [updated] = await db
    .update(devices)
    .set({
      status: "revoked",
      revokedAt: sql`coalesce(${devices.revokedAt}, ${now.toISOString()}::timestamptz)`,
      revocationEpoch: sql`${devices.revocationEpoch} + 1`,
    })
    .where(and(eq(devices.id, deviceId), eq(devices.ownerUserId, userId)))
    .returning();
  return deviceJson(updated!, now);
}

export async function mintConnectToken(
  principal: Principal,
  deviceId: string,
  requested: Scope[] | undefined,
  now = new Date(),
) {
  const scopes = expandScopes(requested ?? [SCOPE_READ]);
  const missing = scopes.filter((s) => !principal.scopes.includes(s));
  if (missing.length > 0) {
    throw errors.forbidden("insufficient_scope", `client token lacks ${missing.join(", ")}`);
  }
  const device = await ownedDevice(principal.user.id, deviceId);
  if (device.status !== "active") {
    throw new HttpError(409, "device_revoked", "device has been revoked");
  }
  const key = await currentSigningKey();
  const issued = await signConnectToken(key, {
    issuer: config.issuer(),
    userId: principal.user.id,
    deviceId: device.id,
    scopes,
    revocationEpoch: device.revocationEpoch,
    now,
  });
  const db = await getDb();
  await db.insert(connectTokenIssuances).values({
    jti: issued.jti,
    deviceId: device.id,
    userId: principal.user.id,
    clientTokenId: principal.kind === "client" ? principal.clientTokenId : null,
    scope: issued.scope,
    revocationEpoch: device.revocationEpoch,
    issuedAt: issued.issuedAt,
    expiresAt: issued.expiresAt,
  });
  return {
    token: issued.token,
    tokenType: "Bearer",
    scope: issued.scope,
    expiresIn: Math.round((issued.expiresAt.getTime() - issued.issuedAt.getTime()) / 1000),
    expiresAt: issued.expiresAt.toISOString(),
    deviceId: device.id,
    endpoint: deviceEndpoint(device),
  };
}
