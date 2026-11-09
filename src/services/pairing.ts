import { and, eq, isNull, lt, or } from "drizzle-orm";
import type { z } from "zod";
import { getDb } from "@/db";
import { retryOnConflict } from "@/db/errors";
import { devicePairings, devices, type DevicePairing, type User } from "@/db/schema";
import * as config from "@/lib/config";
import {
  formatUserCode,
  generateUserCode,
  newId,
  newSecret,
  normalizeUserCode,
  pairingExchangeMessage,
  publicKeyFingerprint,
  sha256Hex,
  verifyEd25519,
} from "@/lib/crypto";
import { errors, HttpError } from "@/lib/http";
import {
  DEVICE_CREDENTIAL_PREFIX,
  EXCHANGE_CLOCK_SKEW_SECONDS,
  HEARTBEAT_INTERVAL_SECONDS,
  PAIRING_TTL_SECONDS,
  POLL_INTERVAL_SECONDS,
} from "@/lib/protocol";
import type { createPairingSchema, exchangeSchema } from "@/lib/validation";

export type PairingView = "pending" | "approved" | "denied" | "expired" | "exchanged";

export function pairingStatus(p: DevicePairing, now = new Date()): PairingView {
  if (p.status === "pending" && p.expiresAt <= now) return "expired";
  return p.status;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

async function findByCode(rawCode: string): Promise<DevicePairing> {
  const code = normalizeUserCode(rawCode);
  if (!code) throw errors.notFound("unknown pairing code");
  const db = await getDb();
  const [pairing] = await db.select().from(devicePairings).where(eq(devicePairings.code, code)).limit(1);
  if (!pairing) throw errors.notFound("unknown pairing code");
  return pairing;
}

async function cleanupExpired(now: Date) {
  const db = await getDb();
  const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  await db.delete(devicePairings).where(lt(devicePairings.expiresAt, cutoff));
}

export async function createPairing(input: z.infer<typeof createPairingSchema>, now = new Date()) {
  const db = await getDb();
  await cleanupExpired(now);
  const expiresAt = new Date(now.getTime() + PAIRING_TTL_SECONDS * 1000);
  const row = await retryOnConflict(async () => {
    const [inserted] = await db
      .insert(devicePairings)
      .values({
        id: newId("dpr"),
        code: generateUserCode(),
        publicKey: input.publicKey,
        name: input.name ?? input.hostname,
        hostname: input.hostname,
        platform: input.platform,
        arch: input.arch,
        clientKind: input.client.kind,
        clientVersion: input.client.version,
        tailscaleIp: input.tailscale.ip ?? null,
        magicDnsName: input.tailscale.magicDnsName ?? null,
        port: input.port,
        capabilities: input.capabilities,
        expiresAt,
        createdAt: now,
      })
      .returning();
    return inserted!;
  });
  const display = formatUserCode(row.code);
  return {
    pairingId: row.id,
    code: display,
    verificationUri: config.url("/pair"),
    verificationUriComplete: config.url(`/pair?code=${display}`),
    expiresAt: row.expiresAt.toISOString(),
    interval: POLL_INTERVAL_SECONDS,
  };
}

export function pairingDeviceJson(p: DevicePairing) {
  return {
    name: p.name,
    hostname: p.hostname,
    platform: p.platform,
    arch: p.arch,
    client: { kind: p.clientKind, version: p.clientVersion },
    tailscale: { ip: p.tailscaleIp, magicDnsName: p.magicDnsName },
    port: p.port,
    capabilities: p.capabilities,
    publicKeyFingerprint: publicKeyFingerprint(p.publicKey),
  };
}

export async function getPairing(rawCode: string, viewer: User | null, now = new Date()) {
  const pairing = await findByCode(rawCode);
  return {
    pairingId: pairing.id,
    code: formatUserCode(pairing.code),
    status: pairingStatus(pairing, now),
    expiresAt: pairing.expiresAt.toISOString(),
    ...(viewer ? { device: pairingDeviceJson(pairing) } : {}),
  };
}

export async function decidePairing(
  rawCode: string,
  user: User,
  decision: "approve" | "deny",
  name: string | undefined,
  now = new Date(),
) {
  const pairing = await findByCode(rawCode);
  if (pairingStatus(pairing, now) !== "pending") {
    throw new HttpError(409, "pairing_not_pending", `pairing is ${pairingStatus(pairing, now)}`);
  }
  const db = await getDb();
  const [updated] = await db
    .update(devicePairings)
    .set(
      decision === "approve"
        ? { status: "approved", approvedByUserId: user.id, deviceId: newId("dev"), name: name ?? pairing.name }
        : { status: "denied", approvedByUserId: user.id },
    )
    .where(and(eq(devicePairings.id, pairing.id), eq(devicePairings.status, "pending")))
    .returning();
  if (!updated) throw new HttpError(409, "pairing_not_pending", "pairing was already decided");
  return { pairingId: updated.id, status: pairingStatus(updated, now), deviceId: updated.deviceId };
}

const pollError = (code: string, message: string) => new HttpError(400, code, message);

export async function exchangePairing(rawCode: string, body: z.infer<typeof exchangeSchema>, now = new Date()) {
  const pairing = await findByCode(rawCode);

  // Proof of possession comes first so that only the device can observe the pairing outcome.
  if (!RFC3339.test(body.timestamp)) {
    throw new HttpError(401, "invalid_signature", "timestamp must be RFC 3339");
  }
  const ts = Date.parse(body.timestamp);
  if (!Number.isFinite(ts) || Math.abs(now.getTime() - ts) > EXCHANGE_CLOCK_SKEW_SECONDS * 1000) {
    throw new HttpError(401, "invalid_signature", "timestamp outside allowed clock skew");
  }
  const message = pairingExchangeMessage(pairing.code, pairing.id, body.timestamp);
  if (!verifyEd25519(pairing.publicKey, message, body.signature)) {
    throw new HttpError(401, "invalid_signature", "signature does not verify with the pairing public key");
  }

  const db = await getDb();
  const minGap = new Date(now.getTime() - (POLL_INTERVAL_SECONDS - 1) * 1000);
  const [polled] = await db
    .update(devicePairings)
    .set({ lastPolledAt: now })
    .where(
      and(
        eq(devicePairings.id, pairing.id),
        or(isNull(devicePairings.lastPolledAt), lt(devicePairings.lastPolledAt, minGap)),
      ),
    )
    .returning({ id: devicePairings.id });
  if (!polled) throw pollError("slow_down", "polling too fast");

  switch (pairingStatus(pairing, now)) {
    case "pending":
      throw pollError("authorization_pending", "waiting for the user to approve");
    case "denied":
      throw pollError("access_denied", "the user denied this device");
    case "expired":
    case "exchanged":
      throw pollError("expired_token", "pairing expired or already used");
    case "approved":
      break;
  }

  const credential = newSecret(DEVICE_CREDENTIAL_PREFIX);
  const device = await db.transaction(async (tx) => {
    const [claimed] = await tx
      .update(devicePairings)
      .set({ status: "exchanged" })
      .where(and(eq(devicePairings.id, pairing.id), eq(devicePairings.status, "approved")))
      .returning();
    if (!claimed?.deviceId || !claimed.approvedByUserId) return null;
    const [inserted] = await tx
      .insert(devices)
      .values({
        id: claimed.deviceId,
        ownerUserId: claimed.approvedByUserId,
        name: claimed.name,
        hostname: claimed.hostname,
        platform: claimed.platform,
        arch: claimed.arch,
        clientKind: claimed.clientKind,
        clientVersion: claimed.clientVersion,
        tailscaleIp: claimed.tailscaleIp,
        magicDnsName: claimed.magicDnsName,
        port: claimed.port,
        capabilities: claimed.capabilities,
        publicKey: claimed.publicKey,
        publicKeyFingerprint: publicKeyFingerprint(claimed.publicKey),
        credentialHash: sha256Hex(credential),
        createdAt: now,
        lastSeenAt: now,
      })
      .returning();
    return inserted ?? null;
  });
  if (!device) throw pollError("expired_token", "pairing already used");

  return {
    deviceId: device.id,
    deviceCredential: credential,
    ownerUserId: device.ownerUserId,
    issuer: config.issuer(),
    jwksUri: config.url("/.well-known/jwks.json"),
    revocationEpoch: device.revocationEpoch,
    heartbeatIntervalSeconds: HEARTBEAT_INTERVAL_SECONDS,
  };
}
