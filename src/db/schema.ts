import { index, integer, jsonb, pgTable, text, timestamp } from "drizzle-orm/pg-core";

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true, mode: "date" }).notNull().defaultNow(),
};

const tz = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  vercelUserId: text("vercel_user_id").notNull().unique(),
  email: text("email"),
  name: text("name"),
  username: text("username"),
  avatarUrl: text("avatar_url"),
  ...timestamps,
  updatedAt: tz("updated_at").notNull().defaultNow(),
});

/** Device metadata reported by a daemon at pairing time and refreshed by heartbeats. */
const deviceMetadata = {
  name: text("name").notNull(),
  hostname: text("hostname").notNull(),
  platform: text("platform").notNull(),
  arch: text("arch").notNull(),
  clientKind: text("client_kind").notNull(),
  clientVersion: text("client_version").notNull(),
  tailscaleIp: text("tailscale_ip"),
  magicDnsName: text("magic_dns_name"),
  port: integer("port").notNull(),
  capabilities: jsonb("capabilities").$type<string[]>().notNull().default([]),
};

export type PairingStatus = "pending" | "approved" | "denied" | "exchanged";

export const devicePairings = pgTable(
  "device_pairings",
  {
    id: text("id").primaryKey(),
    /** Normalized (no hyphen) 8-character user code. */
    code: text("code").notNull().unique(),
    publicKey: text("public_key").notNull(),
    ...deviceMetadata,
    status: text("status").$type<PairingStatus>().notNull().default("pending"),
    approvedByUserId: text("approved_by_user_id").references(() => users.id, { onDelete: "cascade" }),
    /** Device ID reserved at approval time and used by the exchange. */
    deviceId: text("device_id"),
    expiresAt: tz("expires_at").notNull(),
    lastPolledAt: tz("last_polled_at"),
    ...timestamps,
  },
  (t) => [index("device_pairings_expires_at_idx").on(t.expiresAt)],
);

export type DeviceStatus = "active" | "revoked";

export const devices = pgTable(
  "devices",
  {
    id: text("id").primaryKey(),
    ownerUserId: text("owner_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    ...deviceMetadata,
    publicKey: text("public_key").notNull(),
    publicKeyFingerprint: text("public_key_fingerprint").notNull(),
    /** SHA-256 hex of the device credential. Kept after revocation so heartbeats can report `device_revoked`. */
    credentialHash: text("credential_hash").notNull().unique(),
    status: text("status").$type<DeviceStatus>().notNull().default("active"),
    revocationEpoch: integer("revocation_epoch").notNull().default(0),
    ...timestamps,
    lastSeenAt: tz("last_seen_at"),
    revokedAt: tz("revoked_at"),
  },
  (t) => [index("devices_owner_idx").on(t.ownerUserId)],
);

export type AuthorizationStatus = "pending" | "approved" | "denied" | "exchanged";

export const clientAuthorizations = pgTable(
  "client_authorizations",
  {
    id: text("id").primaryKey(),
    userCode: text("user_code").notNull().unique(),
    deviceCodeHash: text("device_code_hash").notNull().unique(),
    clientName: text("client_name").notNull(),
    clientKind: text("client_kind").notNull(),
    clientVersion: text("client_version").notNull(),
    scopes: jsonb("scopes").$type<string[]>().notNull(),
    status: text("status").$type<AuthorizationStatus>().notNull().default("pending"),
    userId: text("user_id").references(() => users.id, { onDelete: "cascade" }),
    expiresAt: tz("expires_at").notNull(),
    lastPolledAt: tz("last_polled_at"),
    ...timestamps,
  },
  (t) => [index("client_authorizations_expires_at_idx").on(t.expiresAt)],
);

export const clientTokens = pgTable(
  "client_tokens",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    name: text("name").notNull(),
    clientKind: text("client_kind").notNull(),
    clientVersion: text("client_version").notNull(),
    scopes: jsonb("scopes").$type<string[]>().notNull(),
    ...timestamps,
    expiresAt: tz("expires_at").notNull(),
    lastUsedAt: tz("last_used_at"),
    revokedAt: tz("revoked_at"),
  },
  (t) => [index("client_tokens_user_idx").on(t.userId)],
);

/** Audit trail of issued connect tokens (metadata only, never the token). */
export const connectTokenIssuances = pgTable(
  "connect_token_issuances",
  {
    jti: text("jti").primaryKey(),
    deviceId: text("device_id")
      .notNull()
      .references(() => devices.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientTokenId: text("client_token_id"),
    scope: text("scope").notNull(),
    revocationEpoch: integer("revocation_epoch").notNull(),
    issuedAt: tz("issued_at").notNull(),
    expiresAt: tz("expires_at").notNull(),
  },
  (t) => [index("connect_token_issuances_device_idx").on(t.deviceId)],
);

export type User = typeof users.$inferSelect;
export type Device = typeof devices.$inferSelect;
export type DevicePairing = typeof devicePairings.$inferSelect;
export type ClientAuthorization = typeof clientAuthorizations.$inferSelect;
export type ClientToken = typeof clientTokens.$inferSelect;
