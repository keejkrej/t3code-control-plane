import { z } from "zod";
import { isEd25519PublicKey } from "./crypto";
import { SUPPORTED_SCOPES } from "./protocol";

const TAILSCALE_V4 = /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)$/;
const TAILSCALE_V6 = /^fd7a:115c:a1e0:[0-9a-f:]*$/i;
const DNS_NAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;

export const tailscaleSchema = z
  .object({
    ip: z
      .string()
      .refine((v) => TAILSCALE_V4.test(v) || TAILSCALE_V6.test(v), "must be a Tailscale address (100.64.0.0/10 or fd7a:115c:a1e0::/48)")
      .optional()
      .nullable(),
    magicDnsName: z.string().regex(DNS_NAME, "must be a DNS name").optional().nullable(),
  })
  .refine((t) => Boolean(t.ip || t.magicDnsName), "tailscale.ip or tailscale.magicDnsName is required");

export const clientSchema = z.object({
  kind: z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, "invalid client kind"),
  version: z.string().min(1).max(64),
});

export const capabilitiesSchema = z
  .array(z.string().regex(/^[a-z0-9][a-z0-9:._-]{0,63}$/, "invalid capability"))
  .max(32);

const label = (max: number) => z.string().trim().min(1).max(max);

export const portSchema = z.number().int().min(1).max(65535);

export const createPairingSchema = z.object({
  publicKey: z.string().refine(isEd25519PublicKey, "must be a base64url raw 32-byte Ed25519 public key"),
  name: label(100).optional(),
  hostname: label(253),
  platform: z.enum(["darwin", "linux"]),
  arch: label(32),
  client: clientSchema,
  tailscale: tailscaleSchema,
  port: portSchema,
  capabilities: capabilitiesSchema.default([]),
});

export const exchangeSchema = z.object({
  timestamp: z.string().min(1).max(64),
  signature: z.string().min(1).max(128),
});

export const approveSchema = z.object({
  name: label(100).optional(),
});

export const heartbeatSchema = z.object({
  tailscale: tailscaleSchema.optional(),
  port: portSchema.optional(),
  client: clientSchema.optional(),
  capabilities: capabilitiesSchema.optional(),
});

export const scopesSchema = z.array(z.enum(SUPPORTED_SCOPES)).min(1).max(2);

export const createClientAuthorizationSchema = z.object({
  clientName: label(100),
  client: clientSchema,
  scopes: scopesSchema.optional(),
});

export const clientTokenRequestSchema = z.object({
  deviceCode: z.string().min(1).max(128),
});

export const connectTokenRequestSchema = z.object({
  scopes: scopesSchema.optional(),
});
