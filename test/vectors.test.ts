import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeUserCode, pairingExchangeMessage, publicKeyFingerprint, verifyEd25519 } from "@/lib/crypto";
import { ed25519FromSeed } from "@/lib/testkeys";
import { verifyConnectToken, type DeviceVerificationContext } from "@/lib/tokens";
import type { Scope } from "@/lib/protocol";

const vectors = JSON.parse(readFileSync(path.join(import.meta.dirname, "..", "protocol", "test-vectors.json"), "utf8"));

describe("protocol test vectors", () => {
  it("normalizes codes", () => {
    for (const v of vectors.codeNormalization) {
      expect(normalizeUserCode(v.input), v.input).toBe(v.normalized);
    }
  });

  it("derives fingerprints and pairing signatures", () => {
    const pe = vectors.pairingExchange;
    const key = ed25519FromSeed(Buffer.from(pe.deviceSeed, "base64url"));
    expect(key.publicKey).toBe(pe.publicKey);
    expect(publicKeyFingerprint(vectors.fingerprint.publicKey)).toBe(vectors.fingerprint.fingerprint);
    expect(pairingExchangeMessage(pe.code, pe.pairingId, pe.timestamp)).toBe(pe.message);
    expect(key.sign(pe.message)).toBe(pe.signature);
    expect(verifyEd25519(pe.publicKey, pe.message, pe.signature)).toBe(true);
  });

  it("verifies every connect-token case", () => {
    const ct = vectors.connectTokens;
    for (const c of ct.cases) {
      const ctx: DeviceVerificationContext = { ...ct.context, jwks: ct.jwks, revoked: c.revoked };
      const result = verifyConnectToken(c.token, ctx, c.requiredScope as Scope);
      if (c.expect.valid) {
        expect(result, c.name).toMatchObject({ ok: true, scopes: c.expect.scopes });
      } else {
        expect(result, c.name).toMatchObject({ ok: false, error: c.expect.error });
      }
    }
  });
});
