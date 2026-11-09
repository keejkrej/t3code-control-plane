/**
 * Generates protocol/test-vectors.json from the server's own primitives and verifies every expected
 * outcome against the reference verifier. Go (g0code) and Rust (r4code) ports consume the file.
 *
 *   npm run vectors
 */
import { writeFileSync } from "node:fs";
import path from "node:path";
import {
  CODE_ALPHABET,
  formatUserCode,
  normalizeUserCode,
  pairingExchangeMessage,
  publicKeyFingerprint,
  verifyEd25519,
} from "../src/lib/crypto";
import { PROTOCOL_VERSION, READ_TOOLS, SCOPE_READ, SCOPE_WRITE, WRITE_TOOLS, type Scope } from "../src/lib/protocol";
import { craftJwt, ed25519FromSeed, seedFrom } from "../src/lib/testkeys";
import { loadSigningKey, signConnectToken, verifyConnectToken, type DeviceVerificationContext } from "../src/lib/tokens";

async function main() {
  // --- Code normalization -------------------------------------------------------------------
  const codeNormalization = [
    ["BCDF-GHJK", "BCDFGHJK"],
    ["bcdf-ghjk", "BCDFGHJK"],
    ["  bcdf ghjk ", "BCDFGHJK"],
    ["BCDFGHJK", "BCDFGHJK"],
    ["B-C-D-F-G-H-J-K", "BCDFGHJK"],
    ["BCDF-GHJ", null],
    ["BCDF-GHJKL", null],
    ["BCDF-GHJA", null],
    ["BCDF-GHJ0", null],
    ["", null],
  ].map(([input, expected]) => {
    const actual = normalizeUserCode(input as string);
    if (actual !== expected) throw new Error(`normalize(${input}) = ${actual}, expected ${expected}`);
    return { input, normalized: expected };
  });

  // --- Device key, fingerprint, pairing exchange --------------------------------------------
  const device = ed25519FromSeed(seedFrom("t3cp test vector device key"));
  const fingerprint = publicKeyFingerprint(device.publicKey);
  const code = "BCDFGHJK";
  const pairingId = "dpr_0testvector00000000000000";
  const timestamp = "2026-11-09T20:00:00.000Z";
  const message = pairingExchangeMessage(code, pairingId, timestamp);
  const signature = device.sign(message);
  if (!verifyEd25519(device.publicKey, message, signature)) throw new Error("pairing signature does not verify");

  // --- Connect tokens -----------------------------------------------------------------------
  const signer = ed25519FromSeed(seedFrom("t3cp test vector signing key"));
  const other = ed25519FromSeed(seedFrom("t3cp test vector unrelated key"));
  const key = await loadSigningKey(JSON.stringify(signer.privateJwk));
  const otherKey = await loadSigningKey(JSON.stringify(other.privateJwk));

  const issuer = "https://control-plane.test";
  const deviceId = "dev_0testvector00000000000000";
  const now = 1_793_995_200; // 2026-11-06T20:00:00Z
  const context = { issuer, deviceId, revocationEpoch: 1, now };
  const jwks = { keys: [key.publicJwk] };

  const header = { alg: "EdDSA", typ: "JWT", kid: key.kid };
  const claims = (over: Record<string, unknown> = {}) => ({
    iss: issuer,
    sub: "usr_0testvector00000000000000",
    aud: deviceId,
    iat: now - 10,
    nbf: now - 10,
    exp: now + 290,
    jti: "ctk_0testvector00000000000000",
    scope: SCOPE_READ,
    t3cp_epoch: 1,
    t3cp_ver: PROTOCOL_VERSION,
    ...over,
  });
  const signed = (payload: Record<string, unknown>, h: Record<string, unknown> = header) => craftJwt(h, payload, signer);
  /** Signs a payload given as raw JSON text, for number encodings JSON.stringify can't produce. */
  const rawSigned = (payloadJson: string) => {
    const input = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(payloadJson).toString("base64url")}`;
    return `${input}.${signer.sign(Buffer.from(input, "ascii"))}`;
  };

  const serverIssued = await signConnectToken(key, {
    issuer,
    userId: "usr_0testvector00000000000000",
    deviceId,
    scopes: [SCOPE_READ, SCOPE_WRITE],
    revocationEpoch: 1,
    now: new Date((now - 5) * 1000),
    jti: "ctk_0servertestvector000000000",
  });
  const foreignIssued = await signConnectToken(otherKey, {
    issuer,
    userId: "usr_0testvector00000000000000",
    deviceId,
    scopes: [SCOPE_READ],
    revocationEpoch: 1,
    now: new Date(now * 1000),
  });

  const valid = signed(claims());
  const [vh, vp, vs] = valid.split(".") as [string, string, string];
  const tamperedPayload = Buffer.from(JSON.stringify(claims({ scope: `${SCOPE_READ} ${SCOPE_WRITE}` }))).toString("base64url");
  const flippedSig = `${vs.slice(0, -2)}${vs.endsWith("AA") ? "BA" : "AA"}`;

  type Case = {
    name: string;
    token: string;
    requiredScope: Scope;
    revoked?: boolean;
    expect: { valid: true; scopes: string[] } | { valid: false; error: string };
  };
  const ok = (scopes: string[]) => ({ valid: true as const, scopes });
  const err = (error: string) => ({ valid: false as const, error });

  const cases: Case[] = [
    { name: "server_issued_write", token: serverIssued.token, requiredScope: SCOPE_WRITE, expect: ok([SCOPE_READ, SCOPE_WRITE]) },
    { name: "server_issued_read_op", token: serverIssued.token, requiredScope: SCOPE_READ, expect: ok([SCOPE_READ, SCOPE_WRITE]) },
    { name: "valid_read", token: valid, requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "read_token_write_op", token: valid, requiredScope: SCOPE_WRITE, expect: err("insufficient_scope") },
    { name: "write_only_scope_allows_read", token: signed(claims({ scope: SCOPE_WRITE })), requiredScope: SCOPE_READ, expect: ok([SCOPE_WRITE]) },
    { name: "empty_scope", token: signed(claims({ scope: "" })), requiredScope: SCOPE_READ, expect: err("insufficient_scope") },
    { name: "no_typ_header", token: signed(claims(), { alg: "EdDSA", kid: key.kid }), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "expired", token: signed(claims({ iat: now - 400, nbf: now - 400, exp: now - 100 })), requiredScope: SCOPE_READ, expect: err("token_expired") },
    { name: "expired_within_leeway", token: signed(claims({ iat: now - 310, nbf: now - 310, exp: now - 10 })), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "expired_at_leeway_boundary", token: signed(claims({ iat: now - 330, nbf: now - 330, exp: now - 30 })), requiredScope: SCOPE_READ, expect: err("token_expired") },
    { name: "not_yet_valid", token: signed(claims({ iat: now + 120, nbf: now + 120, exp: now + 420 })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "nbf_within_leeway", token: signed(claims({ iat: now + 20, nbf: now + 20, exp: now + 320 })), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "lifetime_too_long", token: signed(claims({ exp: now + 3600 })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "missing_exp", token: signed(claims({ exp: undefined })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "wrong_audience", token: signed(claims({ aud: "dev_someotherdevice0000000000" })), requiredScope: SCOPE_READ, expect: err("wrong_audience") },
    { name: "audience_array_single", token: signed(claims({ aud: [deviceId] })), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "audience_array_multiple", token: signed(claims({ aud: [deviceId, "dev_someotherdevice0000000000"] })), requiredScope: SCOPE_READ, expect: err("wrong_audience") },
    { name: "wrong_issuer", token: signed(claims({ iss: "https://evil.test" })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "issuer_trailing_slash", token: signed(claims({ iss: `${issuer}/` })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "stale_epoch", token: signed(claims({ t3cp_epoch: 0 })), requiredScope: SCOPE_READ, expect: err("stale_epoch") },
    { name: "newer_epoch", token: signed(claims({ t3cp_epoch: 2 })), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "missing_epoch", token: signed(claims({ t3cp_epoch: undefined })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "wrong_version", token: signed(claims({ t3cp_ver: 2 })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "device_revoked", token: valid, requiredScope: SCOPE_READ, revoked: true, expect: err("device_revoked") },
    { name: "bad_signature", token: `${vh}.${vp}.${flippedSig}`, requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "tampered_payload", token: `${vh}.${tamperedPayload}.${vs}`, requiredScope: SCOPE_WRITE, expect: err("invalid_token") },
    { name: "alg_none", token: craftJwt({ alg: "none", typ: "JWT", kid: key.kid }, claims(), null), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "alg_hs256", token: signed(claims(), { alg: "HS256", typ: "JWT", kid: key.kid }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "alg_ed25519_name", token: signed(claims(), { alg: "Ed25519", typ: "JWT", kid: key.kid }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "wrong_typ", token: signed(claims(), { alg: "EdDSA", typ: "at+jwt", kid: key.kid }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "missing_kid", token: signed(claims(), { alg: "EdDSA", typ: "JWT" }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "unknown_kid", token: foreignIssued.token, requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "known_kid_wrong_key", token: craftJwt(header, claims(), other), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "two_segments", token: `${vh}.${vp}`, requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "garbage", token: "not-a-token", requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "integral_float_exp", token: rawSigned(JSON.stringify(claims()).replace(`"exp":${now + 290}`, `"exp":${now + 290}.0`)), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "fractional_exp", token: signed(claims({ exp: now + 290.5 })), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "epoch_beyond_safe_integer", token: rawSigned(JSON.stringify(claims()).replace(`"t3cp_epoch":1`, `"t3cp_epoch":9007199254740993`)), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "typ_null", token: signed(claims(), { alg: "EdDSA", typ: null, kid: key.kid }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "kid_not_string", token: signed(claims(), { alg: "EdDSA", typ: "JWT", kid: 7 }), requiredScope: SCOPE_READ, expect: err("invalid_token") },
    { name: "audience_array_empty", token: signed(claims({ aud: [] })), requiredScope: SCOPE_READ, expect: err("wrong_audience") },
    { name: "scope_not_string", token: signed(claims({ scope: [SCOPE_READ] })), requiredScope: SCOPE_READ, expect: err("insufficient_scope") },
    { name: "missing_sub_and_jti", token: signed(claims({ sub: undefined, jti: undefined })), requiredScope: SCOPE_READ, expect: ok([SCOPE_READ]) },
    { name: "precedence_audience_before_time", token: signed(claims({ aud: "dev_someotherdevice0000000000", exp: undefined })), requiredScope: SCOPE_READ, expect: err("wrong_audience") },
    { name: "precedence_epoch_before_revoked", token: signed(claims({ t3cp_epoch: 0 })), requiredScope: SCOPE_READ, revoked: true, expect: err("stale_epoch") },
  ];

  for (const c of cases) {
    const ctx: DeviceVerificationContext = { ...context, jwks, revoked: c.revoked ?? false };
    const result = verifyConnectToken(c.token, ctx, c.requiredScope);
    const matches = c.expect.valid
      ? result.ok && JSON.stringify(result.scopes) === JSON.stringify(c.expect.scopes)
      : !result.ok && result.error === c.expect.error;
    if (!matches) {
      throw new Error(`vector ${c.name}: expected ${JSON.stringify(c.expect)}, got ${JSON.stringify(result)}`);
    }
  }

  const vectors = {
    description:
      "t3code control-plane protocol v1 test vectors. Generated by `npm run vectors`; do not edit by hand. " +
      "All keys here are public test keys and must never be used in a deployment.",
    protocolVersion: PROTOCOL_VERSION,
    codeAlphabet: CODE_ALPHABET,
    codeNormalization,
    codeFormatting: [{ normalized: code, display: formatUserCode(code) }],
    fingerprint: { publicKey: device.publicKey, fingerprint },
    pairingExchange: {
      deviceSeed: device.seed,
      publicKey: device.publicKey,
      code,
      pairingId,
      timestamp,
      message,
      signature,
    },
    connectTokens: {
      signingKey: { seed: signer.seed, privateJwk: signer.privateJwk, kid: key.kid },
      jwks,
      context,
      leewaySeconds: 30,
      maxLifetimeSeconds: 900,
      cases: cases.map((c) => ({
        name: c.name,
        token: c.token,
        requiredScope: c.requiredScope,
        revoked: c.revoked ?? false,
        expect: c.expect,
      })),
    },
    toolScopes: { read: READ_TOOLS, write: WRITE_TOOLS },
  };

  const out = path.join(import.meta.dirname, "..", "protocol", "test-vectors.json");
  writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`);
  console.log(`wrote ${cases.length} connect-token cases to ${path.relative(process.cwd(), out)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
