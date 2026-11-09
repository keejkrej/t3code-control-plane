import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { POST as clientAuthStart } from "@/app/v1/client-authorizations/route";
import { POST as clientAuthApprove } from "@/app/v1/client-authorizations/[code]/approve/route";
import { POST as clientAuthDeny } from "@/app/v1/client-authorizations/[code]/deny/route";
import { GET as clientAuthGet } from "@/app/v1/client-authorizations/[code]/route";
import { POST as clientToken } from "@/app/v1/client-authorizations/token/route";
import { POST as revokeClientToken } from "@/app/v1/client-tokens/revoke/route";
import { POST as pairingStart } from "@/app/v1/device-pairings/route";
import { GET as pairingGet } from "@/app/v1/device-pairings/[code]/route";
import { POST as pairingApprove } from "@/app/v1/device-pairings/[code]/approve/route";
import { POST as pairingDeny } from "@/app/v1/device-pairings/[code]/deny/route";
import { POST as pairingExchange } from "@/app/v1/device-pairings/[code]/exchange/route";
import { GET as devicesList } from "@/app/v1/devices/route";
import { GET as deviceGet } from "@/app/v1/devices/[id]/route";
import { POST as connectTokens } from "@/app/v1/devices/[id]/connect-tokens/route";
import { POST as heartbeat } from "@/app/v1/devices/[id]/heartbeat/route";
import { POST as revokeDevice } from "@/app/v1/devices/[id]/revoke/route";
import { GET as me } from "@/app/v1/me/route";
import { GET as jwksRoute } from "@/app/.well-known/jwks.json/route";
import { GET as discovery } from "@/app/.well-known/t3code-control-plane/route";
import type { Db } from "@/db";
import { clientAuthorizations, devicePairings } from "@/db/schema";
import { normalizeUserCode, pairingExchangeMessage } from "@/lib/crypto";
import { ed25519FromSeed, seedFrom } from "@/lib/testkeys";
import { verifyConnectToken, type PublicJwk } from "@/lib/tokens";
import { BASE, body, configureEnv, freshDb, params, req, signIn } from "./helpers";

configureEnv();

let db: Db;
beforeEach(async () => {
  db = await freshDb();
});

const deviceKey = ed25519FromSeed(seedFrom("flow test device"));

const pairingRequest = (over: Record<string, unknown> = {}) => ({
  publicKey: deviceKey.publicKey,
  name: "Mac mini",
  hostname: "mac-mini",
  platform: "darwin",
  arch: "arm64",
  client: { kind: "g0code", version: "0.1.0" },
  tailscale: { ip: "100.101.102.103", magicDnsName: "mac-mini.tailnet-abc.ts.net" },
  port: 7420,
  capabilities: ["mcp", "orchestration"],
  ...over,
});

async function startPairing(over: Record<string, unknown> = {}) {
  const res = await pairingStart(req("/v1/device-pairings", { body: pairingRequest(over), origin: null }));
  expect(res.status).toBe(201);
  return body<{ pairingId: string; code: string; verificationUriComplete: string; interval: number }>(res);
}

async function exchange(code: string, pairingId: string, key = deviceKey, timestamp = new Date().toISOString()) {
  // Tests poll faster than the protocol interval; reset the poll clock so slow_down isn't triggered.
  await db.update(devicePairings).set({ lastPolledAt: null }).where(eq(devicePairings.id, pairingId));
  const signature = key.sign(pairingExchangeMessage(normalizeUserCode(code)!, pairingId, timestamp));
  const res = await pairingExchange(
    req(`/v1/device-pairings/${code}/exchange`, { body: { timestamp, signature }, origin: null }),
    params({ code }),
  );
  return { status: res.status, json: await body(res) };
}

async function pairDevice(cookie: string, over: Record<string, unknown> = {}) {
  const p = await startPairing(over);
  const approved = await pairingApprove(req(`/v1/device-pairings/${p.code}/approve`, { body: {}, cookie }), params({ code: p.code }));
  expect(approved.status).toBe(200);
  const ex = await exchange(p.code, p.pairingId);
  expect(ex.status).toBe(200);
  return ex.json as { deviceId: string; deviceCredential: string; revocationEpoch: number; issuer: string };
}

async function authorizeClient(cookie: string, scopes?: string[]) {
  const start = await body<{ deviceCode: string; userCode: string }>(
    await clientAuthStart(
      req("/v1/client-authorizations", {
        body: { clientName: "r4code desktop", client: { kind: "r4code", version: "0.1.0" }, ...(scopes ? { scopes } : {}) },
        origin: null,
      }),
    ),
  );
  const ok = await clientAuthApprove(
    req(`/v1/client-authorizations/${start.userCode}/approve`, { body: {}, cookie }),
    params({ code: start.userCode }),
  );
  expect(ok.status).toBe(200);
  const res = await clientToken(req("/v1/client-authorizations/token", { body: { deviceCode: start.deviceCode }, origin: null }));
  expect(res.status).toBe(200);
  return body<{ accessToken: string; scope: string; userId: string }>(res);
}

async function jwks() {
  return body<{ keys: PublicJwk[] }>(await jwksRoute());
}

describe("discovery", () => {
  it("publishes endpoints and an Ed25519 JWKS", async () => {
    const doc = await body(await discovery());
    expect(doc).toMatchObject({
      protocolVersion: 1,
      issuer: BASE,
      jwksUri: `${BASE}/.well-known/jwks.json`,
      scopesSupported: ["orchestration:read", "orchestration:write"],
    });
    const { keys } = await jwks();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig" });
  });
});

describe("device pairing", () => {
  it("runs the full pairing → heartbeat → connect → revoke lifecycle", async () => {
    const { user, cookie } = await signIn();
    const p = await startPairing();
    expect(p.code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(p.verificationUriComplete).toBe(`${BASE}/pair?code=${p.code}`);

    // Anonymous status reveals no device metadata; a signed-in viewer sees it.
    const anon = await body(await pairingGet(req(`/v1/device-pairings/${p.code}`), params({ code: p.code })));
    expect(anon).toMatchObject({ status: "pending" });
    expect(anon).not.toHaveProperty("device");
    const viewed = await body(await pairingGet(req(`/v1/device-pairings/${p.code.toLowerCase()}`, { cookie }), params({ code: p.code.toLowerCase() })));
    expect(viewed).toMatchObject({ device: { hostname: "mac-mini", client: { kind: "g0code" } } });

    expect((await exchange(p.code, p.pairingId)).json).toMatchObject({ error: "authorization_pending" });

    const approve = await pairingApprove(
      req(`/v1/device-pairings/${p.code}/approve`, { body: { name: "Studio Mac" }, cookie }),
      params({ code: p.code }),
    );
    expect(await body(approve)).toMatchObject({ status: "approved" });

    const ex = await exchange(p.code, p.pairingId);
    expect(ex.status).toBe(200);
    const paired = ex.json as { deviceId: string; deviceCredential: string; ownerUserId: string; issuer: string };
    expect(paired.deviceCredential).toMatch(/^t3cpd_[A-Za-z0-9_-]{43}$/);
    expect(paired.ownerUserId).toBe(user.id);
    expect(paired.issuer).toBe(BASE);

    // Exactly one exchange succeeds.
    expect((await exchange(p.code, p.pairingId)).json).toMatchObject({ error: "expired_token" });

    // Heartbeat updates addresses.
    const hb = await heartbeat(
      req(`/v1/devices/${paired.deviceId}/heartbeat`, {
        body: { tailscale: { ip: "100.64.0.9" }, port: 7421, client: { kind: "g0code", version: "0.1.1" } },
        bearer: paired.deviceCredential,
        origin: null,
      }),
      params({ id: paired.deviceId }),
    );
    expect(hb.status).toBe(200);
    expect(await body(hb)).toMatchObject({ deviceId: paired.deviceId, status: "active", revocationEpoch: 0, heartbeatIntervalSeconds: 60 });

    // GUI client lists the device and mints a connect token.
    const client = await authorizeClient(cookie);
    expect(client.scope).toBe("orchestration:read orchestration:write");
    const list = await body<{ devices: Array<Record<string, unknown>> }>(await devicesList(req("/v1/devices", { bearer: client.accessToken })));
    expect(list.devices).toHaveLength(1);
    expect(list.devices[0]).toMatchObject({
      id: paired.deviceId,
      name: "Studio Mac",
      online: true,
      endpoint: "http://100.64.0.9:7421",
      client: { kind: "g0code", version: "0.1.1" },
    });

    const minted = await connectTokens(
      req(`/v1/devices/${paired.deviceId}/connect-tokens`, { body: { scopes: ["orchestration:write"] }, bearer: client.accessToken, origin: null }),
      params({ id: paired.deviceId }),
    );
    expect(minted.status).toBe(201);
    const token = await body<{ token: string; scope: string; expiresIn: number; endpoint: string }>(minted);
    expect(token).toMatchObject({ scope: "orchestration:read orchestration:write", expiresIn: 300, endpoint: "http://100.64.0.9:7421" });

    // The device verifies the token with the published JWKS.
    const now = Math.floor(Date.now() / 1000);
    const ctx = { issuer: BASE, deviceId: paired.deviceId, revocationEpoch: 0, jwks: await jwks(), now };
    const verified = verifyConnectToken(token.token, ctx, "orchestration:write");
    expect(verified).toMatchObject({ ok: true, claims: { sub: user.id, aud: paired.deviceId, t3cp_epoch: 0, t3cp_ver: 1 } });
    expect(verifyConnectToken(token.token, { ...ctx, deviceId: "dev_other" })).toMatchObject({ ok: false, error: "wrong_audience" });

    // Revocation bumps the epoch, invalidates outstanding tokens, and stops heartbeats.
    const revoked = await revokeDevice(req(`/v1/devices/${paired.deviceId}/revoke`, { body: {}, bearer: client.accessToken, origin: null }), params({ id: paired.deviceId }));
    expect(await body(revoked)).toMatchObject({ status: "revoked", revocationEpoch: 1, endpoint: null, online: false });
    expect(verifyConnectToken(token.token, { ...ctx, revocationEpoch: 1 })).toMatchObject({ ok: false, error: "stale_epoch" });

    const hb2 = await heartbeat(
      req(`/v1/devices/${paired.deviceId}/heartbeat`, { body: {}, bearer: paired.deviceCredential, origin: null }),
      params({ id: paired.deviceId }),
    );
    expect(hb2.status).toBe(403);
    expect(await body(hb2)).toMatchObject({ error: "device_revoked" });

    const mintAfter = await connectTokens(
      req(`/v1/devices/${paired.deviceId}/connect-tokens`, { body: {}, bearer: client.accessToken, origin: null }),
      params({ id: paired.deviceId }),
    );
    expect(mintAfter.status).toBe(409);
    expect(await body(mintAfter)).toMatchObject({ error: "device_revoked" });
  });

  it("requires the device private key to exchange", async () => {
    const { cookie } = await signIn();
    const p = await startPairing();
    await pairingApprove(req(`/v1/device-pairings/${p.code}/approve`, { body: {}, cookie }), params({ code: p.code }));

    const thief = ed25519FromSeed(seedFrom("someone who saw the code"));
    const stolen = await exchange(p.code, p.pairingId, thief);
    expect(stolen).toMatchObject({ status: 401, json: { error: "invalid_signature" } });

    const stale = await exchange(p.code, p.pairingId, deviceKey, new Date(Date.now() - 10 * 60_000).toISOString());
    expect(stale).toMatchObject({ status: 401, json: { error: "invalid_signature" } });

    const notRfc = await exchange(p.code, p.pairingId, deviceKey, String(Date.now()));
    expect(notRfc).toMatchObject({ status: 401, json: { error: "invalid_signature" } });

    expect((await exchange(p.code, p.pairingId)).status).toBe(200);
  });

  it("reports denial and slow_down", async () => {
    const { cookie } = await signIn();
    const p = await startPairing();
    const denied = await pairingDeny(req(`/v1/device-pairings/${p.code}/deny`, { body: {}, cookie }), params({ code: p.code }));
    expect(await body(denied)).toMatchObject({ status: "denied" });
    expect((await exchange(p.code, p.pairingId)).json).toMatchObject({ error: "access_denied" });

    // Second poll inside the interval without resetting the clock.
    const ts = new Date().toISOString();
    const signature = deviceKey.sign(pairingExchangeMessage(normalizeUserCode(p.code)!, p.pairingId, ts));
    const res = await pairingExchange(
      req(`/v1/device-pairings/${p.code}/exchange`, { body: { timestamp: ts, signature }, origin: null }),
      params({ code: p.code }),
    );
    expect(await body(res)).toMatchObject({ error: "slow_down" });
  });

  it("reports expiry and refuses late approval", async () => {
    const { cookie } = await signIn();
    const p = await startPairing();
    await db.update(devicePairings).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(devicePairings.id, p.pairingId));
    expect((await exchange(p.code, p.pairingId)).json).toMatchObject({ error: "expired_token" });
    const late = await pairingApprove(req(`/v1/device-pairings/${p.code}/approve`, { body: {}, cookie }), params({ code: p.code }));
    expect(late.status).toBe(409);
  });

  it("validates pairing requests", async () => {
    const bad = async (over: Record<string, unknown>) => {
      const res = await pairingStart(req("/v1/device-pairings", { body: pairingRequest(over), origin: null }));
      expect(res.status).toBe(400);
      return body(res);
    };
    expect(await bad({ publicKey: "too-short" })).toMatchObject({ error: "invalid_request" });
    expect(await bad({ platform: "windows" })).toMatchObject({ error: "invalid_request" });
    expect(await bad({ tailscale: { ip: "192.168.1.10" } })).toMatchObject({ error: "invalid_request" });
    expect(await bad({ tailscale: {} })).toMatchObject({ error: "invalid_request" });
    expect(await bad({ port: 70000 })).toMatchObject({ error: "invalid_request" });
    expect(await bad({ client: { kind: "Bad Kind", version: "1" } })).toMatchObject({ error: "invalid_request" });

    // IPv6 Tailscale addresses and r4code clients are accepted.
    const ok = await pairingStart(
      req("/v1/device-pairings", {
        body: pairingRequest({ tailscale: { ip: "fd7a:115c:a1e0::1" }, client: { kind: "r4code", version: "0.1.0" }, platform: "linux" }),
        origin: null,
      }),
    );
    expect(ok.status).toBe(201);
  });

  it("brackets IPv6 endpoints and prefers MagicDNS", async () => {
    const { cookie } = await signIn();
    const v6 = await pairDevice(cookie, { tailscale: { ip: "fd7a:115c:a1e0::1" } });
    const dns = await pairDevice(cookie);
    const one = async (id: string) =>
      body<{ endpoint: string }>(await deviceGet(req(`/v1/devices/${id}`, { cookie }), params({ id })));
    expect((await one(v6.deviceId)).endpoint).toBe("http://[fd7a:115c:a1e0::1]:7420");
    expect((await one(dns.deviceId)).endpoint).toBe("http://mac-mini.tailnet-abc.ts.net:7420");
  });
});

describe("authorization boundaries", () => {
  it("rejects cross-origin and token-based approvals", async () => {
    const { cookie } = await signIn();
    const p = await startPairing();
    const cross = await pairingApprove(
      req(`/v1/device-pairings/${p.code}/approve`, { body: {}, cookie, origin: "https://evil.example" }),
      params({ code: p.code }),
    );
    expect(cross.status).toBe(403);
    expect(await body(cross)).toMatchObject({ error: "cross_origin" });

    const noOrigin = await pairingApprove(req(`/v1/device-pairings/${p.code}/approve`, { body: {}, cookie, origin: null }), params({ code: p.code }));
    expect(noOrigin.status).toBe(403);

    const client = await authorizeClient(cookie);
    const viaToken = await pairingApprove(
      req(`/v1/device-pairings/${p.code}/approve`, { body: {}, bearer: client.accessToken }),
      params({ code: p.code }),
    );
    expect(viaToken.status).toBe(401);
  });

  it("isolates devices between users", async () => {
    const alice = await signIn("vercel_alice", "alice");
    const bob = await signIn("vercel_bob", "bob");
    const device = await pairDevice(alice.cookie);
    const bobClient = await authorizeClient(bob.cookie);

    expect((await body<{ devices: unknown[] }>(await devicesList(req("/v1/devices", { bearer: bobClient.accessToken })))).devices).toHaveLength(0);
    const mint = await connectTokens(
      req(`/v1/devices/${device.deviceId}/connect-tokens`, { body: {}, bearer: bobClient.accessToken, origin: null }),
      params({ id: device.deviceId }),
    );
    expect(mint.status).toBe(404);
    const revoke = await revokeDevice(req(`/v1/devices/${device.deviceId}/revoke`, { body: {}, bearer: bobClient.accessToken, origin: null }), params({ id: device.deviceId }));
    expect(revoke.status).toBe(404);
  });

  it("rejects bad device credentials", async () => {
    const { cookie } = await signIn();
    const a = await pairDevice(cookie);
    const b = await pairDevice(cookie);
    const wrong = await heartbeat(req(`/v1/devices/${a.deviceId}/heartbeat`, { body: {}, bearer: b.deviceCredential, origin: null }), params({ id: a.deviceId }));
    expect(wrong.status).toBe(401);
    expect(await body(wrong)).toMatchObject({ error: "invalid_credential" });
    const none = await heartbeat(req(`/v1/devices/${a.deviceId}/heartbeat`, { body: {}, origin: null }), params({ id: a.deviceId }));
    expect(none.status).toBe(401);
  });

  it("enforces client token scopes and revocation", async () => {
    const { cookie, user } = await signIn();
    const device = await pairDevice(cookie);
    const readOnly = await authorizeClient(cookie, ["orchestration:read"]);
    expect(readOnly.scope).toBe("orchestration:read");

    const write = await connectTokens(
      req(`/v1/devices/${device.deviceId}/connect-tokens`, { body: { scopes: ["orchestration:write"] }, bearer: readOnly.accessToken, origin: null }),
      params({ id: device.deviceId }),
    );
    expect(write.status).toBe(403);
    expect(await body(write)).toMatchObject({ error: "insufficient_scope" });

    const read = await connectTokens(
      req(`/v1/devices/${device.deviceId}/connect-tokens`, { body: {}, bearer: readOnly.accessToken, origin: null }),
      params({ id: device.deviceId }),
    );
    expect(await body(read)).toMatchObject({ scope: "orchestration:read" });

    expect(await body(await me(req("/v1/me", { bearer: readOnly.accessToken })))).toMatchObject({ user: { id: user.id, username: "jack" } });
    expect((await revokeClientToken(req("/v1/client-tokens/revoke", { body: {}, bearer: readOnly.accessToken, origin: null }))).status).toBe(204);
    const after = await me(req("/v1/me", { bearer: readOnly.accessToken }));
    expect(after.status).toBe(401);
    expect(await body(after)).toMatchObject({ error: "invalid_token" });
  });

  it("supports session-authenticated browser revocation via form posts", async () => {
    const { cookie } = await signIn();
    const device = await pairDevice(cookie);
    const res = await revokeDevice(req(`/v1/devices/${device.deviceId}/revoke`, { form: {}, cookie }), params({ id: device.deviceId }));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${BASE}/`);
  });
});

describe("client authorization", () => {
  it("handles pending, denial, single use, and metadata visibility", async () => {
    const { cookie } = await signIn();
    const start = await body<{ deviceCode: string; userCode: string; authorizationId: string }>(
      await clientAuthStart(
        req("/v1/client-authorizations", { body: { clientName: "g0code desktop", client: { kind: "g0code", version: "0.1.0" } }, origin: null }),
      ),
    );
    const poll = async () => {
      await db.update(clientAuthorizations).set({ lastPolledAt: null }).where(eq(clientAuthorizations.id, start.authorizationId));
      return body(await clientToken(req("/v1/client-authorizations/token", { body: { deviceCode: start.deviceCode }, origin: null })));
    };
    expect(await poll()).toMatchObject({ error: "authorization_pending" });

    const anon = await body(await clientAuthGet(req(`/v1/client-authorizations/${start.userCode}`), params({ code: start.userCode })));
    expect(anon).not.toHaveProperty("client");
    const seen = await body(await clientAuthGet(req(`/v1/client-authorizations/${start.userCode}`, { cookie }), params({ code: start.userCode })));
    expect(seen).toMatchObject({ client: { name: "g0code desktop" }, scopes: ["orchestration:read", "orchestration:write"] });

    await clientAuthDeny(req(`/v1/client-authorizations/${start.userCode}/deny`, { body: {}, cookie }), params({ code: start.userCode }));
    expect(await poll()).toMatchObject({ error: "access_denied" });

    expect(await body(await clientToken(req("/v1/client-authorizations/token", { body: { deviceCode: "nope" }, origin: null })))).toMatchObject({
      error: "expired_token",
    });
  });
});
