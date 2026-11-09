# t3code control plane

Device registry and connection authorization for [g0code](../g0code) (Go) and [r4code](../r4code) (Rust), deployed on Vercel.

The wire contract is [`protocol/PROTOCOL.md`](protocol/PROTOCOL.md). Shared test vectors are in [`protocol/test-vectors.json`](protocol/test-vectors.json). Both client implementations test against those vectors.

## Remote devices: Tailscale-first architecture

### Decision

The MyGo/Rune GUI connects directly over Tailscale to user-owned macOS/Linux devices. Vercel hosts only the control plane. The first version needs neither Cloudflare Tunnel nor a general-purpose traffic relay.

This suits private devices such as a Mac mini or DGX Spark that have internet access but no public IP. Tailscale provides private reachability and WireGuard encryption. The application still authenticates and authorizes every request.

### Stack

- **Control plane (this repo):** Next.js 16 + TypeScript on Vercel.
- **Identity:** Sign in with Vercel (OAuth 2.0 + PKCE). The control plane maps each Vercel user to the devices they own.
- **Database:** Postgres (Neon) with Drizzle migrations. No Redis. Local development and tests use embedded PGlite.
- **GUI:** g0code MyGo desktop app / r4code Rune desktop app.
- **Device daemon:** g0code (Go) or r4code (Rust) on macOS and Linux. It runs the orchestrator, the MCP server, and a small HTTP/WebSocket device API.
- **Network:** Tailscale IP or MagicDNS name. Devices must share a tailnet or use Tailscale node sharing/ACLs.

Don't put long-lived device tunnels in Vercel Functions. If direct connectivity later needs a fallback, add a separate long-running relay without changing the control-plane or device identity model.

### Flows

```text
device daemon                         control plane (Vercel)                     browser
  POST /v1/device-pairings  ───────▶  pending pairing + code
  show code / URL                                                   ◀──────  /pair?code=…  (Sign in with Vercel)
                                                                             approve ──▶ POST …/approve
  POST …/exchange (Ed25519-signed) ─▶ device + t3cpd_ credential
  POST /v1/devices/:id/heartbeat ──▶  address / epoch refresh

GUI client
  POST /v1/client-authorizations ──▶  user code                    ◀──────  /authorize?code=…
  POST …/token (poll) ─────────────▶  t3cpc_ client token
  GET  /v1/devices ────────────────▶  devices + Tailscale endpoints
  POST /v1/devices/:id/connect-tokens ▶ 5-minute EdDSA JWT (aud = device)
  ── direct Tailscale HTTP/WebSocket to device, Bearer JWT ──▶ device verifies with JWKS
```

### Security properties

- **Proof of possession at pairing.** The exchange is signed with the device's Ed25519 key, so someone who sees the pairing code can't take the credential.
- **Approvals need a browser session plus a same-origin check.** API tokens can never approve pairings or client authorizations.
- **Connect tokens are narrow.** Each one names exactly one device (`aud`), carries explicit scopes (`orchestration:read` / `orchestration:write`), and lasts 300 s. It's signed with Ed25519, and devices verify it offline against `/.well-known/jwks.json`.
- **Revocation is immediate on the control plane.** Revoking a device increments its revocation epoch, blocks further connect tokens, and makes its heartbeat return `device_revoked`. Devices reject tokens older than the epoch they last heard.
- **Secrets are stored as hashes.** Device credentials and client tokens are stored only as SHA-256 hashes. Pairing codes, credentials, and tokens are never logged.
- **Each user sees only their own devices.** Device and token queries are scoped to the owner.

Tailscale reachability alone is not application authorization.

## Endpoints

| Method | Path | Auth |
| --- | --- | --- |
| GET | `/.well-known/t3code-control-plane` | — |
| GET | `/.well-known/jwks.json` | — |
| POST | `/v1/device-pairings` | — |
| GET | `/v1/device-pairings/:code` | — (metadata with session) |
| POST | `/v1/device-pairings/:code/approve` · `/deny` | browser session |
| POST | `/v1/device-pairings/:code/exchange` | Ed25519 signature |
| POST | `/v1/client-authorizations` | — |
| GET | `/v1/client-authorizations/:code` | — (metadata with session) |
| POST | `/v1/client-authorizations/:code/approve` · `/deny` | browser session |
| POST | `/v1/client-authorizations/token` | device code |
| GET | `/v1/me` | client token / session |
| POST | `/v1/client-tokens/revoke` | client token |
| GET | `/v1/devices` · `/v1/devices/:id` | client token / session |
| POST | `/v1/devices/:id/connect-tokens` | client token / session |
| POST | `/v1/devices/:id/heartbeat` | device credential |
| POST | `/v1/devices/:id/revoke` | client token / session |

Web pages: `/` (device list and revocation), `/pair`, `/authorize`.

## Layout

```text
protocol/            PROTOCOL.md (normative) + test-vectors.json (generated)
src/app/             Next.js routes and pages
src/services/        pairing, devices, client authorization, OAuth
src/lib/             protocol constants, crypto, connect tokens + reference verifier, auth, validation
src/db/              Drizzle schema, Neon / PGlite drivers
drizzle/             SQL migrations
scripts/             keygen, migrate, generate-vectors
test/                end-to-end route tests (PGlite) + vector conformance
```

## Develop

```sh
npm install
cp .env.example .env.local
npm run keygen            # paste SESSION_SECRET and CONNECT_TOKEN_SIGNING_KEY into .env.local
npm run dev               # DATABASE_URL=pglite:.data/pglite migrates automatically
```

Sign-in needs a Vercel OAuth app, even locally. Use the callback `http://localhost:3000/api/auth/callback`.

```sh
npm test                  # vitest: route-level end-to-end flows + protocol vectors
npm run typecheck
npm run build
npm run vectors           # regenerate protocol/test-vectors.json after protocol changes
```

After regenerating vectors, copy them into `g0code/controlplane/testdata/` and `r4code/src/controlplane/testdata/`.

## Deploy to Vercel

1. Create a Neon database (Vercel Marketplace → Neon), which sets `DATABASE_URL`.
2. Create a **Sign in with Vercel** OAuth app with callback `https://<your-domain>/api/auth/callback`, and set `VERCEL_CLIENT_ID` / `VERCEL_CLIENT_SECRET`.
3. Run `npm run keygen` and set `SESSION_SECRET` and `CONNECT_TOKEN_SIGNING_KEY`.
4. Set `CONTROL_PLANE_URL=https://<your-domain>`. This is the token issuer that devices pin at pairing, so use the stable production domain, not a preview URL.
5. Optionally set `ALLOWED_USERS` to restrict sign-in.
6. Apply migrations: `DATABASE_URL=… npm run db:migrate`, run locally or as a pre-deploy step.
7. Run `vercel deploy --prod`.

**Key rotation:** generate a new key, move the old public `x` into `CONNECT_TOKEN_RETIRED_KEYS`, deploy, and remove it after 5 minutes. Devices refetch the JWKS when they see an unknown `kid`.

## Not in this repo

- The device daemons (HTTP/WebSocket device API, heartbeat loop, keychain storage) belong in g0code and r4code. Both repos provide a `controlplane` client/verifier library tested against the shared vectors.
- Rate limiting on unauthenticated endpoints. Use Vercel Firewall rules for `/v1/device-pairings*` and `/v1/client-authorizations*`.
- A traffic relay for networks without Tailscale.
