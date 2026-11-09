# t3code control-plane protocol v1

This document is the wire contract between the Vercel-hosted control plane and its clients:

- **Device daemons** — g0code (Go) and r4code (Rust) processes that run the orchestrator/MCP server on a user-owned Mac or Linux machine.
- **GUI clients** — the g0code MyGo desktop app, the r4code Rune desktop app, or any other tool that lists devices and connects to them.

Everything here is language-neutral: plain JSON over HTTPS, Ed25519 signatures, and compact JWS (JWT) tokens. [`protocol/test-vectors.json`](test-vectors.json) contains fixed keys, messages, signatures, and tokens. Every implementation should check itself against those vectors.

The control plane only carries **metadata and authorization**. Orchestration traffic never passes through Vercel: GUI clients connect directly to the device over Tailscale.

## Conventions

- Base URL: the deployment origin, e.g. `https://t3code-control-plane.vercel.app`. It is also the token **issuer** (`iss`), with no trailing slash.
- Request and response bodies are `application/json; charset=utf-8`.
- Timestamps are RFC 3339 UTC strings with millisecond precision (`2026-11-09T20:00:00.000Z`).
- `base64url` means RFC 4648 §5 without padding.
- Errors use a non-2xx status and the body `{"error": "<snake_case_code>", "message": "<human text>"}`. Clients should branch on `error`, never on `message`.
- Unknown JSON fields must be ignored by both sides, so new fields can be added within v1.

### Discovery

`GET /.well-known/t3code-control-plane`

```json
{
  "protocolVersion": 1,
  "issuer": "https://cp.example.com",
  "jwksUri": "https://cp.example.com/.well-known/jwks.json",
  "devicePairingEndpoint": "https://cp.example.com/v1/device-pairings",
  "clientAuthorizationEndpoint": "https://cp.example.com/v1/client-authorizations",
  "clientTokenEndpoint": "https://cp.example.com/v1/client-authorizations/token",
  "devicesEndpoint": "https://cp.example.com/v1/devices",
  "scopesSupported": ["orchestration:read", "orchestration:write"],
  "connectTokenTtlSeconds": 300,
  "heartbeatIntervalSeconds": 60
}
```

Clients are configured with only the base URL. All paths in this document are fixed relative to that base URL. Discovery confirms the protocol version, issuer, and JWKS location, and is a convenience for the main endpoints; it does not list every route.

## Credentials

| Credential | Format | Holder | Lifetime | Used for |
| --- | --- | --- | --- | --- |
| Device key | Ed25519 keypair | Device daemon (private key in OS keychain or `0600` file) | Until re-paired | Proving possession during pairing exchange |
| Device credential | `t3cpd_` + 43 base64url chars (32 random bytes) | Device daemon | Until device revoked | `POST /v1/devices/:id/heartbeat` |
| Client token | `t3cpc_` + 43 base64url chars | GUI client | 90 days | Listing devices, minting connect tokens |
| Connect token | EdDSA JWT | GUI client → device | 300 s | Authorizing one connection to one device |
| Web session | HttpOnly cookie | Browser | 30 days | Approving pairings and client authorizations |

The control plane stores only SHA-256 hashes of device credentials and client tokens. Secrets are never logged.

Credentials are sent as `Authorization: Bearer <value>`.

## Device pairing

Pairing ties a device's Ed25519 public key to a signed-in user. It is modelled on the OAuth device authorization grant (RFC 8628), with the token exchange bound to the device key.

### 1. Start pairing (device)

`POST /v1/device-pairings` — unauthenticated.

```json
{
  "publicKey": "<base64url raw 32-byte Ed25519 public key>",
  "name": "Jack's Mac mini",
  "hostname": "mac-mini",
  "platform": "darwin",
  "arch": "arm64",
  "client": { "kind": "g0code", "version": "0.1.0" },
  "tailscale": { "ip": "100.101.102.103", "magicDnsName": "mac-mini.tailnet-abc.ts.net" },
  "port": 7420,
  "capabilities": ["mcp", "orchestration"]
}
```

- `platform`: `darwin` or `linux`.
- `client.kind`: `g0code`, `r4code`, or another implementation identifier matching `^[a-z0-9][a-z0-9-]{0,31}$`.
- `tailscale`: at least one of `ip` (IPv4 in `100.64.0.0/10` or IPv6 in `fd7a:115c:a1e0::/48`) or `magicDnsName`.
- `port`: TCP port the device API listens on (1–65535).
- `capabilities`: up to 32 strings matching `^[a-z0-9][a-z0-9:._-]{0,63}$`.

Response `201`:

```json
{
  "pairingId": "dpr_…",
  "code": "BCDF-GHJK",
  "verificationUri": "https://cp.example.com/pair",
  "verificationUriComplete": "https://cp.example.com/pair?code=BCDF-GHJK",
  "expiresAt": "2026-11-09T20:10:00.000Z",
  "interval": 5
}
```

The device displays `code` and `verificationUriComplete` (optionally as a QR code).

**Pairing codes** are 8 characters from the alphabet `BCDFGHJKLMNPQRSTVWXZ`, shown as `XXXX-XXXX`. To normalize a code, uppercase ASCII `a`–`z`, drop every character that is not ASCII `A`–`Z` or `0`–`9` (spaces, hyphens, other punctuation), and accept the result only if exactly 8 characters remain and all are in the alphabet. Codes in URLs and API paths may use either form. Codes expire after 10 minutes.

### 2. Approve (user, browser)

The user opens `verificationUriComplete`, signs in with Vercel, checks the hostname, platform, client kind, Tailscale address, and key fingerprint, then approves or denies. This uses the web session and is not part of the device-facing protocol:

- `POST /v1/device-pairings/:code/approve` (optional body `{"name": "…"}` to rename)
- `POST /v1/device-pairings/:code/deny`

Both require a web session and a same-origin `Origin` header.

`GET /v1/device-pairings/:code` returns `{"pairingId", "status", "expiresAt"}`. With a web session it also includes the `device` metadata shown on the approval page.

`status` is one of `pending`, `approved`, `denied`, `expired`, `exchanged`.

**Key fingerprint**, shown to the user and recommended for display by the device: `SHA256:` + base64url(SHA-256(raw public key bytes)), unpadded.

### 3. Exchange (device)

The device polls every `interval` seconds:

`POST /v1/device-pairings/:code/exchange`

```json
{
  "timestamp": "2026-11-09T20:01:00.000Z",
  "signature": "<base64url Ed25519 signature>"
}
```

The signature is over the UTF-8 bytes of the following message, with `\n` (0x0A) separators and no trailing newline:

```text
t3cp-pairing-exchange-v1
<normalized code, 8 chars, no hyphen>
<pairingId>
<timestamp, exactly as sent>
```

The control plane verifies the signature with the public key from step 1 and accepts timestamps within ±300 s of its clock. Only the holder of the private key can complete pairing, so someone who sees the code on screen can't steal the credential.

Responses:

| Status | Body | Meaning |
| --- | --- | --- |
| `200` | see below | Paired. Exactly one exchange succeeds per pairing. |
| `400` | `{"error":"authorization_pending"}` | Keep polling. |
| `400` | `{"error":"slow_down"}` | Add 5 s to the interval. |
| `400` | `{"error":"access_denied"}` | User denied. Stop. |
| `400` | `{"error":"expired_token"}` | Code expired or already exchanged. Start over. |
| `401` | `{"error":"invalid_signature"}` | Signature or timestamp rejected. |
| `404` | `{"error":"not_found"}` | Unknown code. |

Success body:

```json
{
  "deviceId": "dev_…",
  "deviceCredential": "t3cpd_…",
  "ownerUserId": "usr_…",
  "issuer": "https://cp.example.com",
  "jwksUri": "https://cp.example.com/.well-known/jwks.json",
  "revocationEpoch": 0,
  "heartbeatIntervalSeconds": 60
}
```

The device persists `deviceId`, `deviceCredential`, `issuer`, and `revocationEpoch` next to its private key.

## Device heartbeat

`POST /v1/devices/:deviceId/heartbeat` — `Authorization: Bearer t3cpd_…`

```json
{
  "tailscale": { "ip": "100.101.102.103", "magicDnsName": "mac-mini.tailnet-abc.ts.net" },
  "port": 7420,
  "client": { "kind": "g0code", "version": "0.1.1" },
  "capabilities": ["mcp", "orchestration"]
}
```

All fields are optional. Fields that are present replace the stored values, so address changes propagate.

Response `200`:

```json
{
  "deviceId": "dev_…",
  "status": "active",
  "revocationEpoch": 0,
  "issuer": "https://cp.example.com",
  "jwksUri": "https://cp.example.com/.well-known/jwks.json",
  "heartbeatIntervalSeconds": 60,
  "serverTime": "2026-11-09T20:02:00.000Z"
}
```

- The device keeps max(stored epoch, returned `revocationEpoch`) and rejects connect tokens with a lower `t3cp_epoch`.
- The issuer stays pinned to the value stored at pairing; a heartbeat never changes it. The device may update its cached `jwksUri` from the heartbeat.
- `401 {"error":"invalid_credential"}`: credential unknown or not for this device.
- `403 {"error":"device_revoked"}`: the device must stop accepting **all** connect tokens, delete its credential, and require re-pairing.

A device is shown as online while its last heartbeat is within 3 × `heartbeatIntervalSeconds`.

## GUI client authorization

Desktop GUIs can't receive an OAuth redirect easily, so they use a device-code flow.

### 1. Start

`POST /v1/client-authorizations` — unauthenticated.

```json
{
  "clientName": "g0code desktop on mac-mini",
  "client": { "kind": "g0code", "version": "0.1.0" },
  "scopes": ["orchestration:read", "orchestration:write"]
}
```

`scopes` defaults to both scopes.

Response `201`:

```json
{
  "authorizationId": "cau_…",
  "deviceCode": "<secret, 43 base64url chars>",
  "userCode": "BCDF-GHJK",
  "verificationUri": "https://cp.example.com/authorize",
  "verificationUriComplete": "https://cp.example.com/authorize?code=BCDF-GHJK",
  "expiresAt": "…",
  "interval": 5
}
```

The GUI opens `verificationUriComplete` in the system browser and keeps `deviceCode` secret.

### 2. Approve (browser)

`POST /v1/client-authorizations/:userCode/approve` and `/deny` require a web session and a same-origin `Origin` header.

### 3. Token

`POST /v1/client-authorizations/token`

```json
{ "deviceCode": "…" }
```

This returns the same `authorization_pending` / `slow_down` / `access_denied` / `expired_token` errors as pairing exchange. On success:

```json
{
  "accessToken": "t3cpc_…",
  "tokenType": "Bearer",
  "scope": "orchestration:read orchestration:write",
  "userId": "usr_…",
  "expiresAt": "…"
}
```

### Session endpoints

- `GET /v1/me` → `{"user": {"id", "name", "username", "email", "avatarUrl"}, "scope"}`
- `POST /v1/client-tokens/revoke` revokes the presenting client token. Returns `204`.

Both accept a client token or a web session. Revoked or expired client tokens return `401 {"error":"invalid_token"}`.

## Devices

### List

`GET /v1/devices` — client token or web session.

```json
{
  "devices": [
    {
      "id": "dev_…",
      "name": "Jack's Mac mini",
      "hostname": "mac-mini",
      "platform": "darwin",
      "arch": "arm64",
      "client": { "kind": "g0code", "version": "0.1.0" },
      "tailscale": { "ip": "100.101.102.103", "magicDnsName": "mac-mini.tailnet-abc.ts.net" },
      "port": 7420,
      "endpoint": "http://mac-mini.tailnet-abc.ts.net:7420",
      "capabilities": ["mcp", "orchestration"],
      "publicKeyFingerprint": "SHA256:…",
      "status": "active",
      "online": true,
      "revocationEpoch": 0,
      "createdAt": "…",
      "lastSeenAt": "…"
    }
  ]
}
```

`endpoint` prefers the MagicDNS name and falls back to the Tailscale IP, with IPv6 in brackets. It is plain `http` because WireGuard already encrypts the hop. Revoked devices are included with `status: "revoked"`, `endpoint: null`, and `online: false`. `tailscale.ip` and `tailscale.magicDnsName` may each be `null`. `revokedAt` is `null` unless the device is revoked.

`GET /v1/devices/:deviceId` returns a single device object of the same shape (not wrapped).

### Mint a connect token

`POST /v1/devices/:deviceId/connect-tokens` — client token or web session.

```json
{ "scopes": ["orchestration:write"] }
```

`scopes` defaults to `["orchestration:read"]`. Requesting a scope the client token lacks returns `403 {"error":"insufficient_scope"}`. A revoked device returns `409 {"error":"device_revoked"}`. An unknown or foreign device returns `404`.

Response `201`:

```json
{
  "token": "<JWT>",
  "tokenType": "Bearer",
  "scope": "orchestration:read orchestration:write",
  "expiresIn": 300,
  "expiresAt": "…",
  "deviceId": "dev_…",
  "endpoint": "http://mac-mini.tailnet-abc.ts.net:7420"
}
```

### Revoke

`POST /v1/devices/:deviceId/revoke` — owner's client token or web session. Sets `status` to `revoked`, increments `revocationEpoch`, and invalidates the device credential. Returns the updated device as a bare device object (not wrapped).

## Connect tokens

Compact JWS with this header:

```json
{ "alg": "EdDSA", "typ": "JWT", "kid": "<key id>" }
```

Claims:

| Claim | Type | Meaning |
| --- | --- | --- |
| `iss` | string | Control-plane issuer (base URL) |
| `sub` | string | User ID (`usr_…`) |
| `aud` | string | Exactly one device ID (`dev_…`) |
| `iat`, `nbf`, `exp` | integer seconds | `nbf = iat`, `exp = iat + 300` |
| `jti` | string | Unique token ID (`ctk_…`) |
| `scope` | string | Space-separated scopes. `orchestration:write` is always issued with `orchestration:read`. |
| `t3cp_epoch` | integer | Device revocation epoch when the token was issued |
| `t3cp_ver` | integer | Protocol version, `1` |

Public keys are published at `GET /.well-known/jwks.json` as RFC 8037 OKP keys:

```json
{ "keys": [ { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "…", "alg": "EdDSA", "use": "sig" } ] }
```

`kid` is the RFC 7638 JWK thumbprint (base64url SHA-256 of `{"crv":"Ed25519","kty":"OKP","x":"…"}`). During key rotation, retired public keys stay in the JWKS until tokens signed with them have expired.

### Device-side verification (normative)

A device accepts a connect token only if **all** of the following hold:

1. The token has three base64url segments. The header decodes to JSON with `alg == "EdDSA"` (anything else, including `none`, is rejected), `typ == "JWT"` when present, and a `kid`.
2. `kid` matches an `OKP`/`Ed25519` key in the JWKS cached from `jwksUri`. On an unknown `kid`, the device may refetch the JWKS at most once per 60 s, then rejects.
3. The Ed25519 signature verifies over the ASCII bytes `<header segment>.<payload segment>`.
4. `iss` equals the issuer stored at pairing.
5. `aud` equals the device's own ID. If `aud` is an array, it must contain exactly that one ID.
6. `exp > now − 30` and `nbf ≤ now + 30` (30 s leeway), and `exp − iat ≤ 900`.
7. `t3cp_ver == 1`.
8. `t3cp_epoch ≥` the device's stored revocation epoch.
9. The device has not been told it is revoked (`403 device_revoked` from heartbeat).
10. The scope covers the operation: read operations need `orchestration:read` or `orchestration:write`, and write operations need `orchestration:write`.

Failures return `401` (steps 1–9) or `403` (step 10) from the device API, with the same error body shape. Suggested codes: `invalid_token`, `token_expired`, `wrong_audience`, `stale_epoch`, `device_revoked`, `insufficient_scope`.

Further rules, so every port returns identical results:

- **Precedence.** Checks run in the order above, and the first failing step decides the error code. For example, a wrong `aud` together with a missing `exp` yields `wrong_audience`.
- **Types.** `kid` must be a string. `typ`, if present, must be the string `"JWT"`; `null` is rejected. `iat`, `nbf`, `exp`, `t3cp_epoch`, and `t3cp_ver` must be integral JSON numbers within ±(2^53 − 1); a missing or ill-typed time claim is `invalid_token`. A `scope` that is missing or not a string counts as no scopes, giving `insufficient_scope` at step 10.
- **Encoding.** Segments must be unpadded base64url. Implementations may reject non-canonical encodings, such as a length of 4n+1.
- **No `iat` ordering.** `nbf == iat` holds for issued tokens, but verifiers don't check `iat` beyond the lifetime bound.
- **Informational claims.** `sub` and `jti` are always issued, but they are for audit and logging. Verifiers must not reject a token because they are missing.
- **JWKS entries.** Keys are matched on `kid`, `kty == "OKP"`, and `crv == "Ed25519"` only; `alg` and `use` are advisory. Entries that can't be parsed are skipped individually, not the whole set. Implementations may use strict Ed25519 verification that rejects small-order keys or points.
- **Heartbeat status.** A `200` heartbeat with any `status` other than `"active"` is treated as revoked.
- **Polling.** Clients use `interval` (default 5 s when missing or 0) and stop locally once `expiresAt` has passed.

The device API accepts the token as `Authorization: Bearer <JWT>` on HTTP and on the WebSocket upgrade request. The token is checked when a connection is established. A long-lived WebSocket should be closed when the token's `exp` passes, unless the client re-authenticates on the open socket with a fresh token.

### Operation scopes for the orchestrator MCP surface

g0code and r4code expose the same MCP tool names:

| Scope | Tools |
| --- | --- |
| `orchestration:read` | `orchestrator_capabilities`, `t3_thread_list`, `t3_thread_read`, `t3_thread_wait`, `task_status` |
| `orchestration:write` | `create_threads`, `delegate_task`, `task_cancel`, `t3_thread_send`, `t3_thread_interrupt`, `t3_pending_request` |

`initialize`, `ping`, `tools/list`, and every `notifications/*` message (including `notifications/initialized` and `notifications/cancelled`) need only a valid token, so read-only clients can finish the MCP handshake. `tools/call` uses the table above, and unknown tools need `orchestration:write`. Any other JSON-RPC method also needs `orchestration:write`.

## Test vectors

`protocol/test-vectors.json` is generated by `npm run vectors` from the same code the server uses. It contains:

- `codeNormalization`: input → normalized code, or `null` if invalid.
- `fingerprint`: public key → fingerprint.
- `pairingExchange`: a fixed device seed, the resulting public key, the signed message, and the deterministic Ed25519 signature.
- `connectTokens`: a fixed signing key and JWKS, verification context (`issuer`, `deviceId`, `revocationEpoch`, `now`), and tokens with expected outcomes (`valid` + scopes, or an error code).

The keys in the vectors are public test keys. Never use them in a deployment.
