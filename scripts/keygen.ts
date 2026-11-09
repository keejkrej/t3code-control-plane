/**
 * Prints a fresh Ed25519 private JWK for CONNECT_TOKEN_SIGNING_KEY and a random SESSION_SECRET.
 *
 *   npm run keygen
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { thumbprint } from "../src/lib/tokens";

const { privateKey } = generateKeyPairSync("ed25519");
const jwk = privateKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string; d: string };
const kid = await thumbprint(jwk.x);

console.log(`# connect-token signing key (kid ${kid})`);
console.log(`CONNECT_TOKEN_SIGNING_KEY='${JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d })}'`);
console.log(`SESSION_SECRET='${randomBytes(32).toString("base64url")}'`);
console.log("");
console.log("# When rotating, append the old public part to CONNECT_TOKEN_RETIRED_KEYS until old tokens expire:");
console.log(`# CONNECT_TOKEN_RETIRED_KEYS='[{"x":"${jwk.x}"}]'`);
