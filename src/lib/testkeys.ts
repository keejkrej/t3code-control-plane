import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";

/** Deterministic Ed25519 key from a 32-byte seed, for tests and test vectors only. */
export function ed25519FromSeed(seed: Buffer) {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  // PKCS#8 prefix for an Ed25519 private key followed by the raw seed.
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const publicJwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return {
    privateKey,
    seed: seed.toString("base64url"),
    publicKey: publicJwk.x,
    privateJwk: { kty: "OKP" as const, crv: "Ed25519" as const, x: publicJwk.x, d: seed.toString("base64url") },
    sign: (message: string | Buffer) =>
      sign(null, typeof message === "string" ? Buffer.from(message, "utf8") : message, privateKey).toString("base64url"),
  };
}

export function seedFrom(label: string): Buffer {
  return createHash("sha256").update(label).digest();
}

const b64json = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** Builds a compact JWS with an arbitrary header/payload, signed by `signer` (or unsigned when null). */
export function craftJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signer: { sign: (m: Buffer) => string } | null,
): string {
  const input = `${b64json(header)}.${b64json(payload)}`;
  return `${input}.${signer ? signer.sign(Buffer.from(input, "ascii")) : ""}`;
}
