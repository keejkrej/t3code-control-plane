import { createHash, createPublicKey, randomBytes, randomInt, timingSafeEqual, verify } from "node:crypto";
import { PAIRING_EXCHANGE_CONTEXT } from "./protocol";

/** Unambiguous consonant alphabet: no vowels (no accidental words), no 0/O/1/I confusion. */
export const CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
export const CODE_LENGTH = 8;

export function generateUserCode(): string {
  let code = "";
  for (let i = 0; i < CODE_LENGTH; i++) {
    code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  }
  return code;
}

/**
 * Uppercases ASCII letters, drops every character that is not an ASCII letter or digit (spaces, hyphens, …),
 * and returns the result only if exactly 8 characters remain and all are in the alphabet.
 */
export function normalizeUserCode(input: string): string | null {
  const out = input.replace(/[a-z]/g, (c) => c.toUpperCase()).replace(/[^A-Z0-9]/g, "");
  if (out.length !== CODE_LENGTH) {
    return null;
  }
  for (const ch of out) {
    if (!CODE_ALPHABET.includes(ch)) {
      return null;
    }
  }
  return out;
}

export function formatUserCode(normalized: string): string {
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

const ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"; // Crockford base32, lowercase

/** Random 128-bit identifier with a type prefix, e.g. `dev_5z…`. */
export function newId(prefix: string): string {
  const bytes = randomBytes(16);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ID_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ID_ALPHABET[(value << (5 - bits)) & 31];
  }
  return `${prefix}_${out}`;
}

/** 32 random bytes, base64url, with an optional credential prefix. */
export function newSecret(prefix = ""): string {
  return prefix + randomBytes(32).toString("base64url");
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

const B64URL = /^[A-Za-z0-9_-]+$/;

export function decodeBase64Url(value: string): Buffer | null {
  if (!B64URL.test(value)) {
    return null;
  }
  return Buffer.from(value, "base64url");
}

/** Validates a base64url raw Ed25519 public key (32 bytes). */
export function isEd25519PublicKey(value: string): boolean {
  const raw = decodeBase64Url(value);
  return raw !== null && raw.length === 32 && raw.toString("base64url") === value;
}

export function publicKeyFingerprint(publicKey: string): string {
  const raw = decodeBase64Url(publicKey);
  if (!raw) {
    throw new Error("invalid public key");
  }
  return `SHA256:${createHash("sha256").update(raw).digest("base64url")}`;
}

export function pairingExchangeMessage(normalizedCode: string, pairingId: string, timestamp: string): string {
  return [PAIRING_EXCHANGE_CONTEXT, normalizedCode, pairingId, timestamp].join("\n");
}

export function verifyEd25519(publicKey: string, message: string, signature: string): boolean {
  const sig = decodeBase64Url(signature);
  if (!sig || sig.length !== 64 || !isEd25519PublicKey(publicKey)) {
    return false;
  }
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
    return verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}
