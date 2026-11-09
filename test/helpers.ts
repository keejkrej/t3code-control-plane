import { generateKeyPairSync } from "node:crypto";
import { setDb } from "@/db";
import { openPglite } from "@/db/pglite";
import { createSessionToken } from "@/lib/auth";
import { upsertVercelUser } from "@/services/oauth";

export const BASE = "http://localhost:3000";

export function configureEnv() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  process.env.CONTROL_PLANE_URL = BASE;
  process.env.SESSION_SECRET = "test-session-secret-that-is-long-enough-0123456789";
  process.env.CONNECT_TOKEN_SIGNING_KEY = JSON.stringify(jwk);
  delete process.env.ALLOWED_USERS;
  delete process.env.CONNECT_TOKEN_RETIRED_KEYS;
}

export async function freshDb() {
  const db = await openPglite();
  setDb(db);
  return db;
}

export async function signIn(sub = "vercel_user_1", username = "jack") {
  const user = await upsertVercelUser({ sub, preferred_username: username, name: username, email: `${username}@example.com` });
  const cookie = `t3cp_session=${await createSessionToken(user.id)}`;
  return { user, cookie };
}

type Init = {
  method?: string;
  body?: unknown;
  form?: Record<string, string>;
  bearer?: string;
  cookie?: string;
  origin?: string | null;
};

export function req(path: string, init: Init = {}): Request {
  const headers = new Headers();
  let body: string | undefined;
  if (init.form) {
    headers.set("content-type", "application/x-www-form-urlencoded");
    body = new URLSearchParams(init.form).toString();
  } else if (init.body !== undefined) {
    headers.set("content-type", "application/json");
    body = JSON.stringify(init.body);
  }
  if (init.bearer) headers.set("authorization", `Bearer ${init.bearer}`);
  if (init.cookie) headers.set("cookie", init.cookie);
  const method = init.method ?? (body !== undefined ? "POST" : "GET");
  if (init.origin !== null && method !== "GET") headers.set("origin", init.origin ?? BASE);
  return new Request(`${BASE}${path}`, { method, headers, body });
}

export const params = <T extends Record<string, string>>(p: T) => ({ params: Promise.resolve(p) });

export async function body<T = Record<string, unknown>>(res: Response): Promise<T> {
  const text = await res.text();
  return (text ? JSON.parse(text) : {}) as T;
}
