import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import * as schema from "./schema";

export { schema };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Db = PgDatabase<PgQueryResultHKT, typeof schema, any>;

// Cached on globalThis so dev-server hot reloads don't open a second PGlite/Neon pool.
const globalDb = globalThis as typeof globalThis & { __t3cpDb?: Promise<Db> };

/**
 * Returns the process-wide database.
 *
 * - `postgres://` / `postgresql://` URLs use the Neon serverless driver (WebSocket pool, supports transactions).
 * - `pglite:<dir>` (or `pglite:memory`) uses embedded PGlite for local development and applies migrations on start.
 */
export function getDb(): Promise<Db> {
  globalDb.__t3cpDb ??= open(process.env.DATABASE_URL).catch((err: unknown) => {
    globalDb.__t3cpDb = undefined;
    throw err;
  });
  return globalDb.__t3cpDb;
}

/** Test seam: replace the database for the current process. */
export function setDb(db: Db | undefined): void {
  globalDb.__t3cpDb = db ? Promise.resolve(db) : undefined;
}

async function open(url: string | undefined): Promise<Db> {
  if (!url) {
    throw new Error("DATABASE_URL is not configured");
  }
  if (url.startsWith("pglite:")) {
    const { openPglite } = await import("./pglite");
    const dir = url.slice("pglite:".length);
    return openPglite(dir === "memory" || dir === "" ? undefined : dir);
  }
  const { Pool } = await import("@neondatabase/serverless");
  const { drizzle } = await import("drizzle-orm/neon-serverless");
  const pool = new Pool({ connectionString: url });
  return drizzle({ client: pool, schema }) as unknown as Db;
}
