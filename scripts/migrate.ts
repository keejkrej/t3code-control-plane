/**
 * Applies drizzle/ migrations to DATABASE_URL (Neon/Postgres, or `pglite:<dir>` for local dev).
 *
 *   DATABASE_URL=postgres://… npm run db:migrate
 */
import path from "node:path";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
const migrationsFolder = path.join(import.meta.dirname, "..", "drizzle");

if (url.startsWith("pglite:")) {
  const { openPglite } = await import("../src/db/pglite");
  await openPglite(url.slice("pglite:".length) || undefined);
} else {
  const { Pool } = await import("@neondatabase/serverless");
  const { drizzle } = await import("drizzle-orm/neon-serverless");
  const { migrate } = await import("drizzle-orm/neon-serverless/migrator");
  const pool = new Pool({ connectionString: url });
  await migrate(drizzle({ client: pool }), { migrationsFolder });
  await pool.end();
}
console.log("migrations applied");
