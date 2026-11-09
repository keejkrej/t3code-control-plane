/** Detects a Postgres unique-constraint violation through driver/ORM error wrappers. */
export function isUniqueViolation(err: unknown): boolean {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && current; depth++) {
    if (typeof current === "object" && current !== null && "code" in current && (current as { code: unknown }).code === "23505") {
      return true;
    }
    current = typeof current === "object" && current !== null && "cause" in current ? (current as { cause: unknown }).cause : undefined;
  }
  return false;
}

/** Retries `fn` when it fails with a unique violation (e.g. a random user-code collision). */
export async function retryOnConflict<T>(fn: () => Promise<T>, attempts = 5): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i >= attempts || !isUniqueViolation(err)) throw err;
    }
  }
}
