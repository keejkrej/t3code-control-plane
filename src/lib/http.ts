import { ZodError, type ZodType } from "zod";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
  }
}

export const errors = {
  badRequest: (message: string) => new HttpError(400, "invalid_request", message),
  unauthorized: (code = "unauthorized", message = "authentication required") => new HttpError(401, code, message),
  forbidden: (code = "forbidden", message = "not allowed") => new HttpError(403, code, message),
  notFound: (message = "not found") => new HttpError(404, "not_found", message),
};

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" };

export function json(body: unknown, status = 200, headers?: HeadersInit): Response {
  const h = new Headers(JSON_HEADERS);
  if (headers) {
    new Headers(headers).forEach((v, k) => h.set(k, v));
  }
  return new Response(JSON.stringify(body), { status, headers: h });
}

export function errorResponse(err: unknown): Response {
  if (err instanceof HttpError) {
    if (err.status >= 500) {
      console.error(`[control-plane] ${err.code}: ${err.message}`);
    }
    return json({ error: err.code, message: err.message }, err.status);
  }
  console.error("[control-plane] unhandled error", err);
  return json({ error: "server_error", message: "internal server error" }, 500);
}

/** Wraps a route handler so thrown `HttpError`s become protocol error bodies. */
export function handler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (err) {
      return errorResponse(err);
    }
  };
}

const MAX_BODY_BYTES = 16 * 1024;

/** Parses a JSON (or, for browser forms, urlencoded) body and validates it. Empty bodies parse as `{}`. */
export async function parseBody<T>(request: Request, schema: ZodType<T>): Promise<T> {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) {
    throw new HttpError(413, "payload_too_large", "request body too large");
  }
  let raw: unknown = {};
  const contentType = request.headers.get("content-type") ?? "";
  if (text.trim() !== "") {
    if (contentType.includes("application/x-www-form-urlencoded")) {
      raw = Object.fromEntries(new URLSearchParams(text));
    } else {
      try {
        raw = JSON.parse(text);
      } catch {
        throw errors.badRequest("body is not valid JSON");
      }
    }
  }
  try {
    return schema.parse(raw);
  } catch (err) {
    if (err instanceof ZodError) {
      const issue = err.issues[0];
      const where = issue?.path.length ? `${issue.path.join(".")}: ` : "";
      throw errors.badRequest(`${where}${issue?.message ?? "invalid body"}`);
    }
    throw err;
  }
}

export function iso(date: Date | null | undefined): string | null {
  return date ? date.toISOString() : null;
}

export function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) {
    return null;
  }
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  return match?.[1] ?? null;
}

/** True when the request was submitted by an HTML form (so we should redirect instead of returning JSON). */
export function isFormPost(request: Request): boolean {
  return (request.headers.get("content-type") ?? "").includes("application/x-www-form-urlencoded");
}
