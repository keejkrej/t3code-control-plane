import { createSessionToken, OAUTH_COOKIE, readCookie, sessionCookie } from "@/lib/auth";
import { handler, HttpError } from "@/lib/http";
import { completeLogin } from "@/services/oauth";

export const GET = handler(async (request: Request) => {
  const params = new URL(request.url).searchParams;
  const error = params.get("error");
  if (error) throw new HttpError(400, "oauth_denied", params.get("error_description") ?? error);
  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) throw new HttpError(400, "invalid_request", "missing code or state");

  const { user, returnTo } = await completeLogin(code, state, readCookie(request, OAUTH_COOKIE));
  const headers = new Headers({ Location: new URL(returnTo, request.url).toString(), "Cache-Control": "no-store" });
  headers.append("Set-Cookie", sessionCookie(await createSessionToken(user.id)));
  headers.append("Set-Cookie", `${OAUTH_COOKIE}=; Path=/api/auth; Max-Age=0; HttpOnly; SameSite=Lax`);
  return new Response(null, { status: 303, headers });
});
