import { readCookie, SESSION_COOKIE, sessionUser } from "@/lib/auth";
import { handler, json } from "@/lib/http";
import type { CodeContext } from "@/lib/routes";
import { getClientAuthorization } from "@/services/clients";

export const GET = handler(async (request: Request, ctx: CodeContext) => {
  const { code } = await ctx.params;
  const viewer = await sessionUser(readCookie(request, SESSION_COOKIE));
  return json(await getClientAuthorization(code, viewer));
});
