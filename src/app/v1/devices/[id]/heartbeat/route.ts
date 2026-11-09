import { bearerToken, handler, json, parseBody } from "@/lib/http";
import type { IdContext } from "@/lib/routes";
import { heartbeatSchema } from "@/lib/validation";
import { heartbeat } from "@/services/devices";

export const POST = handler(async (request: Request, ctx: IdContext) => {
  const { id } = await ctx.params;
  const body = await parseBody(request, heartbeatSchema);
  return json(await heartbeat(id, bearerToken(request), body));
});
