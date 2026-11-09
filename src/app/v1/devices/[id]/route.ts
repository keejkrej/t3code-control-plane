import { authenticate } from "@/lib/auth";
import { handler, json } from "@/lib/http";
import type { IdContext } from "@/lib/routes";
import { getDevice } from "@/services/devices";

export const GET = handler(async (request: Request, ctx: IdContext) => {
  const { id } = await ctx.params;
  const principal = await authenticate(request);
  return json(await getDevice(principal.user.id, id));
});
