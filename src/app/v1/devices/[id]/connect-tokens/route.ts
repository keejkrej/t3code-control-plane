import { authenticate } from "@/lib/auth";
import { handler, json, parseBody } from "@/lib/http";
import type { IdContext } from "@/lib/routes";
import { connectTokenRequestSchema } from "@/lib/validation";
import { mintConnectToken } from "@/services/devices";

export const POST = handler(async (request: Request, ctx: IdContext) => {
  const { id } = await ctx.params;
  const principal = await authenticate(request, { mutation: true });
  const body = await parseBody(request, connectTokenRequestSchema);
  return json(await mintConnectToken(principal, id, body.scopes), 201);
});
