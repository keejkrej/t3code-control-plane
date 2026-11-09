import { handler, json, parseBody } from "@/lib/http";
import type { CodeContext } from "@/lib/routes";
import { exchangeSchema } from "@/lib/validation";
import { exchangePairing } from "@/services/pairing";

export const POST = handler(async (request: Request, ctx: CodeContext) => {
  const { code } = await ctx.params;
  const body = await parseBody(request, exchangeSchema);
  return json(await exchangePairing(code, body));
});
