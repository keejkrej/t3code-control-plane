import { handler, json, parseBody } from "@/lib/http";
import { clientTokenRequestSchema } from "@/lib/validation";
import { exchangeClientToken } from "@/services/clients";

export const POST = handler(async (request: Request) => {
  const body = await parseBody(request, clientTokenRequestSchema);
  return json(await exchangeClientToken(body.deviceCode));
});
