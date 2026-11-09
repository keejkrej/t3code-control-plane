import { handler, json, parseBody } from "@/lib/http";
import { createClientAuthorizationSchema } from "@/lib/validation";
import { createClientAuthorization } from "@/services/clients";

export const POST = handler(async (request: Request) => {
  const body = await parseBody(request, createClientAuthorizationSchema);
  return json(await createClientAuthorization(body), 201);
});
