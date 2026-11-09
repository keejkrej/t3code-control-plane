import { handler, json, parseBody } from "@/lib/http";
import { createPairingSchema } from "@/lib/validation";
import { createPairing } from "@/services/pairing";

export const POST = handler(async (request: Request) => {
  const body = await parseBody(request, createPairingSchema);
  return json(await createPairing(body), 201);
});
