import { authenticate } from "@/lib/auth";
import { handler, json } from "@/lib/http";
import { listDevices } from "@/services/devices";

export const GET = handler(async (request: Request) => {
  const principal = await authenticate(request);
  return json(await listDevices(principal.user.id));
});
