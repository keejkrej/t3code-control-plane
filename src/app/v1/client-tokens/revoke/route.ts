import { authenticate } from "@/lib/auth";
import { handler } from "@/lib/http";
import { revokeClientToken } from "@/services/clients";

export const POST = handler(async (request: Request) => {
  const principal = await authenticate(request, { mutation: true });
  await revokeClientToken(principal);
  return new Response(null, { status: 204 });
});
