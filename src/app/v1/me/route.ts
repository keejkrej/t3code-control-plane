import { authenticate, userJson } from "@/lib/auth";
import { handler, json } from "@/lib/http";

export const GET = handler(async (request: Request) => {
  const principal = await authenticate(request);
  return json({ user: userJson(principal.user), scope: principal.scopes.join(" ") });
});
