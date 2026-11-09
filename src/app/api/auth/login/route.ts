import { handler } from "@/lib/http";
import { beginLogin } from "@/services/oauth";

export const GET = handler(async (request: Request) => {
  const { location, cookie } = await beginLogin(new URL(request.url).searchParams.get("returnTo"));
  return new Response(null, { status: 302, headers: { Location: location, "Set-Cookie": cookie, "Cache-Control": "no-store" } });
});
