import { assertSameOrigin, sessionCookie } from "@/lib/auth";
import { handler } from "@/lib/http";
import { seeOther } from "@/lib/routes";

export const POST = handler(async (request: Request) => {
  assertSameOrigin(request);
  const response = seeOther(request, "/");
  response.headers.append("Set-Cookie", sessionCookie("", 0));
  return response;
});
