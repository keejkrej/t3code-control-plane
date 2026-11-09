import { requireSession } from "@/lib/auth";
import { handler, isFormPost, json, parseBody } from "@/lib/http";
import { approveSchema } from "@/lib/validation";
import { decideClientAuthorization } from "@/services/clients";
import { decidePairing } from "@/services/pairing";

export type CodeContext = { params: Promise<{ code: string }> };
export type IdContext = { params: Promise<{ id: string }> };

export function seeOther(request: Request, path: string): Response {
  return new Response(null, { status: 303, headers: { Location: new URL(path, request.url).toString() } });
}

/** Approve/deny handler shared by the device-pairing and client-authorization browser flows. */
export function decisionRoute(kind: "pairing" | "client", decision: "approve" | "deny") {
  return handler(async (request: Request, ctx: CodeContext) => {
    const { code } = await ctx.params;
    const user = await requireSession(request);
    const body = await parseBody(request, approveSchema);
    const result =
      kind === "pairing"
        ? await decidePairing(code, user, decision, body.name)
        : await decideClientAuthorization(code, user, decision);
    if (isFormPost(request)) {
      return seeOther(request, `${kind === "pairing" ? "/pair" : "/authorize"}?code=${encodeURIComponent(code)}`);
    }
    return json(result);
  });
}
