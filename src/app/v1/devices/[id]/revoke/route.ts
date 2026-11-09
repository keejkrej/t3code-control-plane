import { authenticate } from "@/lib/auth";
import { handler, isFormPost, json } from "@/lib/http";
import { seeOther, type IdContext } from "@/lib/routes";
import { revokeDevice } from "@/services/devices";

export const POST = handler(async (request: Request, ctx: IdContext) => {
  const { id } = await ctx.params;
  const principal = await authenticate(request, { mutation: true });
  const device = await revokeDevice(principal.user.id, id);
  return isFormPost(request) ? seeOther(request, "/") : json(device);
});
