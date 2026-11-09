import { handler, json } from "@/lib/http";
import { publishedJwks } from "@/lib/tokens";

export const GET = handler(async () => json(await publishedJwks(), 200, { "Cache-Control": "public, max-age=300" }));
