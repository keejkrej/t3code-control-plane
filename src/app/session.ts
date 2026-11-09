import { cookies } from "next/headers";
import { SESSION_COOKIE, sessionUser } from "@/lib/auth";

export async function currentUser() {
  const store = await cookies();
  return sessionUser(store.get(SESSION_COOKIE)?.value);
}

export function loginHref(returnTo: string) {
  return `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
}
