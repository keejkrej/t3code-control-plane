import { HttpError } from "@/lib/http";
import { getClientAuthorization } from "@/services/clients";
import { currentUser, loginHref } from "../session";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ code?: string }> };

export default async function AuthorizePage({ searchParams }: Props) {
  const { code = "" } = await searchParams;
  const user = await currentUser();

  if (!code) {
    return (
      <div className="panel">
        <h1>Authorize an app</h1>
        <form method="get" action="/authorize" className="row">
          <input type="text" name="code" placeholder="XXXX-XXXX" autoComplete="off" required />
          <button type="submit">Continue</button>
        </form>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="panel">
        <h1>Authorize an app</h1>
        <p>Sign in to review request <span className="mono">{code}</span>.</p>
        <a className="button" href={loginHref(`/authorize?code=${encodeURIComponent(code)}`)}>
          Sign in with Vercel
        </a>
      </div>
    );
  }

  let auth;
  try {
    auth = await getClientAuthorization(code, user);
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) {
      return (
        <div className="panel">
          <h1>Unknown code</h1>
          <p>Check the code shown in the app and try again.</p>
        </div>
      );
    }
    throw err;
  }

  const canWrite = auth.scopes?.includes("orchestration:write");
  return (
    <div className="panel">
      <h1>Authorize an app</h1>
      <div className="code">{auth.userCode}</div>
      <p>
        <strong>{auth.client?.name}</strong> wants to list your devices and{" "}
        {canWrite ? "read and control orchestration on them" : "read orchestration state on them"}.
      </p>
      <dl>
        <dt>Client</dt>
        <dd>
          {auth.client?.kind} {auth.client?.version}
        </dd>
        <dt>Scopes</dt>
        <dd>{auth.scopes?.join(" ")}</dd>
        <dt>Status</dt>
        <dd>{auth.status}</dd>
      </dl>
      {auth.status === "pending" ? (
        <div className="row">
          <form method="post" action={`/v1/client-authorizations/${auth.userCode}/approve`}>
            <button type="submit">Approve</button>
          </form>
          <form method="post" action={`/v1/client-authorizations/${auth.userCode}/deny`}>
            <button className="danger" type="submit">
              Deny
            </button>
          </form>
        </div>
      ) : (
        <p className="notice">
          {auth.status === "approved" || auth.status === "exchanged"
            ? "Approved. Return to the app; you can close this page."
            : `This request is ${auth.status}.`}
        </p>
      )}
    </div>
  );
}
