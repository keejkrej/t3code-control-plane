import { listDevices } from "@/services/devices";
import { currentUser, loginHref } from "./session";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await currentUser();
  if (!user) {
    return (
      <div className="panel">
        <h1>Sign in</h1>
        <p>
          Manage the Macs and Linux machines that run g0code or r4code. This service stores device metadata and hands out
          short-lived connection tokens. Orchestration traffic goes straight to your devices over Tailscale.
        </p>
        <a className="button" href={loginHref("/")}>
          Sign in with Vercel
        </a>
      </div>
    );
  }

  const { devices } = await listDevices(user.id);
  return (
    <>
      <h1>Devices</h1>
      <p>
        To pair a device, run the daemon&apos;s pair command and open the link it prints. Desktop apps sign in from the
        app and send you to an approval page.
      </p>
      <div className="panel">
        {devices.length === 0 ? <p>No devices paired yet.</p> : null}
        {devices.map((d) => (
          <div className="device" key={d.id}>
            <div className="row spread">
              <div className="row">
                <strong>{d.name}</strong>
                <span className="badge">{d.client.kind}</span>
                {d.status === "revoked" ? (
                  <span className="badge bad">revoked</span>
                ) : (
                  <span className={`badge ${d.online ? "ok" : ""}`}>{d.online ? "online" : "offline"}</span>
                )}
              </div>
              {d.status === "active" ? (
                <form method="post" action={`/v1/devices/${d.id}/revoke`}>
                  <button className="danger" type="submit">
                    Revoke
                  </button>
                </form>
              ) : null}
            </div>
            <dl>
              <dt>Endpoint</dt>
              <dd>{d.endpoint ?? "—"}</dd>
              <dt>Host</dt>
              <dd>
                {d.hostname} · {d.platform}/{d.arch} · {d.client.kind} {d.client.version}
              </dd>
              <dt>Key</dt>
              <dd>{d.publicKeyFingerprint}</dd>
              <dt>Last seen</dt>
              <dd>{d.lastSeenAt ?? "never"}</dd>
            </dl>
          </div>
        ))}
      </div>
    </>
  );
}
