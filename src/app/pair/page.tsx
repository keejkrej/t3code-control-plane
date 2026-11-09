import { HttpError } from "@/lib/http";
import { getPairing } from "@/services/pairing";
import { currentUser, loginHref } from "../session";

export const dynamic = "force-dynamic";

type Props = { searchParams: Promise<{ code?: string }> };

export default async function PairPage({ searchParams }: Props) {
  const { code = "" } = await searchParams;
  const user = await currentUser();

  if (!code) {
    return (
      <div className="panel">
        <h1>Pair a device</h1>
        <form method="get" action="/pair" className="row">
          <input type="text" name="code" placeholder="XXXX-XXXX" autoComplete="off" required />
          <button type="submit">Continue</button>
        </form>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="panel">
        <h1>Pair a device</h1>
        <p>Sign in to review pairing request <span className="mono">{code}</span>.</p>
        <a className="button" href={loginHref(`/pair?code=${encodeURIComponent(code)}`)}>
          Sign in with Vercel
        </a>
      </div>
    );
  }

  let pairing;
  try {
    pairing = await getPairing(code, user);
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) {
      return (
        <div className="panel">
          <h1>Unknown code</h1>
          <p>Check the code shown on the device and try again.</p>
        </div>
      );
    }
    throw err;
  }

  const d = pairing.device!;
  return (
    <div className="panel">
      <h1>Pair a device</h1>
      <div className="code">{pairing.code}</div>
      <p>Check that this code and key fingerprint match what the device shows before you approve.</p>
      <dl>
        <dt>Name</dt>
        <dd>{d.name}</dd>
        <dt>Host</dt>
        <dd>
          {d.hostname} · {d.platform}/{d.arch}
        </dd>
        <dt>Client</dt>
        <dd>
          {d.client.kind} {d.client.version}
        </dd>
        <dt>Tailscale</dt>
        <dd>
          {[d.tailscale.magicDnsName, d.tailscale.ip].filter(Boolean).join(" · ")} : {d.port}
        </dd>
        <dt>Capabilities</dt>
        <dd>{d.capabilities.join(", ") || "—"}</dd>
        <dt>Key</dt>
        <dd>{d.publicKeyFingerprint}</dd>
        <dt>Status</dt>
        <dd>{pairing.status}</dd>
      </dl>
      {pairing.status === "pending" ? (
        <div className="row">
          <form method="post" action={`/v1/device-pairings/${pairing.code}/approve`} className="row">
            <input type="text" name="name" defaultValue={d.name} aria-label="Device name" />
            <button type="submit">Approve</button>
          </form>
          <form method="post" action={`/v1/device-pairings/${pairing.code}/deny`}>
            <button className="danger" type="submit">
              Deny
            </button>
          </form>
        </div>
      ) : (
        <p className="notice">
          {pairing.status === "approved" || pairing.status === "exchanged"
            ? "Approved. The device finishes pairing on its own; you can close this page."
            : `This request is ${pairing.status}.`}
        </p>
      )}
    </div>
  );
}
