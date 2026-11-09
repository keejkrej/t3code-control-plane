import type { Metadata } from "next";
import type { ReactNode } from "react";
import { currentUser } from "./session";
import "./globals.css";

export const metadata: Metadata = {
  title: "t3code control plane",
  description: "Device registry and connection authorization for g0code and r4code",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const user = await currentUser();
  return (
    <html lang="en">
      <body>
        <main>
          <header className="top">
            <a href="/">t3code control plane</a>
            {user ? (
              <div className="row">
                <span className="badge">{user.username ?? user.email ?? user.id}</span>
                <form method="post" action="/api/auth/logout">
                  <button className="secondary" type="submit">
                    Sign out
                  </button>
                </form>
              </div>
            ) : null}
          </header>
          {children}
        </main>
      </body>
    </html>
  );
}
