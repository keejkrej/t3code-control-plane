/** Protocol-level constants shared by the server, tests, and test-vector generator. */

export const PROTOCOL_VERSION = 1;

export const SCOPE_READ = "orchestration:read";
export const SCOPE_WRITE = "orchestration:write";
export const SUPPORTED_SCOPES = [SCOPE_READ, SCOPE_WRITE] as const;
export type Scope = (typeof SUPPORTED_SCOPES)[number];

export const CONNECT_TOKEN_TTL_SECONDS = 300;
export const HEARTBEAT_INTERVAL_SECONDS = 60;
export const ONLINE_WINDOW_SECONDS = HEARTBEAT_INTERVAL_SECONDS * 3;
export const PAIRING_TTL_SECONDS = 600;
export const POLL_INTERVAL_SECONDS = 5;
export const EXCHANGE_CLOCK_SKEW_SECONDS = 300;
export const CLIENT_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60;
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;

export const PAIRING_EXCHANGE_CONTEXT = "t3cp-pairing-exchange-v1";
export const DEVICE_CREDENTIAL_PREFIX = "t3cpd_";
export const CLIENT_TOKEN_PREFIX = "t3cpc_";

/** Normalizes a scope request: write always implies read; result is sorted and de-duplicated. */
export function expandScopes(scopes: readonly string[]): Scope[] {
  const set = new Set<Scope>();
  for (const scope of scopes) {
    if (scope === SCOPE_WRITE) {
      set.add(SCOPE_READ);
      set.add(SCOPE_WRITE);
    } else if (scope === SCOPE_READ) {
      set.add(SCOPE_READ);
    }
  }
  return SUPPORTED_SCOPES.filter((s) => set.has(s));
}

export function isSupportedScope(scope: string): scope is Scope {
  return (SUPPORTED_SCOPES as readonly string[]).includes(scope);
}

/** MCP tools that only need `orchestration:read`; anything else needs `orchestration:write`. */
export const READ_TOOLS = [
  "orchestrator_capabilities",
  "t3_thread_list",
  "t3_thread_read",
  "t3_thread_wait",
  "task_status",
] as const;

export const WRITE_TOOLS = [
  "create_threads",
  "delegate_task",
  "task_cancel",
  "t3_thread_send",
  "t3_thread_interrupt",
  "t3_pending_request",
] as const;
