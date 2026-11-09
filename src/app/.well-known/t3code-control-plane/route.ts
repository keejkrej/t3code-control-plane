import * as config from "@/lib/config";
import { handler, json } from "@/lib/http";
import { CONNECT_TOKEN_TTL_SECONDS, HEARTBEAT_INTERVAL_SECONDS, PROTOCOL_VERSION, SUPPORTED_SCOPES } from "@/lib/protocol";

export const GET = handler(async () =>
  json(
    {
      protocolVersion: PROTOCOL_VERSION,
      issuer: config.issuer(),
      jwksUri: config.url("/.well-known/jwks.json"),
      devicePairingEndpoint: config.url("/v1/device-pairings"),
      clientAuthorizationEndpoint: config.url("/v1/client-authorizations"),
      clientTokenEndpoint: config.url("/v1/client-authorizations/token"),
      devicesEndpoint: config.url("/v1/devices"),
      scopesSupported: SUPPORTED_SCOPES,
      connectTokenTtlSeconds: CONNECT_TOKEN_TTL_SECONDS,
      heartbeatIntervalSeconds: HEARTBEAT_INTERVAL_SECONDS,
    },
    200,
    { "Cache-Control": "public, max-age=300" },
  ),
);
