# mcp-server-servlet

An MCP server on the official [MCP Java SDK](https://github.com/modelcontextprotocol/java-sdk)
(2.1.0, Streamable HTTP servlet transport) in embedded Jetty, protected by `keycard-mcp`. It's
the compatibility proof for the module's design: `keycard-mcp` has no MCP SDK dependency and
attaches at the servlet seam, and the SDK's transport mounts behind it untouched.

The chain on `/mcp` is `RequireBearerAuthFilter`, then the grant filter from
`AuthProvider.grant(...)`, then the transport. `KeycardTransportContext` is the transport's
`contextExtractor`: it copies the verified caller and the grant's `AccessContext` from request
attributes into the `McpTransportContext`, where tool handlers read them.

Two tools:

- `whoami` reports the verified caller's `sub` and `client_id`.
- `downstream` reports, per downstream resource, the issued token's `sub`, `aud` and `act`
  claims, or why that exchange failed. It never prints a token.

The grant runs on every request to `/mcp`, so each MCP message (initialize, tools/list,
tools/call) performs one exchange per resource. A server that only needs downstream tokens in
some tools can call `AuthProvider.exchangeTokens(...)` from those handlers instead.

## Run

```sh
export KEYCARD_ZONE_URL=https://<zone-id>.keycard.cloud
export KEYCARD_RESOURCE_ID=http://127.0.0.1:8765/mcp
export KEYCARD_CLIENT_ID=... KEYCARD_CLIENT_SECRET=...
export DOWNSTREAM_RESOURCES=https://api.example.com
../../gradlew -p . run
```

| Env var | Meaning |
| --- | --- |
| `KEYCARD_ZONE_URL` | The zone issuer URL (required) |
| `KEYCARD_RESOURCE_ID` | This server's registered resource identifier; inbound tokens must carry it as an audience (required) |
| `KEYCARD_CLIENT_ID` | The application's client id (required) |
| `KEYCARD_CLIENT_SECRET` | Its client secret, for a `ClientSecret` credential |
| `KEYCARD_ASSERTION_FILE` | Instead of a secret: a file holding a workload identity token (such as a JWT-SVID) for a v2 token credential |
| `DOWNSTREAM_RESOURCES` | Space-separated resources the grant exchanges for (required) |
| `KEYCARD_REQUIRED_SCOPES` | Space-separated scopes every caller must hold (optional) |
| `HOST`, `PORT` | Bind address, default `127.0.0.1:8765` |

Endpoints: `GET /healthz`, `GET /.well-known/oauth-protected-resource/mcp`,
`GET /.well-known/oauth-authorization-server` (proxied from the zone), and `/mcp`.

## Verify

- `bin/selftest` needs no network. It stands up a stub zone (real RSA key, discovery, JWKS and a
  token endpoint), starts this server against it, checks the HTTP contract (healthz, both
  well-knowns, the 401 challenge, the 403 `insufficient_scope`), then drives both tools with the
  MCP SDK's own client. One downstream resource exchanges and one is refused, so it also checks
  that a failed resource doesn't stop the other. CI runs it.
- `bin/live-e2e` runs the grant-decorator Integration Tests against a live zone. It reuses the
  [engine-obo](../engine-obo) provisioning and `LIVE_DIR`: the server runs as the engine
  application (v2 token credential, JWT-SVID assertion minted from the SPIRE server container),
  the user token from engine-obo's `bin/sign-in` calls it, and the grant exchanges that token
  for the ledger resource plus one resource registered nowhere. It expects a token for the
  ledger with the engine in `act`, and `invalid_target` for the other.
