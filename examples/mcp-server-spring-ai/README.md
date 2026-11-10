# mcp-server-spring-ai

An MCP server on Spring AI 2.0's WebMVC starter (Streamable HTTP, MCP Java SDK 2.1.0) protected by
`keycard-spring-boot-starter`. It's the Spring counterpart of
[mcp-server-servlet](../mcp-server-servlet): the starter puts Spring Security's own OAuth2 resource
server in front of `/mcp`, with Keycard's verifier, challenges and metadata.

The app adds two beans on top of the starter:

- Spring AI's transport, built with a context extractor that copies Spring Security's verified
  `Jwt` into the MCP transport context, where tool handlers read it.
- Two tools. `whoami` reports the caller. `downstream` exchanges the caller's token through the
  starter's `AuthProvider` for each resource it calls and reports the issued token's `sub`, `aud`
  and `act`, or why the exchange failed. It never prints a token.

Spring AI routes MCP through router functions rather than `@Controller` methods, so
`@KeycardGrant` doesn't reach the tools; the tool that needs downstream tokens exchanges for them
when it runs, and the other MCP messages (initialize, tools/list) cost no exchange.

## Run

```sh
export KEYCARD_ZONE_URL=https://<zone-id>.keycard.cloud
export KEYCARD_AUDIENCES=http://127.0.0.1:8766/mcp
export KEYCARD_CLIENT_ID=... KEYCARD_CLIENT_SECRET=...   # or KEYCARD_ASSERTION_FILE for a v2 workload credential
export DOWNSTREAM_RESOURCES=https://api.example.com
../../gradlew -p . run
```

Spring's relaxed binding maps the environment onto `keycard.*`; the SDK itself reads no
environment variables.

## Verify

- `bin/selftest` needs no network, and CI runs it. It starts the app against a stub zone and
  checks the contract (protected-resource metadata, the proxied authorization-server metadata,
  401 with `resource_metadata` on a bare POST), then drives both tools with the MCP SDK's client,
  with one downstream resource exchanging and one refused.
- `bin/live-e2e` runs against a live zone, reusing the [engine-obo](../engine-obo) provisioning:
  the app runs as the engine (v2 workload credential, SPIRE JWT-SVID), the signed-in user's token
  calls it, and `downstream` gets a ledger token with the engine in `act` and `invalid_target`
  for a resource registered nowhere.

## FRAMEWORK-INTEGRATIONS checklist

| Check | How the starter meets it |
| --- | --- |
| Native primitive | A `SecurityFilterChain` configurer (`http.with(keycard, ...)`), a `JwtDecoder` bean, and a Spring MVC interceptor and argument resolver. |
| No duplicated concepts | Spring's `Jwt`, `Authentication` and `SCOPE_*` authorities. The new nouns are `AccessContext` and `@KeycardGrant`, which Spring has no equivalent for. |
| Thin, decoupled attachment | Every bean backs off to an application-defined one, and the configurer applies to any chain. |
| 3 to 4 step happy path, fail-closed | Set `keycard.zone-url`; the default chain requires a verified token on every request; add `@KeycardGrant`; take an `AccessContext` parameter. |
| New capability via the framework's seam | `@KeycardGrant` on MVC handlers, scope rules through Spring's `hasAuthority("SCOPE_...")`. MCP tools on router functions exchange in the tool, through the same `AuthProvider`. |
| Signals surfaced | RFC 6750 challenges and per-resource exchange errors on the `AccessContext`; nothing is swallowed. |
| Standards-named surface | RFC 9728 metadata through Spring Security's own filter, RFC 8414 proxy, RFC 6750 challenges, RFC 8693 exchange. |
| Bearer HTTP contract | 401 with a challenge for a missing or invalid token, 400 for a malformed header, 403 `insufficient_scope`, 503 `temporarily_unavailable` with no challenge when the zone's keys can't be fetched. The starter's tests cover each. |
