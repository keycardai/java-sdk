# a2a-delegation

Agent-to-agent delegation with `keycard-a2a`: one agent calls another on the user's behalf, and
the user stays the subject at every hop.

- Agent B speaks A2A through the official [a2a-java](https://github.com/a2aproject/a2a-java)
  SDK (1.5.1). Its card is an a2a-java `AgentCard` serialized by a2a-java, and its JSON-RPC
  endpoint parses requests and writes replies with a2a-java's own codec (`JSONRPCUtils`). The
  endpoint sits behind `keycard-mcp`'s bearer filter, audience-bound to B's own URL. B answers
  with what it verified: the token's `sub`, `aud` and `act`, checked against the zone's keys
  rather than taken from the caller.
- Agent A takes `POST /delegate` with a user's bearer token and a text body. It verifies the
  token, then calls B with `DelegationClient`: discover B's card, exchange the user's token for
  one scoped to B (RFC 8693, authenticated with A's own credential), and send the message as
  A2A 1.0 `SendMessage`.

The example doesn't run a2a-java's full server. Its request handler is wired through CDI and the
Quarkus reference app; the codec is the part that decides whether the two sides agree on the
wire, and B uses it directly in a plain servlet.

## Verify

- `bin/selftest` needs no network, and CI runs it. A stub zone performs a real exchange: it
  checks A's client authentication, keeps the user as `sub`, re-scopes `aud` to the target, and
  records A in `act`. The selftest checks B's card, the 401 on an unauthenticated call, that a
  token minted for A is refused at B, and that B verified the user, its own audience and A in
  `act` after a2a-java parsed A's message.
- `bin/live-e2e` runs the Integration Tests against a live zone. It reuses the
  [engine-obo](../engine-obo) provisioning and its signed-in user token: A runs as the engine
  and B as the gateway (v2 token credentials, JWT-SVIDs from the SPIRE server container), and B
  delegates on to a reporting agent C. B and C listen on `127.0.0.1:9601` and `:9603`, the
  identifiers of their registered resources, because the exchange's resource is the target's
  base URL.

Row 1 (B sees the user as `sub` and the engine in `act`) passes. Row 2 expects `act` on C's token
to name the gateway over the engine; production zones replace the chain with the latest caller
when the exchange carries no actor token, so C sees only the gateway. The A2A path sends no
actor token in any SDK, so row 2 fails in every SDK against a live zone today.
