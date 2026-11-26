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
- Live coverage against a real zone is the `a2a-delegation-java` template in
  [keycardai/templates](https://github.com/keycardai/templates), which the weekly Template Eval
  runs: the user's token reaches the caller, the caller exchanges it for the target, and the
  target reports the user as `sub` and the caller in `act`.

The spec's integration row 2 expects a third hop to see `act` nest over the first caller.
Production zones replace the chain with the latest caller when the exchange carries no actor
token, and the A2A path sends none in any SDK, so that row isn't part of the eval
([conformance report](../../docs/conformance-report.md), finding 5).
