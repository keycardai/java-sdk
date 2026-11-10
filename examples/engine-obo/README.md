# engine-obo

BNY's engine flow, end to end against a live Keycard zone: a user signs in, and an engine
authenticated by a SPIFFE JWT-SVID exchanges the user's token for a token to a downstream
resource, with the engine recorded as the actor.

Two paths, both checked by `bin/live-e2e`:

1. The SVID as the client assertion only, through a v2 token credential (`client_id` set). The
   zone names the authenticated engine in `act`.
2. The SVID as the client assertion and as the RFC 8693 actor token. The actor token is matched
   against a v1 token credential (by issuer and subject); v2 credentials can't be actors today.

For a single hop both produce the same token. The actor token matters when an earlier actor in
the chain must stay visible, which the optional second hop shows: when the zone also has a
gateway application (its own SPIFFE ID, resource and credentials, depending on the downstream
resource), the engine's token is exchanged again by the gateway.

3. With an actor token on both hops, `act` nests: the gateway, over the engine.
4. Without an actor token on the gateway's hop, the zone replaces the chain with the gateway and
   the engine drops out.

## Running it

Needs a zone provisioned with an engine application (v1 and v2 token credentials trusting your
SPIRE issuer, owning both resources, depending on the downstream one), a public CLI application
with the redirect URI `http://127.0.0.1:8765/callback`, and policy letting the user reach both
resources. `LIVE_DIR` holds `state.json` with `cli_client_id` and `engine_v2_client_id` (and
`gateway_v2_client_id` for the second hop); the
user's token and the SVID are written there too, readable only by the owner.

```sh
export KEYCARD_ZONE_URL=https://<zone-id>.keycard.cloud LIVE_DIR=/path/outside/the/repo
bin/sign-in      # opens the browser, stores the user's access token
bin/live-e2e     # mints a JWT-SVID from the SPIRE server container, runs both paths
bin/live-e2e-workload-api   # same paths, SVID from a SPIRE agent over the Workload API
```

`bin/live-e2e` reads the SVID from a file, the way spiffe-helper delivers it, through
`FileTokenSource`. `bin/live-e2e-workload-api` starts a SPIRE agent joined to the server
container, registers the workload by `unix:uid:0`, and runs the same code in a JDK container
that shares the agent's PID namespace, fetching SVIDs with `SpiffeJwtSvidSource`.

Output names claims only, never a token.
