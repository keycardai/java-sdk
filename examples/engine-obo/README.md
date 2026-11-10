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
the chain must stay visible.

## Running it

Needs a zone provisioned with an engine application (v1 and v2 token credentials trusting your
SPIRE issuer, owning both resources, depending on the downstream one), a public CLI application
with the redirect URI `http://127.0.0.1:8765/callback`, and policy letting the user reach both
resources. `LIVE_DIR` holds `state.json` with `cli_client_id` and `engine_v2_client_id`; the
user's token and the SVID are written there too, readable only by the owner.

```sh
export KEYCARD_ZONE_URL=https://<zone-id>.keycard.cloud LIVE_DIR=/path/outside/the/repo
bin/sign-in      # opens the browser, stores the user's access token
bin/live-e2e     # mints a JWT-SVID from the SPIRE server container, runs both paths
```

Output names claims only, never a token.
