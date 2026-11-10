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

## Device authorization grant

`bin/device-e2e` runs the device-authorization Integration Tests as the engine:

```sh
bin/device-e2e headless   # unknown resource is invalid_target; another client's poll is invalid_grant
bin/device-e2e confirm    # prints a user code; approve it, then it checks the tokens and a refresh
bin/device-e2e deny       # prints a user code; deny it, and the poll ends with access_denied
```

`confirm` asks for `openid` and two resources, so the zone adds its UserInfo resource and the
client needs dependencies on all three. Production zones can't show the confirmation page for a
code a v2 workload credential requested yet: the verify page looks the client up among
credentials without a provider and renders "Invalid or expired code". Until svc-sts #861 ships,
`DEVICE_CLIENT=public` runs `confirm` and `deny` as the public CLI client instead.

## Credential discovery and client registration

`bin/onboarding-e2e` discovers the engine's credential from `KEYCARD_*` variables naming the
SVID file, as a pod would carry them, and exchanges the user's token with it. It then registers
a public client through RFC 7591, and sends malformed metadata (a redirect URI that isn't a URL)
that the spec expects the zone to refuse. Each run adds registrations to the zone.

Production zones accept the malformed registration, and also register a confidential
`client_secret_basic` client with a secret, so the refusal row fails against them today.

## WebIdentity

`bin/web-identity-e2e` runs the WebIdentity Integration Tests and device row 7. The zone fetches
a public-key credential's keys from its `jwks_uri`, so the script serves only the public key set
through a temporary `cloudflared` quick tunnel, registers the credential on the engine
application for the run, and deletes it and stops the tunnel on exit. It needs `cloudflared`,
`ZONE_ID` and `ORG_ID`. The rows: an exchange with the registered key, `invalid_client` for an
unregistered key, a device authorization request, and `invalid_client` when that request's
assertion is audienced to the token endpoint.
