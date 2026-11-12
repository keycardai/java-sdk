## v0.1.0 (2026-11-12)


- build: ship the LICENSE text in every jar
- MIT's one condition is that the notice travels with every copy; the POM only names the license.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(oauth): percent-encode the client id and secret in Basic auth
- RFC 6749 section 2.3.1 encodes each half before joining them, and
svc-sts decodes them that way (ID-715). Sent raw, a client id such as
urn:app:billing was split at its first colon and refused with
invalid_client; checked live against the sandbox zone with a throwaway
password credential (raw 401, encoded 200). Spaces become %20, never +,
since the server decodes %XX only.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(spring): answer another auth scheme with invalid_token in the challenge
- A protected path reached with an Authorization header in a scheme other
than Bearer now gets error="invalid_token" in its challenge, matching the
servlet filter. The check lives in the entry point, not the token
resolver: Spring runs the resolver on every request, so rejecting there
would refuse permitAll paths and break chains that also use httpBasic().
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(a2a): put the build() and endpointFrom javadoc back on their methods
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(a2a,spiffe): keep delegated tokens on the target's origin, harden SVID lifecycle
- - DelegationClient refuses a card whose JSON-RPC endpoint is on another
  origin than the target, before any exchange, unless the origin is
  listed with trustedEndpointOrigins. A card endpoint that isn't an
  absolute http(s) URL is an A2aDiscoveryException, also before the
  exchange.
- A JSON null card or reply is a typed error, and a JSON-RPC error in a
  non-2xx reply is kept on the A2aInvocationException.
- 0.3 results (the message or task itself, tagged with kind) are wrapped
  in the 1.0 shape so message(), task() and text() work for both.
- SpiffeJwtSvidSource: a closed source the wrapper opened refuses to
  fetch instead of reconnecting; close() no longer waits on a connection
  attempt; an unchecked failure from the SVID source is a typed,
  non-retryable error; sub-second init timeouts round up, since
  java-spiffe waits in whole seconds.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(mcp,spring): tighten challenges, CSRF and filter mapping
- - Remove the cookie-less CSRF carve-out from KeycardResourceServer: it
  also switched CSRF off for Basic and form sign-in. The starter's default
  chain disables CSRF and sessions instead, and the README and javadoc say
  when an application chain should do the same.
- Challenges take X-Forwarded-Proto only when it's http or https and Host
  only when it's a plain host and port, and the metadata URL carries the
  context path.
- invalid_token descriptions are fixed text in the servlet filter and the
  Spring decoder, so a challenge never names the expected issuer or
  audiences.
- RequireBearerAuthFilter.build() refuses a multi-zone verifier without a
  zone resolver, per the multi-zone spec's fail-closed inbound rule.
- The bearer filter recognizes a request it already verified and only
  checks its own scopes; the grant filter exchanges only resources not
  already in the AccessContext. The README and example map both to
  /mcp/* for REQUEST, FORWARD and INCLUDE.
- keycard-mcp's POM lists the Servlet API as provided, not compile.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(oauth): keep secrets out of logs and harden the loopback flow and key storage
- - TransportRequest and TransportResponse toString name header keys and
  body sizes only; JdkHttpTransport no longer quotes a refused header.
- complete() checks state before reporting an error redirect.
- The loopback server binds 127.0.0.1, answers 404 to callbacks with the
  wrong path, method or state, and stops with a one-second grace.
- FileKeyStorage writes keys owner-only from creation via a temp file and
  hard link, keeps the first key stored under an id, validates key ids as
  plain file names, and searches ./mcp_keys only for the default dir.
- WebIdentity reloads after storing so racing processes share one key.
- AuthorizationCodeClient takes the authorize client id from WebIdentity.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(oauth): harden discovery, JWKS and verification against hostile input
- From the pre-release adversarial review:
- A JSON null body is a typed error in discovery, the keyring, the
  token endpoint and UserInfo, not a NullPointerException.
- The keyring parses the key set entry by entry and skips malformed or
  unusable keys (RFC 7517 section 5), so one bad key no longer stops
  every token verifying; a duplicate kid on a non-signing key no longer
  hides the signing key.
- A missing metadata field fails that lookup and shortens the cached
  metadata's life to negative_ttl, instead of replacing it with a
  failure that broke other lookups sharing the cache.
- invalidate() and clear() can't be undone by a fetch already in
  flight; an interrupted JWKS fetch surfaces as JwksException.Fetch.
- The verifier rejects aud arrays with non-string members, accepts
  duplicate builder arguments, and turns a keyring returning null or
  throwing untyped into a typed error.
- JwtSigner rejects RSA keys under 2048 bits and non-P-256 EC keys when
  it is built, not at sign time.
- A default negative_ttl shrinks to fit a discovery TTL under a minute.
- AccessToken.expiresAt saturates at Instant.MAX; registration and
  device responses with invalid URIs or out-of-range durations are
  invalid_response; an interaction timeout is no longer retryable.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- build: release pipeline to Maven Central
- One lockstep version, owned by commitizen in .cz.toml and
gradle.properties (0.1.0, ready for the first tag). scripts/
bump_package.py is ruby-sdk's bump flow with the v<version> tag scheme:
a signed bump commit through the release app, a PR merged once green,
and the tag at the squash SHA. scripts/changelog.py detects unreleased
changes, resolves tags and fails CI on version drift; both are unit
tested (33 tests, in CI).
- main.yml bumps after merges once a v* tag exists (v0.1.0 is tagged by
hand, so the first automated bump doesn't skip to 0.2.0) and only when
the release app is configured. release.yml checks the tag against
gradle.properties, refuses to run without signing secrets, publishes
and releases through the Central Portal, and waits for keycard-bom to
resolve. docs/releasing.md covers the path, settings, key custody and
rotation, the first release, and recovery.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): WebIdentity, client registration and credential discovery
- WebIdentity signs private_key_jwt assertions (RFC 7523) with an RSA-2048
key it generates on first use and keeps through KeyStorage; the default
FileKeyStorage writes <dir>/<kid>.pem at 0600 under ./server_keys, the
Python and Ruby layout, and reads PKCS#1 and the legacy ./mcp_keys too.
Assertions sign iss = sub = the client id (the exchange's resource
client id when present), aud = the URL the request goes to, a fresh
jti, and a 300 second lifetime. It implements client authentication, so
the device grant and refresh accept it. TokenExchangeContext now carries
the discovered token endpoint for assertion audiences.
- ClientRegistrationClient registers clients (RFC 7591) at the discovered
registration_endpoint, with an optional initial access token; the
metadata errors are never retryable.
- CredentialDiscovery.discover(env) builds ClientSecret, WorkloadIdentity
or WebIdentity from the canonical KEYCARD_* variables and fails with a
typed CredentialDiscoveryException (absent, ambiguous, incomplete,
unknown_type, not_satisfiable) instead of guessing.
- Ports the three Testing tables, plus device row 22 with the real
WebIdentity.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(spring): Spring AI MCP example; skip CSRF on cookie-less requests
- examples/mcp-server-spring-ai runs a Spring AI 2.0 WebMVC MCP server
behind the starter. Its transport's context extractor carries Spring
Security's verified Jwt to tool handlers, and the downstream tool
exchanges through the starter's AuthProvider. bin/selftest (in CI)
drives it with the MCP SDK client against a stub zone; bin/live-e2e
passed against the sandbox zone (ledger token with the engine in act,
invalid_target for an unregistered resource). The README walks the
FRAMEWORK-INTEGRATIONS checklist.
- The example caught a starter bug: Spring's CSRF filter answered an
unauthenticated POST with 403 before the bearer entry point could send
the 401 challenge. KeycardResourceServer now tells an existing CSRF
configurer to ignore requests with no Cookie header, which can't be
cross-site forgeries; cookie requests keep CSRF, and a chain that
disabled it stays disabled. A starter test covers all three cases.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(spring): Spring Boot starter on Spring Security's resource server
- keycard-spring-boot-starter auto-configures, once keycard.zone-url is
set: an AuthProvider for the zone; KeycardJwtDecoder, Keycard's
TokenVerifier behind Spring Security's JwtDecoder; KeycardResourceServer,
a SecurityFilterChain configurer applied to a default chain when the app
defines none; and @KeycardGrant with AccessContext handler parameters in
Spring MVC.
- The configurer keeps Spring's own pieces where they meet the bearer
contract (RFC 6750 challenges with resource_metadata, 403
insufficient_scope, RFC 9728 metadata with path insertion) and adds what
they don't: 400 invalid_request for a malformed header, 503
temporarily_unavailable with no challenge when the zone's keys can't be
fetched (Spring would rethrow into a 500), and the zone's RFC 8414
metadata proxied ahead of authorization. Every bean backs off to an
application-defined one. The POM pins Spring versions without importing
a BOM.
- keycard-mcp: AuthProvider.exchangeInto for integrations that verify the
caller themselves.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(a2a): delegation client and service discovery
- keycard-a2a gains ServiceDiscovery (agent card fetch, 15 minute cache
per base URL) and DelegationClient (discover, RFC 8693 exchange with
the agent's credential, JSON-RPC SendMessage under A2A-Version 1.0).
The 0.3 opt-in switches method, header, roles, part shape and the
preferred card interface together; an unknown generation fails at
build. Constants match Go and Ruby. Ports the a2a-delegation unit
table.
- examples/a2a-delegation runs agent A on keycard-a2a and agent B on the
official a2a-java 1.5.1 codec behind keycard-mcp's bearer filter.
bin/selftest (in CI) checks against a stub zone that performs a real
exchange: B verifies the user as sub, aud as B, and agent A in act.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): device authorization grant
- DeviceAuthorizationClient runs RFC 8628 from the device: request device
authorization, poll once, and poll until done. Client authentication is
a credential's operation called per request with that request's
endpoint, or a public client_id. The loop waits the interval before
each poll, adds 5 seconds on slow_down, stops at expires_at with
expired_token, and on a network error, 5xx or 429 stops with a
DevicePollException exposing the interval to resume with (doubled
after a network error). Cancellation is thread interruption.
- Ports the 28-row Testing table. engine-obo gains bin/device-e2e; the
headless integration rows (invalid_target, invalid_grant from another
client) pass against the sandbox zone.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- fix(spiffe): raise the Guava floor to 33.7.2
- java-spiffe-core reaches Guava 33.5.0 through gRPC, which is inside
GHSA-xxph-c9ww-hj94. Declared as a direct runtime dependency so the
published POM carries it and Maven consumers resolve the patched
version, not only Gradle ones.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(mcp): AuthProvider and grant filter
- AuthProvider holds the zone and application credential, builds the
inbound TokenVerifier, and hands out GrantFilter instances that
exchange the verified caller's token for one token per resource before
the handler runs. Ports the grant-decorator Unit Tests table: fail-fast
401 without a verified token, per-resource errors recorded on the
AccessContext, stacked grants merged, substitute-user impersonation via
withUserIdentifier, and request scopes per grant or per resource.
- A multi-zone ClientSecret makes the provider multi-zone; a grant
exchanges at the zone that issued the caller's token. Adds
ClientSecret.zones() and a scoped TokenExchangeClient.exchangeToken
overload.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): authorization code with PKCE, refresh and UserInfo
- SDK-47. Ported from authorization-code-pkce.md (spec-version 4, with
the credential refresh from base spec-version 5) and userinfo.md at
keycard-sdk-spec 16cbef2.
- - Pkce: 43-character S256 verifiers from SecureRandom, plain allowed,
  toString never prints the verifier.
- AuthorizationCodeClient: buildAuthorizeUrl (one resource parameter
  per entry), exchangeCode, the web-app begin and complete pair (CSRF
  state compared in constant time, callback errors and a missing code
  rejected before any token request), refresh (invalid_grant treated
  as permanent there, as the spec requires), and a loopback
  authenticate on 127.0.0.1 with an injectable BrowserOpener and an
  InteractionTimeoutException. Public, confidential (Basic) or
  credential client authentication; a credential with a client id or
  secret is a configuration error.
- UserInfoClient: Bearer GET, all claims kept, 401 parsed into a typed
  invalid_token, no userinfo_endpoint a configuration error before any
  request, application/jwt refused by name.
- StubZone now advertises authorization and userinfo endpoints.
- 208 tests: authorization-code rows 1 to 16 (row 13 has no Java
counterpart), userinfo rows 1 to 6, and the loopback round trip with a
simulated browser.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(mcp): servlet bearer filter, OAuth metadata servlets and route gating
- SDK-58. Ported from bearer-token-verification-middleware.md
(spec-version 3), oauth-metadata-endpoints.md and
route-level-auth-gating.md at keycard-sdk-spec 16cbef2, on Jakarta
Servlet 6.0 (compile-only; the container supplies it).
- - RequireBearerAuthFilter: 401 with a resource_metadata challenge for no
  header, 400 for a malformed one, 401 invalid_token for another scheme
  or a failed token (a kid missing from a loaded JWKS included), 403
  insufficient_scope, and 503 temporarily_unavailable with no challenge
  when the zone's keys or metadata can't be fetched. Optional
  ZoneResolver pins each request to one zone and fails closed.
- RequireScopesFilter gates a route on the verified token; stacked gates
  require the union.
- ProtectedResourceMetadataServlet: RFC 9728 document, resource from the
  request origin (X-Forwarded-Proto, Host) and RFC 9728 path insertion,
  authorization_servers [issuer] regardless of MCP-Protocol-Version.
- AuthorizationServerMetadataServlet proxies the zone's RFC 8414
  document unmodified, 502 on an upstream failure; JwksServlet serves
  only the public half of a key set. CORS on all three.
- KeycardRequest reads the AccessToken and AccessContext attributes.
- 25 tests on embedded Jetty 12.1.14 (test only): middleware rows 1 to
11, metadata rows 1 to 6, gating rows 1 to 5. 189 total.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): TokenVerifier, AccessContext and multi-zone routing
- SDK-55. Ported from access-context.md and multi-zone-support.md at
keycard-sdk-spec 16cbef2, with ruby-sdk's TokenVerifier as the shape
reference.
- - TokenVerifier: verifyToken against every trusted zone,
  verifyTokenForZone pinned to one (an untrusted zone fails closed
  before any key lookup), clearCache. One System.Logger warning when no
  audience is configured.
- AccessToken: the verified token with subject, subjectProfile,
  keycardAppId, clientId, issuer, audiences, scopes and expiresAt; the
  javadoc says which identity question each answers.
- AccessContext: access(resource) throws ResourceAccessException with
  GLOBAL_ERROR, RESOURCE_ERROR or MISSING_TOKEN; every other reader is
  non-throwing (Optional getters, Status enum); setToken and
  setResourceError replace each other.
- TokenExchangeClient.forZone(issuer): a client for another zone sharing
  the credential and the issuer-keyed caches; a per-zone ClientSecret
  without that zone fails closed before sending.
- 164 tests, including access-context rows 1 to 16 and multi-zone rows 1
to 6 against two stub zones with separate keys.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): JWT signing and verification, and JWKS caching
- SDK-46. Ported from jwt-signing-and-verification.md (spec-version 1)
and jwks-caching.md (spec-version 4, with the SDK-93 cooldown) at
keycard-sdk-spec 16cbef2.
- - JwtVerifier runs the spec's fail-closed order: structure, alg
  allowlist (RS256 default, ES256 available, none always rejected),
  trusted issuer, the RFC 9068 claim set, exp and nbf with zero default
  skew, audience, kid, then key resolution and the signature. An
  untrusted iss never reaches the keyring.
- JwksKeyring: jwks_uri from the shared metadata cache and required to
  share the issuer's origin; the last key set per jwks_uri kept for
  key_ttl; an unknown kid refetches at most once per 30 second
  cooldown; one in-flight fetch per jwks_uri; 256-entry key cache;
  invalidate and clear drop the set and any in-flight fetch.
- InvalidTokenException for every rejection, including a kid the JWKS
  lacks. JwksException.Discovery, UriValidation and Fetch pass through
  the verifier so the servlet filter can answer 503 for an outage.
- JwtSigner signs claims verbatim with header {alg, kid}, alg from the
  key type, and adds the key's issuer only when iss is absent.
- SingleFlight, extracted from the metadata cache and shared with the
  keyring, keeps an interrupted fetch from poisoning its waiters.
- 148 tests: JWT rows 1 to 16 and JWKS rows 1 to 19.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(spiffe): JWT-SVID token source over the SPIFFE Workload API
- SDK-50. keycard-spiffe now holds SpiffeJwtSvidSource, an
IdentityTokenSource backed by io.spiffe:java-spiffe-core 0.8.17, for
use as a WorkloadIdentity client assertion, a token-exchange actor, or
both, which is BNY's engine flow.
- - Required audience, optional SPIFFE ID and socket path (java-spiffe
  falls back to SPIFFE_ENDPOINT_SOCKET), 10 second init timeout.
- Connects on first fetch, not at construction; close() releases the
  connection it opened and leaves an injected JwtSvidSource alone.
- Failures are WorkloadIdentity*Exception with source "spiffe". An
  agent that can't be reached or can't issue an SVID is retryable, via
  a new WorkloadIdentityRuntimeException constructor taking an explicit
  classification.
- The gRPC transport stays the application's choice
  (io.spiffe:grpc-netty-linux, -macos or -macos-aarch64), noted in the
  module build and the class docs.
- 7 tests with a fake JwtSvidSource issuing real ES256 SVIDs, including
the SVID as both client assertion and actor on one exchange. 115 total.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): token exchange with actor tokens, and impersonation
- SDK-49. Ported from token-exchange.md (spec-version 4) and
impersonation.md at keycard-sdk-spec 16cbef2. The actor-source surface
follows svc-sts #664 and is proposed for the spec separately.
- - TokenExchangeClient.exchangeToken(subjectToken, resource) builds the
  request through the credential; exchangeToken(request) sends one as
  given. Client authentication comes from the request's
  client_assertion when present, else the credential's
  ClientAuthenticator.
- actor(IdentityTokenSource): the actor's JWT is fetched on every
  exchange and sent as actor_token with type
  urn:ietf:params:oauth:token-type:jwt, unless the request sets its own.
  svc-sts verifies it like a workload-identity client assertion and
  nests it in the issued token's act claim.
- impersonate(user, resource[, scope]): an unsigned substitute-user
  token, the substitute-user type, resource required, and never an actor
  token, since the zone rejects actor tokens on impersonation.
- 108 tests: token-exchange rows 1 to 21, impersonation rows 1 to 6, and
three for the actor source.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): WorkloadIdentity with file and GCP metadata token sources
- SDK-45. Ported from workload-identity.md (spec-version 2) and the
file-path contract in eks-workload-identity.md, at keycard-sdk-spec
16cbef2, with go-sdk oauth/token_sources.go as the reference.
- - IdentityTokenSource, a functional interface, so a lambda is a source.
- WorkloadIdentity: the source's token as a jwt-bearer client_assertion
  on every request, never cached or parsed, client_id when configured.
  Implements ClientAuthenticator with form fields only.
- FileTokenSource: explicit path, else envVarName, then the four
  discovery variables in spec order; validated at construction, re-read
  and trimmed on every call. The environment map is injectable.
- GcpMetadataTokenSource: identity endpoint with audience, format=full
  and Metadata-Flavor: Google, 5 second default timeout.
- WorkloadIdentityConfigurationException and
  WorkloadIdentityRuntimeException carry the source identifier and
  cause. A runtime failure is retryable when its cause is (a metadata
  server that can't be reached), and a lambda's own exception is
  wrapped with the identifier custom.
- No FlyTokenSource (rows 9) and no EKS aliases (row 10), as the plan
scopes out. 82 tests.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): ClientSecret and the client credentials grant
- SDK-44. Ported from client-credentials.md (spec-version 4),
client-secret.md (spec-version 2) and base.md's credential operations
(spec-version 5) at keycard-sdk-spec 16cbef2.
- - Credential, with the one required operation
  prepareTokenExchangeRequest, and ClientAuthenticator as the separate
  client-authentication capability. An operation that needs client
  authentication rejects a credential without it at build time.
- ClientSecret: single pair or perZone(Map<URI, ClientSecret>), Basic
  header only, fails closed for an unknown zone before any request,
  never prints a secret.
- ClientCredentialsClient: discovered token endpoint through the shared
  metadata cache, scope, resource and a caller-supplied assertion,
  every request bounded by fetchTimeout.
- AuthorizationServerMetadataCache.tokenEndpoint: metadata without a
  token_endpoint is remembered for negative_ttl only.
- TokenExchangeRequest, TokenExchangeContext and TokenResponse, shared
  with token exchange (SDK-49). OAuth error bodies become
  OAuthErrorException; a 2xx without access_token is a retryable
  invalid_response.
- 69 tests: the client-secret table (rows 1 to 7) and the
client-credentials table (rows 1 to 12).
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
- feat(oauth): transport, errors and discovery
- SDK-41. The first slice of keycard-oauth, ported from base.md
(spec-version 5) and authorization-server-discovery.md (spec-version 3)
at keycard-sdk-spec 16cbef2.
- - KeycardException hierarchy with a final retryable() computed at
  construction, per base.md's Retryability table, and the exported
  OAuthErrorCodes.PERMANENT set.
- KeycardHttpTransport over java.net.http, injectable or built from a
  caller's HttpClient. Every request carries a timeout (default 10
  seconds) that bounds the whole exchange, body included.
- AuthorizationServerDiscovery: one fetch, RFC 8414 path insertion,
  issuer validation, typed userinfo, end_session and
  device_authorization endpoints, unknown fields kept in raw().
- AuthorizationServerMetadataCache: discovery_ttl, deterministic
  failures held for negative_ttl, transient failures never recorded, one
  shared in-flight fetch per issuer that a fetching thread's interrupt
  doesn't poison.
- 43 tests, including the discovery Unit Tests table and base.md's
retryability, metadata-caching and bounded-request rules.
- Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
