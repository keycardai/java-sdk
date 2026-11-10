# Java SDK conformance report

Where the Java SDK stands against keycard-sdk-spec, as of November 10, 2026. Written by hand
from the suites in this repo; every number below is reproducible with the commands in the last
section.

## Summary

| | |
| --- | --- |
| Modules | `keycard-oauth`, `keycard-spiffe`, `keycard-mcp`, `keycard-a2a`, `keycard-spring-boot-starter` |
| Capability specs covered | 21 of 24; 2 excluded on purpose, `delegated-access/as-itself` waits on the demand-gated agent integrations |
| Unit tests | 310, in 28 suites; 25 are conformance suites mapped to spec Testing tables or the framework checklist |
| Live-zone rows | 42 passing, 5 failing on zone behavior that differs from the spec, 7 not run (listed below) |
| Example selftests | 3 in CI, with no zone: an MCP Java SDK servlet server (12 checks), a Spring AI MCP server (9), and A2A delegation with agent B on a2a-java (10) |
| Java versions | 17, 21 and 25 in CI; bytecode is `--release 17` |
| Checks | `-Xlint:all -Werror`, Javadoc `-Xdoclint:all -Werror`, Spotless (Palantir) |

Each conformance test is named for the spec row it implements (`@DisplayName("row 4: ...")`),
so a reviewer can diff a suite against its spec table. Suites carry a few extra tests beyond the
rows, such as construction errors and Java-specific edges, named without a row number.

## Coverage

### keycard-oauth

| Spec | Suite | Tests |
| --- | --- | --- |
| `base` (retryability, metadata caching, bounded requests) | `BaseRetryabilityConformanceTest`, `BaseMetadataCachingConformanceTest`, `BaseBoundedRequestsConformanceTest` | 27 |
| `oauth-client/authorization-server-discovery` | `AuthorizationServerDiscoveryConformanceTest` | 12 |
| `oauth-client/client-credentials` | `ClientCredentialsConformanceTest` | 17 |
| `oauth-client/token-exchange` | `TokenExchangeConformanceTest`, `ActorTokenSourceTest` | 21 |
| `oauth-client/authorization-code-pkce` | `AuthorizationCodePkceConformanceTest` | 14 |
| `oauth-client/userinfo` | `UserInfoConformanceTest` | 5 |
| `oauth-client/device-authorization` | `DeviceAuthorizationConformanceTest` | 28 |
| `oauth-client/dynamic-client-registration` | `DynamicClientRegistrationConformanceTest` | 6 |
| `application-credentials/client-secret` | `ClientSecretConformanceTest` | 9 |
| `application-credentials/workload-identity` | `WorkloadIdentityConformanceTest` | 13 |
| `application-credentials/web-identity` | `WebIdentityConformanceTest` | 13 |
| `application-credentials/credential-discovery` | `CredentialDiscoveryConformanceTest` | 23 |
| `jwt-jwks/jwt-signing-and-verification` | `JwtSigningAndVerificationConformanceTest` | 16 |
| `jwt-jwks/jwks-caching` | `JwksCachingConformanceTest` | 17 |
| `delegated-access/access-context` | `AccessContextConformanceTest` | 9 |
| `delegated-access/impersonation` | `ImpersonationConformanceTest` | 5 |
| `multi-zone-and-ops/multi-zone-support` | `MultiZoneSupportConformanceTest` | 7 |

### keycard-spiffe

| Spec | Suite | Tests |
| --- | --- | --- |
| `application-credentials/workload-identity` (the SPIFFE source proposed in spec#104) | `SpiffeJwtSvidSourceTest` | 7 |

### keycard-mcp

| Spec | Suite | Tests |
| --- | --- | --- |
| `server-bearer-auth/bearer-token-verification-middleware` | `BearerTokenVerificationMiddlewareConformanceTest` | 12 |
| `server-bearer-auth/oauth-metadata-endpoints` | `OAuthMetadataEndpointsConformanceTest` | 8 |
| `server-bearer-auth/route-level-auth-gating` | `RouteLevelAuthGatingConformanceTest` | 5 |
| `delegated-access/grant-decorator` | `GrantDecoratorConformanceTest` | 10 |

### keycard-a2a

| Spec | Suite | Tests |
| --- | --- | --- |
| `a2a/a2a-delegation` | `A2aDelegationConformanceTest` | 9 |

### keycard-spring-boot-starter

| Spec | Suite | Tests |
| --- | --- | --- |
| FRAMEWORK-INTEGRATIONS.md checklist (bearer contract, metadata, grant) | `KeycardStarterConformanceTest` | 13 |

## Live-zone results

`examples/live-e2e` runs every non-interactive live suite against one sandbox zone. The
interactive device rows run through `examples/engine-obo/bin/device-e2e confirm` and `deny`.
The engine application authenticates with a v2 token credential and SPIRE JWT-SVIDs unless a
row says otherwise; the subject token is a real user's, from the loopback sign-in.

| Spec | Row | Result |
| --- | --- | --- |
| authorization-server-discovery | 1: discover a live zone | pass |
| jwks-caching | 1: resolve a live `kid`, second call cached | pass |
| jwks-caching / jwt-signing-and-verification | 2: verify a real token twice from the cached key | pass |
| jwt-signing-and-verification | 1: a `private_key_jwt` assertion accepted (WebIdentity) | pass |
| token-exchange | 1: exchange a user token for a resource | pass |
| token-exchange | 2: a malformed subject token | **fail**: `invalid_request`, spec says `invalid_grant` (finding 1) |
| token-exchange | 3: an unregistered resource is `invalid_target` | pass |
| workload-identity | 1: exchange with a valid platform token (file and Workload API) | pass |
| workload-identity | 2: a wrong-audience platform token is `invalid_client` | pass |
| client-credentials | 1: the engine's own token | pass |
| client-credentials | 2: an invalid secret is `invalid_client` | pass |
| client-secret | 1 and 2: exchange with a valid and an invalid secret | pass |
| web-identity | 1: exchange with the registered key | pass |
| web-identity | 2: an unregistered key is `invalid_client` | pass |
| credential-discovery | 1: a client secret from the environment exchanges | pass |
| credential-discovery | 2: a token file from the environment exchanges | pass |
| dynamic-client-registration | 1: register a public client | pass |
| dynamic-client-registration | 2: invalid metadata is refused | **fail**: accepted (finding 4) |
| impersonation | 1: `sub` is the user, no `act` | **fail**: `act` names the impersonating app (finding 2) |
| impersonation | 2: a client without permission | **fail**: `access_denied`, spec says `unauthorized_client` (finding 3) |
| impersonation | 3: the downstream verifier sees the user | pass |
| userinfo | 2: an invalid token is `invalid_token` | pass |
| bearer-token-verification-middleware | 1: a real token through the servlet filter | pass |
| bearer-token-verification-middleware | 2: a token for another audience is refused | pass |
| oauth-metadata-endpoints | 1 and 2: RFC 9728 metadata and the RFC 8414 proxy | pass |
| access-context / grant-decorator | 1 and 2: grant succeeds, one failing resource is partial (servlet and Spring) | pass |
| authorization-code-pkce | 1: full loopback sign-in | pass |
| device-authorization | 1: a person confirms; tokens with `refresh_token` and `id_token` | pass, as a public client (finding 6) |
| device-authorization | 4, 5, 6, 7: another client, unknown resource, refresh for one resource, WebIdentity | pass |
| a2a-delegation | 1: B sees the user and agent A in `act` | pass |
| a2a-delegation | 2: C sees `act` naming B over A | **fail**: the chain is replaced (finding 5) |
| token-exchange (actor tokens, spec#104) | actor nests over a prior chain; without an actor token the chain is replaced | pass |

Not run: authorization-code-pkce row 2 (reuse a code), userinfo row 1 (needs a token minted for
the UserInfo resource, which the loopback client doesn't request), device rows 2 and 3 (a person
denies; a code expires), route-level-auth-gating rows 1 and 2 (the signed-in token carries no
scopes), and multi-zone-support row 1 (one sandbox zone). The device-authorization denial path is
covered by a policy denial on the confirmation page, which ended the poll with `access_denied`.

## Findings against the spec

Found by implementing the contracts from scratch and running them live. None are Java-specific.

1. **A malformed subject token is `invalid_request`, not the spec's `invalid_grant`.** The Ruby
   report recorded the same. The live suite keeps asserting the spec.
2. **Impersonated tokens now carry `act`.** The zone names the impersonating application
   (`act={sub=urn:app:java-sdk-engine, sub_profile=app}`), while `impersonation.md` integration
   row 1 says no `act`. The Ruby report found no `act` earlier, so the zone changed since; the spec
   should follow whichever is intended.
3. **Impersonating without access is `access_denied`, not `unauthorized_client`.** In this zone
   any application with a dependency on the resource may impersonate; a client without one is
   refused by policy rather than by client registration.
4. **Dynamic client registration accepts what the spec expects refused.** The zone registered a
   client whose `redirect_uris` held `"not a url"`, and registered a confidential
   `client_secret_basic` client with a secret, although svc-iam documents public clients only.
5. **The A2A spec's accumulating `act` chain doesn't happen without actor tokens.** The zone
   replaces `act` with the latest caller when an exchange has no `actor_token`, and no SDK's A2A
   path sends one, so integration row 2 fails in every SDK. Either the spec changes or the A2A path
   adopts actor tokens, which is the open direction question on spec#104.
6. **The device confirmation page can't resolve v2 workload credentials.** The verify page looks
   the client up among provider-less credentials only and shows "Invalid or expired code". svc-sts
   #861 changes that lookup. Until it ships, row 1 runs as a public client.
7. **Device tokens carry the first resource only.** With two resources and `openid`, the poll's
   access token had `aud` of the first resource and the UserInfo resource;
   `device-authorization.md` says every requested resource is in `aud`. Refreshing for the second
   resource works.

## Deliberate exclusions

| Spec | Why |
| --- | --- |
| `application-credentials/eks-workload-identity` | A deprecated alias of `workload-identity` in the sibling SDKs. Java is new and ships no deprecated surface; `FileTokenSource` covers the same discovery list. |
| `multi-zone-and-ops/per-user-token-cache` | Bound to `@keycardai/cloudflare`. Java's token cache (SDK-54) waits on spec#105. |
| `delegated-access/as-itself` | Implemented by agent-framework integrations; Java's (Spring AI, LangChain4j) start on customer demand. |
| `framework-integrations/*` | Governance documents. The servlet layer and the Spring Boot starter are judged against the FRAMEWORK-INTEGRATIONS.md checklist instead; the Spring AI example's README walks it row by row. |

## Idiom decisions

Java's expression choices and their reasons are in [idiom-profile.md](idiom-profile.md):
sync and blocking APIs (virtual threads give cheap blocking), builders and records, unchecked
exceptions rooted at `KeycardException` with a final `retryable()`, `java.net.http` behind a
transport interface, Nimbus as the only runtime dependency of the core, no Jackson in the core,
thread interruption for cancellation, and a separate `ClientAuthenticator` interface for
client authentication.

## Reproducing

```sh
./gradlew build                                  # 310 tests, lint, Javadoc, formatting
examples/mcp-server-servlet/bin/selftest         # no zone needed
examples/mcp-server-spring-ai/bin/selftest
examples/a2a-delegation/bin/selftest

export KEYCARD_ZONE_URL=https://<zone-id>.keycard.cloud LIVE_DIR=/path/outside/the/repo
export ZONE_ID=<zone-id> ORG_ID=<org-id>
examples/engine-obo/bin/sign-in                  # once, in a browser
examples/live-e2e                                # every non-interactive live suite
examples/engine-obo/bin/device-e2e confirm       # needs a person to approve a code
```
