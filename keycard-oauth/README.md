# keycard-oauth

OAuth 2.0 for Keycard zones: token exchange (RFC 8693), client credentials, authorization code
with PKCE and refresh, the device authorization grant (RFC 8628), dynamic client registration
(RFC 7591), discovery (RFC 8414), UserInfo, JWT signing and verification with a cached JWKS
keyring, and the `AccessContext` that holds per-resource results. Its only runtime dependency
is Nimbus JOSE + JWT.

```kotlin
implementation("ai.keycard:keycard-oauth:0.1.0")
```

## Exchange a user's token for a downstream resource

```java
URI zone = URI.create("https://acme.keycard.cloud");
TokenExchangeClient exchange = TokenExchangeClient.builder(zone)
        .credential(ClientSecret.of(clientId, clientSecret))
        .build();
TokenResponse token = exchange.exchangeToken(userAccessToken, URI.create("https://api.example.com"));
```

The issued token's `sub` is still the user, and the zone records your application in `act`.

## Credentials

| Credential | Use it when |
| --- | --- |
| `ClientSecret.of(id, secret)` | You have a registered client id and secret. `ClientSecret.perZone(...)` holds one pair per zone. |
| `WorkloadIdentity.builder(source).clientId(id)` | The platform gives the workload a token: a projected Kubernetes service-account token, an EKS or AKS token file, GCP metadata, or a SPIFFE JWT-SVID (see `keycard-spiffe`). |
| `WebIdentity.builder().clientId(id)` | The workload can keep a key. It generates an RSA key on first use and signs `private_key_jwt` assertions; publish `publicJwks()` for the zone. |
| `CredentialDiscovery.discover(System.getenv())` | You want the same build to pick its credential from `KEYCARD_*` variables, from a laptop secret to a cluster token file. |

## Verify inbound tokens

```java
TokenVerifier verifier = TokenVerifier.builder(zone)
        .audiences("https://mcp.example.com/mcp")
        .build();
AccessToken caller = verifier.verifyToken(bearerToken);   // throws InvalidTokenException
```

For a servlet application, `keycard-mcp` wraps this in a filter; for Spring Boot,
`keycard-spring-boot-starter` plugs it into Spring Security.

## Sign a user in

```java
AuthorizationCodeClient auth = AuthorizationCodeClient.builder(zone).clientId(cliClientId).build();
TokenResponse tokens = auth.authenticate(AuthorizationCodeClient.Loopback.builder()
        .resources(URI.create("https://api.example.com"))
        .build());   // opens the browser, waits on 127.0.0.1
```

On a machine with no browser, `DeviceAuthorizationClient` runs the device grant:
`requestDeviceAuthorization(...)`, show the user code, then `pollUntilDone(...)`.

## Errors

Every failure is a `KeycardException` with `retryable()`. `OAuthErrorException` carries the
OAuth `error` code, `NetworkException` and `HttpStatusException` (429 and 5xx) are retryable,
and a `ConfigurationException` is never retryable. No request is retried for you, and every request is
bounded by a timeout (10 seconds by default, `fetchTimeout(...)` on each builder).

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-oauth>
