# keycard-spring-boot-starter

Keycard for Spring Boot 4: Spring Security's own OAuth2 resource server, verified by Keycard,
plus delegated access in Spring MVC.

```kotlin
implementation("ai.keycard:keycard-spring-boot-starter:0.1.0")
```

```properties
keycard.zone-url=https://acme.keycard.cloud
keycard.resource-identifier=https://api.example.com/mcp
keycard.client-id=...          # for @KeycardGrant and introspection; or define a Credential bean
keycard.client-secret=...
keycard.introspect=false
```

With `keycard.zone-url` set and no `SecurityFilterChain` of your own, every request needs a
verified bearer token. To write your own rules, apply the starter's configurer:

```java
@Bean
SecurityFilterChain api(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
    return http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/admin/**").hasAuthority("SCOPE_admin")
                    .anyRequest().authenticated())
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .with(keycard, Customizer.withDefaults())
            .build();
}
```

The configurer leaves CSRF as your chain sets it. Disable CSRF and sessions in a chain that only
accepts bearer tokens, as above: the browser never attaches a bearer token by itself, so there's
nothing to forge, and with CSRF on an unauthenticated POST gets a 403 instead of the 401 challenge
MCP clients follow. Keep CSRF on in any chain that also signs people in with cookies, Basic or a
sign-in form.

Declare the resources a handler calls, and take the results as a parameter:

```java
@GetMapping("/events")
@KeycardGrant(resources = "https://calendar.example", scopes = "calendar.read")
List<Event> events(AccessContext access) {
    String token = access.access("https://calendar.example").accessToken();
    ...
}
```

The resource identifier supplies the exact audience and the `resource` in the RFC 9728
document. When the received path and query match it, the challenge advertises the configured
host-root metadata URL. If the application has a servlet context prefix, forward that public
URL into the context and set `keycard.metadata-forwarded=true`. The starter also proxies
the zone's RFC 8414 metadata.

Use a URN, `keycard.multi-resource=true` with `keycard.audiences`, or
`keycard.allow-any-audience=true` for verification without protected-resource discovery.
For multiple zones, use the base issuer as `keycard.zone-url` and configure
`keycard.resource-identifiers-by-zone.<zone-id>` for each trusted zone. Provide a
`RequireBearerAuthFilter.ZoneResolver` bean that reads no token, or use shared discovery
with the same HTTP(S) resource for every zone, `keycard.multi-resource=true`, and the
shared resource as the only `keycard.audiences` value. Without an explicit mode, the
starter keeps legacy discovery and warns at construction. The starter checks the policy
of a custom `KeycardJwtDecoder` against an explicit binding. For other decoders, the
application must enforce the configured audience policy; per-zone request selection
requires the Keycard decoder.

A missing or invalid token gets a 401 with an RFC 6750 challenge, a malformed header 400,
a missing scope 403, and unreachable zone keys a 503 with no challenge. Every bean backs off
to one you define.

Set `keycard.introspect=true` or opt in on your `AuthProvider` with `.introspect(true)` to
check whether a bearer token is still active. Introspection is off when neither opts in.
It runs after local verification and the chain's authorization checks. It uses the resource
server's own application credential (selected by the token's verified zone for multiple
zones), and never caches the result. An inactive token gets a 401 `invalid_token` Bearer
challenge. An introspection failure gets a 503 `temporarily_unavailable` with no
`WWW-Authenticate` header.

[examples/mcp-server-spring-ai](../examples/mcp-server-spring-ai) runs a Spring AI MCP server
behind it.

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-spring-boot-starter>
