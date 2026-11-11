# keycard-spring-boot-starter

Keycard for Spring Boot 4: Spring Security's own OAuth2 resource server, verified by Keycard,
plus delegated access in Spring MVC.

```kotlin
implementation("ai.keycard:keycard-spring-boot-starter:0.1.0")
```

```properties
keycard.zone-url=https://acme.keycard.cloud
keycard.audiences=https://api.example.com
keycard.client-id=...          # for @KeycardGrant; or define a Credential bean
keycard.client-secret=...
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

The starter serves RFC 9728 metadata through Spring Security's filter (Spring's web starter
brings the Jackson it writes with) and proxies the zone's RFC 8414 metadata. A missing or invalid
token gets a 401 with an RFC 6750 challenge, a malformed header 400, a missing scope 403, and
unreachable zone keys a 503 with no challenge. Every bean backs off to one you define.

[examples/mcp-server-spring-ai](../examples/mcp-server-spring-ai) runs a Spring AI MCP server
behind it.

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-spring-boot-starter>
