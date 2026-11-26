# keycard-mcp

Keycard auth for MCP servers, and any Jakarta Servlet 6 application: a bearer filter
(RFC 6750), protected-resource metadata (RFC 9728), the zone's authorization-server metadata
proxied (RFC 8414), scope gating, and a grant filter that exchanges the caller's token for the
resources a request needs. It wraps no MCP SDK; it attaches at the servlet seam, so it works
under the official MCP Java SDK's servlet transport or any servlet container.

```kotlin
implementation("ai.keycard:keycard-mcp:0.1.0")
```

```java
URI zone = URI.create("https://acme.keycard.cloud");
AuthProvider keycard = AuthProvider.builder(zone)
        .credential(ClientSecret.of(clientId, clientSecret))
        .resourceIdentifier("https://mcp.example.com/mcp")
        .build();

context.addServlet(new ServletHolder(keycard.protectedResourceMetadata().build()),
        "/.well-known/oauth-protected-resource/*");
context.addServlet(new ServletHolder(keycard.authorizationServerMetadata()),
        "/.well-known/oauth-authorization-server");
// Map the filters to the same pattern as the servlet they guard, for forwards and includes too.
EnumSet<DispatcherType> dispatches = EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.INCLUDE);
context.addFilter(new FilterHolder(RequireBearerAuthFilter.builder(keycard).build()), "/mcp/*", dispatches);
context.addFilter(new FilterHolder(keycard.grant("https://api.example.com")), "/mcp/*", dispatches);
```

A filter covers only the requests its mapping matches, so map it to every path that reaches the
protected servlet; `/mcp/*` covers `/mcp` and everything under it. With `FORWARD` and `INCLUDE`
in the mapping, a request another servlet forwards to `/mcp` is checked too.

The resource identifier is the exact token audience and the `resource` in the document at
`https://mcp.example.com/.well-known/oauth-protected-resource/mcp`. Challenges include that
URL only when the original request path and query match the identifier, independent of the
servlet's view of the host or scheme. Give each discoverable endpoint its own binding.

Register the advertised metadata URLs at the public host root. If the servlet context has a
prefix, register the metadata servlet in a root context or forward the configured public URLs
to the prefixed context and configure `metadataForwarded(true)` on the metadata builder.
Load the metadata servlet at startup so it can validate the context before serving traffic.

A URN, `multiResource(true)` with an `audiences(...)` list, and `allowAnyAudience(true)`
are verifier-only modes. Do not register the protected-resource servlet in those modes.
For per-zone bindings, pass the base issuer to the provider and set `resourceIdentifiersByZone`
with zone IDs as keys. Configure a `zoneResolver` on the filter that resolves each request's
zone issuer without consulting its token. Register the AS proxy at
`/.well-known/oauth-authorization-server/*`. For a token-keyed server with a shared resource,
use `multiResource(true)` with the same HTTP(S) identifier for every zone and as the sole
list audience, and omit the zone resolver.

An implicit binding retains request-derived discovery and accepts the legacy audience list
during deprecation. It logs a warning at construction. Migrate to one of the explicit modes.

In a handler, `KeycardRequest.accessToken(request)` is the verified caller and
`KeycardRequest.accessContext(request)` holds a token, or an error, per granted resource.
Mark filter holders async-supported when the servlet behind them is asynchronous, like the
MCP SDK's transport.

The filter answers 401 with a challenge for a missing or invalid token, 400 for a malformed
header, 403 `insufficient_scope`, and 503 `temporarily_unavailable` with no challenge when the
zone's keys can't be fetched. A grant never stops a request for a failed exchange; it records the
error on the `AccessContext`.

[examples/mcp-server-servlet](../examples/mcp-server-servlet) runs this in front of the official
MCP Java SDK, with a transport-context extractor that hands the caller and `AccessContext` to
tool handlers.

Javadoc: <https://javadoc.io/doc/ai.keycard/keycard-mcp>
