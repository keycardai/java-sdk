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
        .audiences("https://mcp.example.com/mcp")
        .build();

context.addServlet(new ServletHolder(ProtectedResourceMetadataServlet.builder(zone).build()),
        "/.well-known/oauth-protected-resource/*");
context.addServlet(new ServletHolder(AuthorizationServerMetadataServlet.of(zone)),
        "/.well-known/oauth-authorization-server");
EnumSet<DispatcherType> request = EnumSet.of(DispatcherType.REQUEST);
context.addFilter(new FilterHolder(RequireBearerAuthFilter.builder(keycard.tokenVerifier()).build()), "/mcp", request);
context.addFilter(new FilterHolder(keycard.grant("https://api.example.com")), "/mcp", request);
```

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
