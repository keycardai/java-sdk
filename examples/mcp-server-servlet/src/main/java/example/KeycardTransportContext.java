package example;

import ai.keycard.mcp.KeycardRequest;
import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.AccessToken;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Carries what the Keycard filters put on the servlet request into the MCP SDK's transport
 * context, where tool handlers can read it. The transport calls {@link #extract} on the request
 * thread, after every filter has run.
 */
final class KeycardTransportContext {

    static final String ACCESS_TOKEN = KeycardRequest.ACCESS_TOKEN_ATTRIBUTE;
    static final String ACCESS_CONTEXT = KeycardRequest.ACCESS_CONTEXT_ATTRIBUTE;

    private KeycardTransportContext() {}

    /** The extractor passed to the transport builder's {@code contextExtractor}. */
    static McpTransportContext extract(HttpServletRequest request) {
        Map<String, Object> values = new HashMap<>();
        KeycardRequest.accessToken(request).ifPresent(token -> values.put(ACCESS_TOKEN, token));
        KeycardRequest.accessContext(request).ifPresent(context -> values.put(ACCESS_CONTEXT, context));
        return McpTransportContext.create(values);
    }

    static Optional<AccessToken> accessToken(McpTransportContext context) {
        return context.get(ACCESS_TOKEN) instanceof AccessToken token ? Optional.of(token) : Optional.empty();
    }

    static Optional<AccessContext> accessContext(McpTransportContext context) {
        return context.get(ACCESS_CONTEXT) instanceof AccessContext access ? Optional.of(access) : Optional.empty();
    }
}
