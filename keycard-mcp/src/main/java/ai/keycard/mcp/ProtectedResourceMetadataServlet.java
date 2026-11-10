package ai.keycard.mcp;

import com.nimbusds.jose.util.JSONObjectUtils;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Serves the RFC 9728 protected-resource metadata document, the first thing an MCP client reads
 * after a 401. Map it at {@code /.well-known/oauth-protected-resource/*}.
 *
 * <p>{@code resource} comes from the request: its origin (scheme from {@code X-Forwarded-Proto},
 * host from {@code Host}) plus the context path, plus any path after the well-known prefix (RFC
 * 9728 path insertion, so {@code /.well-known/oauth-protected-resource/mcp} describes {@code
 * <origin>/mcp}). {@code authorization_servers} is always {@code [issuer]}.
 */
public final class ProtectedResourceMetadataServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** The zone that issues tokens for this resource. */
    private final String issuer;

    /** Optional fields to include, in order. */
    private final LinkedHashMap<String, Object> extras;

    private ProtectedResourceMetadataServlet(Builder builder) {
        this.issuer = builder.issuer.toString();
        Map<String, Object> fields = new LinkedHashMap<>();
        if (!builder.scopesSupported.isEmpty()) {
            fields.put("scopes_supported", builder.scopesSupported);
        }
        if (builder.resourceName != null) {
            fields.put("resource_name", builder.resourceName);
        }
        if (builder.resourceDocumentation != null) {
            fields.put("resource_documentation", builder.resourceDocumentation.toString());
        }
        if (builder.jwksUri != null) {
            fields.put("jwks_uri", builder.jwksUri.toString());
        }
        this.extras = new LinkedHashMap<>(fields);
    }

    /**
     * A builder for the document of a resource protected by {@code issuer}.
     *
     * @param issuer the Keycard zone
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getPathInfo() == null ? "" : request.getPathInfo();
        if (path.equals("/")) {
            path = "";
        }
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("resource", BearerChallenge.origin(request) + request.getContextPath() + path);
        document.put("authorization_servers", List.of(issuer));
        document.put("bearer_methods_supported", List.of("header"));
        document.putAll(extras);
        Cors.allow(response);
        BearerChallenge.json(response, 200, JSONObjectUtils.toJSONString(document));
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        Cors.preflight(response);
    }

    /** Configures a {@link ProtectedResourceMetadataServlet}. */
    public static final class Builder {

        private final URI issuer;
        private List<String> scopesSupported = List.of();
        private @Nullable String resourceName;
        private @Nullable URI resourceDocumentation;
        private @Nullable URI jwksUri;

        private Builder(URI issuer) {
            this.issuer = Objects.requireNonNull(issuer, "issuer");
        }

        /**
         * Scopes this resource accepts, advertised as {@code scopes_supported}.
         *
         * @param scopes the scopes
         * @return this builder
         */
        public Builder scopesSupported(String... scopes) {
            this.scopesSupported = List.of(scopes);
            return this;
        }

        /**
         * A human-readable name, advertised as {@code resource_name}.
         *
         * @param resourceName the name
         * @return this builder
         */
        public Builder resourceName(String resourceName) {
            this.resourceName = Objects.requireNonNull(resourceName, "resourceName");
            return this;
        }

        /**
         * A documentation link, advertised as {@code resource_documentation}.
         *
         * @param resourceDocumentation the link
         * @return this builder
         */
        public Builder resourceDocumentation(URI resourceDocumentation) {
            this.resourceDocumentation = Objects.requireNonNull(resourceDocumentation, "resourceDocumentation");
            return this;
        }

        /**
         * Where this resource publishes its own keys, advertised as {@code jwks_uri}.
         *
         * @param jwksUri the JWKS URL
         * @return this builder
         */
        public Builder jwksUri(URI jwksUri) {
            this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
            return this;
        }

        /**
         * Builds the servlet.
         *
         * @return the servlet
         */
        public ProtectedResourceMetadataServlet build() {
            return new ProtectedResourceMetadataServlet(this);
        }
    }
}
