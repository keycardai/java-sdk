package ai.keycard.mcp;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.KeycardHttpTransport;
import com.nimbusds.jose.util.JSONObjectUtils;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * Serves the RFC 9728 protected-resource metadata document, the first thing an MCP client reads
 * after a 401. Map it at {@code /.well-known/oauth-protected-resource/*}.
 *
 * <p>For explicit resource binding, register the configured well-known URLs at the public host
 * root or forward each one from the host root to this servlet.
 */
public final class ProtectedResourceMetadataServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** The zone that issues tokens for this resource. */
    private final String issuer;

    /** The configured protected-resource documents. */
    private final ResourceBinding binding;

    /** Whether public metadata requests are forwarded into this servlet context. */
    private final boolean metadataForwarded;

    /** Optional fields to include, in order. */
    private final LinkedHashMap<String, Object> extras;

    private ProtectedResourceMetadataServlet(Builder builder) {
        this.issuer = builder.issuer == null ? "" : builder.issuer.toString();
        this.binding = builder.sharedBinding == null
                ? ResourceBinding.forMetadata(builder.issuer, builder.options)
                : builder.sharedBinding;
        this.metadataForwarded = builder.metadataForwarded;
        if (builder.sharedBinding == null && binding.isLegacy()) {
            ResourceBinding.warnLegacy();
        }
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
        return new Builder(Objects.requireNonNull(issuer, "issuer"));
    }

    /**
     * Configures standalone metadata without a base issuer.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder(null);
    }

    static Builder builder(URI issuer, ResourceBinding binding) {
        Builder builder = new Builder(issuer);
        builder.sharedBinding = binding;
        return builder;
    }

    @Override
    public void init() {
        List<URI> metadataUrls = binding.metadataUrls();
        if (metadataUrls.isEmpty() || metadataForwarded) {
            return;
        }
        if (!getServletContext().getContextPath().isEmpty()) {
            throw new ConfigurationException(
                    "publish resource metadata at the public host root or configure metadataForwarded");
        }
        ServletRegistration registration = getServletContext().getServletRegistration(getServletName());
        if (registration != null && !registration.getMappings().isEmpty()) {
            for (URI url : metadataUrls) {
                if (registration.getMappings().stream().noneMatch(mapping -> accepts(mapping, url.getPath()))) {
                    throw new ConfigurationException("the metadata servlet is not mapped to " + url.getRawPath());
                }
            }
        }
    }

    private static boolean accepts(String mapping, String path) {
        if (mapping.equals("/") || mapping.equals(path)) {
            return true;
        }
        if (mapping.endsWith("/*")) {
            String prefix = mapping.substring(0, mapping.length() - 2);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }
        return mapping.startsWith("*.")
                && path.substring(path.lastIndexOf('/') + 1).endsWith(mapping.substring(1));
    }

    /**
     * Whether this explicit servlet serves the requested host-root metadata route.
     *
     * @param request the servlet request
     * @return whether the configured path and query match
     */
    public boolean matches(HttpServletRequest request) {
        return binding.isLegacy() || configuredDocument(request).isPresent();
    }

    /**
     * Builds the authorization-server proxy for this servlet's resource configuration.
     *
     * @param transport sends upstream requests
     * @param timeout the bound on upstream requests
     * @return the proxy servlet
     */
    public AuthorizationServerMetadataServlet authorizationServerMetadata(
            KeycardHttpTransport transport, Duration timeout) {
        if (issuer.isEmpty()) {
            throw new ConfigurationException("the authorization-server proxy requires an issuer");
        }
        return AuthorizationServerMetadataServlet.of(URI.create(issuer), binding, transport, timeout);
    }

    private Optional<ResourceBinding.Document> configuredDocument(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (metadataForwarded) {
            path = path.substring(request.getContextPath().length());
        }
        return binding.document(path, request.getQueryString());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Object> document = new LinkedHashMap<>();
        if (binding.isLegacy()) {
            String path = request.getPathInfo() == null ? "" : request.getPathInfo();
            if (path.equals("/")) {
                path = "";
            }
            document.put("resource", BearerChallenge.origin(request) + request.getContextPath() + path);
            document.put("authorization_servers", issuer.isEmpty() ? List.of() : List.of(issuer));
        } else {
            ResourceBinding.Document configured = configuredDocument(request).orElse(null);
            if (configured == null) {
                response.sendError(404);
                return;
            }
            document.put("resource", configured.resource().toString());
            document.put(
                    "authorization_servers",
                    configured.issuers().stream().map(URI::toString).toList());
        }
        document.put("bearer_methods_supported", List.of("header"));
        document.putAll(extras);
        Cors.allow(response);
        BearerChallenge.json(response, 200, JSONObjectUtils.toJSONString(document));
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (matches(request)) {
            Cors.preflight(response);
        } else {
            response.sendError(404);
        }
    }

    /** Configures a {@link ProtectedResourceMetadataServlet}. */
    public static final class Builder {

        private final @Nullable URI issuer;
        private final ResourceBinding.Options options = new ResourceBinding.Options();
        private @Nullable ResourceBinding sharedBinding;
        private boolean metadataForwarded;
        private List<String> scopesSupported = List.of();
        private @Nullable String resourceName;
        private @Nullable URI resourceDocumentation;
        private @Nullable URI jwksUri;

        private Builder(@Nullable URI issuer) {
            this.issuer = issuer;
        }

        /**
         * Configures the exact identifier to publish.
         *
         * @param identifier the HTTP(S) URL or a verifier-only URN
         * @return this builder
         */
        public Builder resourceIdentifier(String identifier) {
            requireStandalone();
            options.identifier(identifier);
            return this;
        }

        /**
         * Configures the identifiers of individual zones.
         *
         * @param identifiers the map from zone ID to resource identifier
         * @return this builder
         */
        public Builder resourceIdentifiersByZone(Map<String, String> identifiers) {
            requireStandalone();
            options.identifiersByZone(identifiers);
            return this;
        }

        /**
         * Disables documents, or enables shared discovery when a zone map is configured.
         *
         * @param enabled whether to use multi-resource mode
         * @return this builder
         */
        public Builder multiResource(boolean enabled) {
            requireStandalone();
            options.multiResource(enabled);
            return this;
        }

        /**
         * Disables protected-resource documents in unrestricted audience mode.
         *
         * @param enabled whether to use unrestricted audiences
         * @return this builder
         */
        public Builder allowAnyAudience(boolean enabled) {
            requireStandalone();
            options.allowAnyAudience(enabled);
            return this;
        }

        /**
         * Allows this servlet to receive host-root metadata requests forwarded into its context.
         *
         * @param forwarded whether the public path is forwarded with the context prefix added
         * @return this builder
         */
        public Builder metadataForwarded(boolean forwarded) {
            this.metadataForwarded = forwarded;
            return this;
        }

        private void requireStandalone() {
            if (sharedBinding != null) {
                throw new ConfigurationException("configure resource binding on the provider");
            }
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
