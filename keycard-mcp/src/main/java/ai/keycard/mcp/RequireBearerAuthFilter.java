package ai.keycard.mcp;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.JwksException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TokenVerifier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Requires a valid Keycard bearer token (bearer-token-verification-middleware.md).
 *
 * <pre>{@code
 * Filter auth = RequireBearerAuthFilter.builder(
 *                 TokenVerifier.builder(URI.create("https://acme.keycard.cloud"))
 *                         .audiences("https://mcp.example.com/mcp")
 *                         .build())
 *         .build();
 * }</pre>
 *
 * <p>Failures are HTTP responses, never exceptions into the application:
 *
 * <ul>
 *   <li>no {@code Authorization} header: 401 with {@code Bearer resource_metadata="..."}
 *   <li>a header that isn't two parts: 400
 *   <li>a scheme other than {@code Bearer}, or a token that fails verification: 401 with {@code
 *       error="invalid_token"}
 *   <li>a required scope missing: 403 with {@code error="insufficient_scope"}
 *   <li>the zone's keys or metadata can't be fetched: 503 {@code {"error":"temporarily_unavailable"}}
 *       with no challenge, since the token was never judged
 * </ul>
 *
 * <p>On success the {@link AccessToken} is stored under {@link
 * KeycardRequest#ACCESS_TOKEN_ATTRIBUTE} and the chain continues.
 */
public final class RequireBearerAuthFilter implements Filter {

    /** Resolves a request's zone issuer for a multi-zone server. */
    @FunctionalInterface
    public interface ZoneResolver {

        /**
         * The zone this request belongs to.
         *
         * @param request the request
         * @return the zone's issuer, or {@code null} when it can't be determined (the request is
         *     then rejected)
         */
        @Nullable
        URI resolve(HttpServletRequest request);
    }

    private final TokenVerifier verifier;
    private final Set<String> requiredScopes;
    private final @Nullable ZoneResolver zoneResolver;
    private final ResourceBinding binding;
    private final boolean authenticationRequired;
    private final @Nullable BearerTokenIntrospection introspection;

    private RequireBearerAuthFilter(Builder builder, ResourceBinding binding) {
        this.verifier = builder.verifier;
        this.requiredScopes = Set.copyOf(builder.requiredScopes);
        this.zoneResolver = builder.zoneResolver;
        this.binding = binding;
        this.authenticationRequired = builder.authenticationRequired;
        this.introspection = builder.introspection();
    }

    /**
     * A builder for a filter verifying with a standalone {@code verifier}.
     * For a provider's verifier, prefer {@link #builder(AuthProvider)}.
     *
     * @param verifier the token verifier, built with this server's audience
     * @return a new builder
     */
    public static Builder builder(TokenVerifier verifier) {
        return new Builder(verifier);
    }

    /**
     * A builder sharing the provider's audience and discovery configuration.
     *
     * @param provider the resource server's provider
     * @return a new builder
     */
    public static Builder builder(AuthProvider provider) {
        Builder builder = new Builder(provider.tokenVerifier());
        builder.sharedBinding = provider.resourceBinding();
        builder.provider = provider;
        return builder;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        URI zone = binding.requiresZone() && zoneResolver != null ? zoneResolver.resolve(request) : null;
        request.setAttribute(BearerChallenge.BINDING_ATTRIBUTE, binding);
        request.setAttribute(BearerChallenge.ZONE_ATTRIBUTE, zone);
        if (binding.requiresZone() && (zone == null || !verifier.issuers().contains(zone))) {
            BearerChallenge.challenge(request, response, 401, "invalid_token", "the request's zone is not configured");
            return;
        }

        // A forward or include of a request this filter already verified: the token stands, and
        // only this instance's scopes are left to check. Request attributes are server-side, so a
        // client can't set this one.
        AccessToken verified = KeycardRequest.accessToken(request).orElse(null);
        if (verified != null && binding.isLegacy() && introspection == null) {
            if (hasRequiredScopes(request, response, verified)) {
                chain.doFilter(request, response);
            }
            return;
        }
        if (!binding.isLegacy() || introspection != null) {
            request.removeAttribute(KeycardRequest.ACCESS_TOKEN_ATTRIBUTE);
        }

        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            if (!authenticationRequired) {
                chain.doFilter(request, response);
                return;
            }
            BearerChallenge.challenge(request, response, 401, null, null);
            return;
        }
        String[] parts = header.trim().split("\\s+");
        if (parts.length != 2) {
            BearerChallenge.badRequest(response, "the Authorization header must be 'Bearer <token>'");
            return;
        }
        if (!parts[0].toLowerCase(Locale.ROOT).equals("bearer")) {
            BearerChallenge.challenge(request, response, 401, "invalid_token", "unsupported authorization scheme");
            return;
        }

        AccessToken token;
        try {
            token = verify(
                    zoneResolver != null && !binding.requiresZone() ? zoneResolver.resolve(request) : zone, parts[1]);
        } catch (InvalidTokenException e) {
            // A fixed description: the verifier's message names the expected issuer and audiences,
            // which a caller probing with forged tokens has no business learning.
            BearerChallenge.challenge(
                    request, response, 401, "invalid_token", "the access token is invalid or expired");
            return;
        } catch (JwksException e) {
            BearerChallenge.unavailable(response);
            return;
        } catch (KeycardException e) {
            // Discovery or transport failures that surface outside the keyring.
            BearerChallenge.unavailable(response);
            return;
        }

        if (!hasRequiredScopes(request, response, token)) {
            return;
        }
        if (introspection != null) {
            switch (introspection.check(token.issuer(), token.token())) {
                case INACTIVE -> {
                    BearerChallenge.challenge(request, response, 401, "invalid_token", "the access token is inactive");
                    return;
                }
                case UNAVAILABLE -> {
                    BearerTokenIntrospection.unavailable(response);
                    return;
                }
                case ACTIVE -> {}
            }
        }
        request.setAttribute(KeycardRequest.ACCESS_TOKEN_ATTRIBUTE, token);
        chain.doFilter(request, response);
    }

    /** Answers 403 {@code insufficient_scope} and returns false when a required scope is missing. */
    private boolean hasRequiredScopes(HttpServletRequest request, HttpServletResponse response, AccessToken token)
            throws IOException {
        List<String> granted = token.scopes();
        for (String scope : requiredScopes) {
            if (!granted.contains(scope)) {
                BearerChallenge.challenge(
                        request, response, 403, "insufficient_scope", "the token lacks the scope " + scope);
                return false;
            }
        }
        return true;
    }

    private AccessToken verify(@Nullable URI zone, String token) {
        if (zoneResolver == null) {
            return verifier.verifyToken(token);
        }
        if (zone == null) {
            throw new InvalidTokenException("the request's zone could not be determined");
        }
        return verifier.verifyTokenForZone(token, zone);
    }

    /** Configures a {@link RequireBearerAuthFilter}. */
    public static final class Builder {

        private final TokenVerifier verifier;
        private final ResourceBinding.Options options = new ResourceBinding.Options();
        private @Nullable ResourceBinding sharedBinding;
        private @Nullable AuthProvider provider;
        private @Nullable URI baseIssuer;
        private @Nullable Boolean introspect;
        private @Nullable Credential credential;
        private @Nullable Duration introspectionTimeout;
        private @Nullable KeycardHttpTransport introspectionTransport;
        private Set<String> requiredScopes = Set.of();
        private @Nullable ZoneResolver zoneResolver;
        private boolean authenticationRequired = true;

        private Builder(TokenVerifier verifier) {
            this.verifier = Objects.requireNonNull(verifier, "verifier");
        }

        /**
         * Enables the uncached status check after local verification and required scope checks.
         *
         * @param enabled whether to introspect; by default inherits the provider setting, or false
         *     for a standalone verifier
         * @return this builder
         */
        public Builder introspect(boolean enabled) {
            this.introspect = enabled;
            return this;
        }

        /**
         * Sets the credential of the Application that owns the protected Resource.
         *
         * @param credential the credential for introspection; defaults to the provider's credential
         * @return this builder
         */
        public Builder credential(Credential credential) {
            this.credential = Objects.requireNonNull(credential, "credential");
            return this;
        }

        /**
         * Sets the timeout per discovery or introspection request.
         *
         * @param timeout the timeout; defaults to the provider's fetch timeout or ten seconds
         * @return this builder
         */
        public Builder introspectionTimeout(Duration timeout) {
            this.introspectionTimeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        /**
         * Sets the HTTPS transport for a standalone filter's introspection requests.
         *
         * @param transport the transport, with redirects disabled
         * @return this builder
         */
        public Builder introspectionTransport(KeycardHttpTransport transport) {
            requireStandalone();
            this.introspectionTransport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        private @Nullable BearerTokenIntrospection introspection() {
            if (Boolean.FALSE.equals(introspect)) {
                return null;
            }
            if (provider != null) {
                BearerTokenIntrospection inherited =
                        provider.bearerTokenIntrospection(false).orElse(null);
                if (inherited == null && introspect == null) {
                    return null;
                }
                return inherited != null && credential == null && introspectionTimeout == null
                        ? inherited
                        : provider.createIntrospection(credential, introspectionTimeout);
            }
            return Boolean.TRUE.equals(introspect)
                    ? new BearerTokenIntrospection(
                            verifier.issuers(),
                            credential,
                            introspectionTransport == null ? KeycardHttpTransport.create() : introspectionTransport,
                            introspectionTimeout == null ? KeycardHttpTransport.DEFAULT_TIMEOUT : introspectionTimeout,
                            Clock.systemUTC())
                    : null;
        }

        /**
         * Scopes every request's token must hold, all of them.
         *
         * @param scopes the required scopes
         * @return this builder
         */
        public Builder requiredScopes(String... scopes) {
            this.requiredScopes = Set.of(scopes);
            return this;
        }

        /**
         * Allows anonymous requests to reach downstream gates while verifying any presented token.
         *
         * @param required whether every request needs a bearer token
         * @return this builder
         */
        public Builder authenticationRequired(boolean required) {
            this.authenticationRequired = required;
            return this;
        }

        /**
         * Requires the supplied verifier to enforce one exact resource identifier.
         *
         * @param identifier the HTTP(S) URL or URN
         * @return this builder
         */
        public Builder resourceIdentifier(String identifier) {
            requireStandalone();
            options.identifier(identifier);
            return this;
        }

        /**
         * Sets zone-specific bindings for a verifier configured with matching issuer audiences.
         *
         * @param issuer the base issuer
         * @param identifiers the resource identifier for each zone ID
         * @return this builder
         */
        public Builder resourceIdentifiersByZone(URI issuer, Map<String, String> identifiers) {
            requireStandalone();
            options.identifiersByZone(identifiers);
            this.baseIssuer = issuer;
            return this;
        }

        /**
         * Enables explicit list-based verification or shared discovery with a zone map.
         *
         * @param enabled whether to use the configured verifier's audience list
         * @return this builder
         */
        public Builder multiResource(boolean enabled) {
            requireStandalone();
            options.multiResource(enabled);
            return this;
        }

        /**
         * Uses a verifier configured to accept any audience and disables discovery.
         *
         * @param enabled whether to skip the audience check
         * @return this builder
         */
        public Builder allowAnyAudience(boolean enabled) {
            requireStandalone();
            options.allowAnyAudience(enabled);
            return this;
        }

        private void requireStandalone() {
            if (sharedBinding != null) {
                throw new ConfigurationException("configure resource binding on the provider");
            }
        }

        /**
         * Pins each request to one zone for a multi-zone server; a request whose zone can't be
         * determined, or isn't trusted by the verifier, is rejected.
         *
         * @param zoneResolver resolves the zone issuer without consulting the bearer token
         * @return this builder
         */
        public Builder zoneResolver(ZoneResolver zoneResolver) {
            this.zoneResolver = Objects.requireNonNull(zoneResolver, "zoneResolver");
            return this;
        }

        /**
         * Builds the filter.
         *
         * @return the filter
         * @throws ConfigurationException when the verifier trusts more than one zone and no zone
         *     resolver is set: each request must be verified against its own zone, never any
         *     trusted one, or when the resource binding is incompatible with the verifier
         */
        public RequireBearerAuthFilter build() {
            ResourceBinding binding = sharedBinding != null
                    ? sharedBinding
                    : ResourceBinding.forPrebuiltVerifier(
                            baseIssuer == null ? verifier.issuers().get(0) : baseIssuer, options, verifier);
            binding.validate(verifier);
            if (zoneResolver == null
                    && (binding.requiresZone() || (verifier.issuers().size() > 1 && !binding.sharedDiscovery()))) {
                throw new ConfigurationException(
                        "the verifier trusts " + verifier.issuers().size()
                                + " zones; set a zoneResolver so each request is verified against its own zone");
            }
            if (binding.sharedDiscovery() && zoneResolver != null) {
                throw new ConfigurationException("shared discovery selects the zone from the token");
            }
            if (sharedBinding == null
                    && binding.isLegacy()
                    && !verifier.audiences().isEmpty()) {
                ResourceBinding.warnLegacy();
            }
            return new RequireBearerAuthFilter(this, binding);
        }
    }
}
