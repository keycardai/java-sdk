package ai.keycard.oauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Introspects tokens using RFC 7662.
 *
 * <p>The caller authenticates as a confidential client and learns whether a token is active.
 * An inactive token is returned as a {@link TokenIntrospection} with {@code active() == false},
 * not thrown as an error. Results are never cached and failed requests are never retried.
 */
public final class TokenIntrospectionClient {

    private final URI issuer;
    private final @Nullable AuthorizationServerMetadata fixedMetadata;
    private final AuthorizationServerMetadataCache metadataCache;
    private final ClientAuthenticator authenticator;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;

    private TokenIntrospectionClient(Builder builder, ClientAuthenticator authenticator) {
        this.issuer = builder.issuer;
        this.fixedMetadata = builder.fixedMetadata;
        this.authenticator = authenticator;
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.metadataCache = builder.metadataCache != null
                ? builder.metadataCache
                : AuthorizationServerMetadataCache.builder()
                        .discovery(AuthorizationServerDiscovery.builder()
                                .transport(transport)
                                .fetchTimeout(fetchTimeout)
                                .build())
                        .clock(builder.clock)
                        .discoveryTtl(builder.discoveryTtl)
                        .negativeTtl(builder.negativeTtl)
                        .build();
    }

    /**
     * A builder that resolves the introspection endpoint by discovery.
     *
     * @param issuer the zone's HTTPS issuer
     * @return a new builder
     * @throws ConfigurationException if the issuer is not an HTTPS issuer URL
     */
    public static Builder builder(URI issuer) {
        AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
        requireHttps(issuer, "issuer");
        return new Builder(issuer, null);
    }

    /**
     * A builder that uses metadata the caller already holds.
     *
     * @param metadata the zone's authorization server metadata
     * @return a builder that skips discovery
     */
    public static Builder builder(AuthorizationServerMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata");
        return new Builder(metadata.issuer(), metadata);
    }

    /**
     * Introspects a token without sending {@code token_type_hint}.
     *
     * @param token the access token or refresh token to check
     * @return the introspection result
     * @throws ConfigurationException if the token is missing or empty or the metadata has no
     *     valid HTTPS introspection endpoint
     * @throws OAuthErrorException if the server returns an OAuth error such as {@code
     *     invalid_client} or {@code invalid_request}
     * @throws OAuthProtocolException with {@link OAuthProtocolException#INVALID_RESPONSE} if the
     *     HTTP 200 response is malformed or lacks a boolean {@code active}
     * @throws KeycardException on discovery, HTTP or network failures
     */
    public TokenIntrospection introspectToken(String token) {
        return introspectToken(token, null);
    }

    /**
     * Introspects a token, optionally sending {@code token_type_hint}.
     *
     * @param token the access token or refresh token to check
     * @param tokenTypeHint the hint to send as {@code token_type_hint}, or {@code null} to omit it
     * @return the introspection result
     * @throws ConfigurationException if the token is missing or empty or the metadata has no
     *     valid HTTPS introspection endpoint
     * @throws OAuthErrorException if the server returns an OAuth error such as {@code
     *     invalid_client} or {@code invalid_request}
     * @throws OAuthProtocolException with {@link OAuthProtocolException#INVALID_RESPONSE} if the
     *     HTTP 200 response is malformed or lacks a boolean {@code active}
     * @throws KeycardException on discovery, HTTP or network failures
     */
    public TokenIntrospection introspectToken(String token, @Nullable String tokenTypeHint) {
        if (token == null || token.isEmpty()) {
            throw new ConfigurationException("token must not be empty");
        }
        Map<String, List<String>> form = new LinkedHashMap<>();
        form.put("token", List.of(token));
        if (tokenTypeHint != null) {
            form.put("token_type_hint", List.of(tokenTypeHint));
        }

        AuthorizationServerMetadata metadata = fixedMetadata != null ? fixedMetadata : metadataCache.get(issuer);
        URI endpoint = metadata.introspectionEndpoint();
        if (endpoint == null) {
            if (fixedMetadata == null) {
                metadataCache.expireMissingEndpoint(issuer, metadata);
            }
            throw new ConfigurationException("the zone " + issuer + " advertises no introspection_endpoint");
        }
        // RFC 7662 requires HTTPS for the token and client authentication.
        requireHttps(endpoint, "introspection_endpoint");

        // Introspection uses the zone issuer as the private-key JWT audience.
        URI zoneIssuer = metadata.issuer();
        ClientAuthentication auth = authenticator.authenticate(zoneIssuer, zoneIssuer);
        TransportResponse response = TokenEndpoint.send(transport, endpoint, form, auth, fetchTimeout);
        if (response.status() != 200) {
            throw TokenEndpoint.error(response, "token introspection request");
        }
        return parseResponse(response.body());
    }

    @Override
    public String toString() {
        return "TokenIntrospectionClient[issuer=" + issuer + ", credential="
                + authenticator.getClass().getName() + "]";
    }

    private static TokenIntrospection parseResponse(String body) {
        Map<String, Object> document = TokenEndpoint.parseObjectOrNull(body);
        if (document == null) {
            throw invalid("token introspection response is not a JSON object");
        }
        Object activeValue = document.get("active");
        if (!(activeValue instanceof Boolean active)) {
            throw invalid("token introspection response has no boolean active");
        }
        return new TokenIntrospection(
                active,
                optionalString(document, "token_type"),
                optionalString(document, "iss"),
                optionalString(document, "sub"),
                optionalString(document, "client_id"),
                audiences(document.get("aud")),
                scopes(document.get("scope")),
                optionalString(document, "sid"),
                optionalString(document, "jti"),
                optionalInstant(document, "iat"),
                optionalInstant(document, "exp"),
                document);
    }

    private static @Nullable String optionalString(Map<String, Object> document, String field) {
        Object value = document.get(field);
        if (value == null || value instanceof String) {
            return (String) value;
        }
        throw invalid("token introspection response has a " + field + " that is not a string");
    }

    private static List<String> audiences(@Nullable Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof String single) {
            return List.of(single);
        }
        if (value instanceof List<?> list) {
            List<String> result = new ArrayList<>(list.size());
            for (Object element : list) {
                if (!(element instanceof String string)) {
                    throw invalid("token introspection response has an aud that is not a string or list of strings");
                }
                result.add(string);
            }
            return result;
        }
        throw invalid("token introspection response has an aud that is not a string or list of strings");
    }

    private static List<String> scopes(@Nullable Object value) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof String string)) {
            throw invalid("token introspection response has a scope that is not a string");
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : string.trim().split("\\s+")) {
            if (!scope.isEmpty()) {
                scopes.add(scope);
            }
        }
        return scopes;
    }

    private static @Nullable Instant optionalInstant(Map<String, Object> document, String field) {
        Object value = document.get(field);
        if (value == null) {
            return null;
        }
        if (value instanceof Long || value instanceof Integer) {
            try {
                return Instant.ofEpochSecond(((Number) value).longValue());
            } catch (DateTimeException e) {
                throw invalid("token introspection response has an out-of-range " + field);
            }
        }
        throw invalid("token introspection response has a " + field + " that is not an integer");
    }

    private static OAuthProtocolException invalid(String message) {
        return new OAuthProtocolException(message, OAuthProtocolException.INVALID_RESPONSE);
    }

    private static void requireHttps(URI uri, String field) {
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new ConfigurationException(field + " must be an HTTPS URL");
        }
    }

    /** Configures a {@link TokenIntrospectionClient}. */
    public static final class Builder {

        private final URI issuer;
        private final @Nullable AuthorizationServerMetadata fixedMetadata;
        private @Nullable ClientAuthenticator credential;
        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer, @Nullable AuthorizationServerMetadata fixedMetadata) {
            this.issuer = issuer;
            this.fixedMetadata = fixedMetadata;
        }

        /**
         * Uses a confidential client credential for client authentication. A private-key JWT
         * assertion uses the zone issuer as its audience.
         *
         * @param credential the confidential client credential
         * @return this builder
         * @throws ConfigurationException when the credential lacks client authentication
         */
        public Builder credential(Credential credential) {
            if (!(credential instanceof ClientAuthenticator clientAuthenticator)) {
                throw new ConfigurationException("the credential does not provide client authentication");
            }
            this.credential = clientAuthenticator;
            return this;
        }

        /**
         * The transport for discovery and introspection requests. Configure custom transports
         * to send requests to the supplied URI over HTTPS with redirects disabled.
         *
         * @param transport the transport
         * @return this builder
         * @throws ConfigurationException if the transport follows redirects
         */
        public Builder transport(KeycardHttpTransport transport) {
            Objects.requireNonNull(transport, "transport").requireRedirectsDisabled();
            this.transport = transport;
            return this;
        }

        /**
         * Sends requests through this JDK client with redirects disabled.
         *
         * @param client the client
         * @return this builder
         * @throws ConfigurationException if the client follows redirects
         */
        public Builder httpClient(HttpClient client) {
            if (client.followRedirects() != HttpClient.Redirect.NEVER) {
                throw new ConfigurationException("token introspection requires HTTP redirects to be disabled");
            }
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each request.
         *
         * @param fetchTimeout the timeout; defaults to {@link KeycardHttpTransport#DEFAULT_TIMEOUT}
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            if (fetchTimeout.isNegative() || fetchTimeout.isZero()) {
                throw new ConfigurationException("fetchTimeout must be positive, got " + fetchTimeout);
            }
            this.fetchTimeout = fetchTimeout;
            return this;
        }

        /**
         * How long discovered metadata is reused.
         *
         * @param discoveryTtl the lifetime; defaults to one hour
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * How long a deterministic discovery failure is cached.
         *
         * @param negativeTtl the lifetime; defaults to one minute
         * @return this builder
         */
        public Builder negativeTtl(Duration negativeTtl) {
            this.negativeTtl = Objects.requireNonNull(negativeTtl, "negativeTtl");
            return this;
        }

        /**
         * Sets the clock used by this client's discovery cache.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Uses a caller-provided metadata cache when discovering endpoints.
         *
         * @param metadataCache the shared cache
         * @return this builder
         */
        public Builder metadataCache(AuthorizationServerMetadataCache metadataCache) {
            this.metadataCache = Objects.requireNonNull(metadataCache, "metadataCache");
            return this;
        }

        /**
         * Builds the client.
         *
         * @return the client
         * @throws ConfigurationException if no credential was configured
         */
        public TokenIntrospectionClient build() {
            if (credential == null) {
                throw new ConfigurationException("token introspection requires a credential");
            }
            return new TokenIntrospectionClient(this, credential);
        }
    }
}
