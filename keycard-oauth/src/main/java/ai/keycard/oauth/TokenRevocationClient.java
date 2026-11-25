package ai.keycard.oauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Revokes tokens using RFC 7009. Revoking a Keycard refresh token revokes its session.
 */
public final class TokenRevocationClient {

    private final URI issuer;
    private final @Nullable AuthorizationServerMetadata fixedMetadata;
    private final AuthorizationServerMetadataCache metadataCache;
    private final ClientAuthenticator authenticator;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;

    private TokenRevocationClient(Builder builder, ClientAuthenticator authenticator) {
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
     * A builder that resolves the revocation endpoint by discovery.
     *
     * @param issuer the zone's issuer
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
        return new Builder(issuer, null);
    }

    /**
     * A builder that uses metadata the caller already holds.
     *
     * @param metadata the zone's authorization server metadata
     * @return a builder that skips discovery
     */
    public static Builder builder(AuthorizationServerMetadata metadata) {
        return new Builder(metadata.issuer(), metadata);
    }

    /**
     * Revokes a token with the default {@code refresh_token} hint.
     *
     * @param token the token to revoke
     * @throws ConfigurationException if the token is missing or empty or the zone advertises no
     *     revocation endpoint
     * @throws KeycardException on discovery, OAuth, HTTP or network failures
     */
    public void revokeToken(String token) {
        revokeToken(token, "refresh_token");
    }

    /**
     * Revokes a token. HTTP 200 succeeds regardless of the response body, including when the
     * server treats the token as unknown, invalid, expired, or already revoked.
     *
     * @param token the token to revoke
     * @param tokenTypeHint the hint to send as {@code token_type_hint}
     * @throws ConfigurationException if the token is missing or empty or the zone advertises no
     *     revocation endpoint
     * @throws OAuthErrorException if the server returns an OAuth error such as {@code
     *     invalid_client}, {@code invalid_grant}, or {@code unsupported_token_type}
     * @throws KeycardException on discovery, HTTP or network failures
     */
    public void revokeToken(String token, String tokenTypeHint) {
        if (token == null || token.isEmpty()) {
            throw new ConfigurationException("token must not be empty");
        }
        Map<String, List<String>> form = Map.of("token", List.of(token), "token_type_hint", List.of(tokenTypeHint));
        AuthorizationServerMetadata metadata = fixedMetadata != null ? fixedMetadata : metadataCache.get(issuer);
        URI endpoint = metadata.revocationEndpoint();
        if (endpoint == null) {
            if (fixedMetadata == null) {
                metadataCache.expireMissingEndpoint(issuer, metadata);
            }
            throw new ConfigurationException("the zone " + issuer + " advertises no revocation_endpoint");
        }

        // Revocation uses the zone issuer as the private-key JWT audience.
        URI zoneIssuer = metadata.issuer();
        ClientAuthentication auth = authenticator.authenticate(zoneIssuer, zoneIssuer);
        TransportResponse response = TokenEndpoint.send(transport, endpoint, form, auth, fetchTimeout);
        if (response.status() != 200) {
            throw TokenEndpoint.error(response, "token revocation request");
        }
    }

    /** Configures a {@link TokenRevocationClient}. */
    public static final class Builder {

        private final URI issuer;
        private final @Nullable AuthorizationServerMetadata fixedMetadata;
        private @Nullable String clientId;
        private @Nullable String clientSecret;
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
         * Sets the client id for public or HTTP Basic authentication.
         *
         * @param clientId the client id
         * @return this builder
         */
        public Builder clientId(String clientId) {
            if (clientId.isEmpty()) {
                throw new ConfigurationException("clientId must not be empty");
            }
            this.clientId = clientId;
            return this;
        }

        /**
         * Uses HTTP Basic with the configured client id and secret.
         *
         * @param clientSecret the client secret
         * @return this builder
         */
        public Builder clientSecret(String clientSecret) {
            if (clientSecret.isEmpty()) {
                throw new ConfigurationException("clientSecret must not be empty");
            }
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Uses an application credential's client authentication. A private-key JWT assertion
         * uses the zone issuer as its audience.
         *
         * @param credential the application credential
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
         * The transport for discovery and revocation requests.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through this JDK client.
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
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
         * @throws ConfigurationException unless configured with either a credential or a client id
         *     with an optional secret
         */
        public TokenRevocationClient build() {
            if (credential != null) {
                if (clientId != null || clientSecret != null) {
                    throw new ConfigurationException("a credential must be used without a client id or secret");
                }
                return new TokenRevocationClient(this, credential);
            }
            if (clientId == null) {
                throw new ConfigurationException("token revocation requires a credential or client id");
            }
            ClientAuthentication auth = clientSecret == null
                    ? ClientAuthentication.formFields(Map.of("client_id", clientId))
                    : ClientAuthentication.basic(clientId, clientSecret);
            return new TokenRevocationClient(this, (issuer, endpoint) -> auth);
        }
    }
}
