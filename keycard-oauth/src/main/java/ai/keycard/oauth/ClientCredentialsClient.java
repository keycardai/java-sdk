package ai.keycard.oauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Requests tokens for a workload itself with the {@code client_credentials} grant (RFC 6749
 * §4.4): no user, no subject token.
 *
 * <pre>{@code
 * ClientCredentialsClient client = ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .credential(ClientSecret.of("my-client", secret))
 *         .build();
 * TokenResponse token = client.requestToken(ClientCredentialsRequest.builder()
 *         .resource(URI.create("https://api.example.com"))
 *         .build());
 * }</pre>
 *
 * <p>The token endpoint is discovered once and cached (see {@link
 * AuthorizationServerMetadataCache}). Each call sends exactly one token request; nothing is
 * retried and no token is cached. The client is safe to share between threads.
 */
public final class ClientCredentialsClient {

    private final URI issuer;
    private final @Nullable ClientAuthenticator credential;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final AuthorizationServerMetadataCache metadata;

    private ClientCredentialsClient(Builder builder) {
        this.issuer = builder.issuer;
        this.credential = builder.credential;
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.metadata = builder.metadataCache != null
                ? builder.metadataCache
                : AuthorizationServerMetadataCache.builder()
                        .discovery(AuthorizationServerDiscovery.builder()
                                .transport(builder.transport)
                                .fetchTimeout(builder.fetchTimeout)
                                .build())
                        .clock(builder.clock)
                        .discoveryTtl(builder.discoveryTtl)
                        .negativeTtl(builder.negativeTtl)
                        .build();
    }

    /**
     * A builder for a client against one zone.
     *
     * @param issuer the zone's issuer, such as {@code https://acme.keycard.cloud}
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    /**
     * Requests a token with no scope or resource.
     *
     * @return the token
     * @throws OAuthErrorException when the zone answers with an OAuth error, such as {@code
     *     invalid_client}
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse requestToken() {
        return requestToken(ClientCredentialsRequest.EMPTY);
    }

    /**
     * Requests a token.
     *
     * @param request the scope, resource and optional caller-supplied assertion
     * @return the token
     * @throws ConfigurationException when the client has no credential and the request carries
     *     no assertion, or a multi-zone credential holds nothing for this zone
     * @throws OAuthErrorException when the zone answers with an OAuth error, such as {@code
     *     invalid_client}
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse requestToken(ClientCredentialsRequest request) {
        if (request.clientAssertion() == null && credential == null) {
            throw new ConfigurationException(
                    "client credentials needs a credential, or a clientAssertion on the request");
        }
        URI endpoint = metadata.tokenEndpoint(issuer);

        Map<String, List<String>> form = new LinkedHashMap<>();
        form.put("grant_type", List.of(TokenTypes.CLIENT_CREDENTIALS_GRANT));
        if (request.scope() != null) {
            form.put("scope", List.of(request.scope()));
        }
        if (request.resource() != null) {
            form.put("resource", List.of(request.resource().toString()));
        }

        ClientAuthentication auth;
        if (request.clientAssertion() != null) {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("client_assertion", request.clientAssertion());
            fields.put("client_assertion_type", Objects.requireNonNull(request.clientAssertionType()));
            auth = ClientAuthentication.formFields(fields);
        } else {
            auth = Objects.requireNonNull(credential).authenticate(issuer, endpoint);
        }
        return TokenEndpoint.post(transport, endpoint, form, auth, fetchTimeout, "client credentials");
    }

    /**
     * The zone this client requests tokens from.
     *
     * @return the issuer
     */
    public URI issuer() {
        return issuer;
    }

    /** Configures a {@link ClientCredentialsClient}. */
    public static final class Builder {

        private final URI issuer;
        private @Nullable ClientAuthenticator credential;
        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer) {
            AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
            this.issuer = issuer;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The credential that authenticates the client. It must provide client authentication
         * ({@link ClientAuthenticator}), as {@link ClientSecret} does.
         *
         * @param credential the credential
         * @return this builder
         * @throws ConfigurationException when the credential can't authenticate the client
         */
        public Builder credential(Credential credential) {
            Objects.requireNonNull(credential, "credential");
            if (!(credential instanceof ClientAuthenticator authenticator)) {
                throw new ConfigurationException(credential.getClass().getName()
                        + " does not provide client authentication, which client credentials needs");
            }
            this.credential = authenticator;
            return this;
        }

        /**
         * Client authentication on its own, for a credential implemented outside the SDK.
         *
         * @param authenticator supplies the headers and form fields
         * @return this builder
         */
        public Builder clientAuthenticator(ClientAuthenticator authenticator) {
            this.credential = Objects.requireNonNull(authenticator, "authenticator");
            return this;
        }

        /**
         * The transport for discovery and token requests. Defaults to {@link
         * KeycardHttpTransport#create()}.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through a caller-configured JDK client.
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each discovery and token request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
         * @return this builder
         * @throws ConfigurationException when the duration is zero or negative
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            if (fetchTimeout.isNegative() || fetchTimeout.isZero()) {
                throw new ConfigurationException("fetchTimeout must be positive, got " + fetchTimeout);
            }
            this.fetchTimeout = fetchTimeout;
            return this;
        }

        /**
         * How long the discovered token endpoint is reused. Defaults to 1 hour.
         *
         * @param discoveryTtl a positive duration
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * How long a deterministic discovery failure is remembered. Defaults to 1 minute.
         *
         * @param negativeTtl a duration of zero or more
         * @return this builder
         */
        public Builder negativeTtl(Duration negativeTtl) {
            this.negativeTtl = Objects.requireNonNull(negativeTtl, "negativeTtl");
            return this;
        }

        /**
         * The clock for discovery TTLs. Defaults to the system UTC clock.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A metadata cache to share with other clients for the same zones. When set, it replaces
         * the cache this builder would otherwise create, and the TTL and clock settings here are
         * not used.
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
         * @throws ConfigurationException when a TTL is out of range
         */
        public ClientCredentialsClient build() {
            return new ClientCredentialsClient(this);
        }
    }
}
