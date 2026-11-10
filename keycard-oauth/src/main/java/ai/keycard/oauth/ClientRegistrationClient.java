package ai.keycard.oauth;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Registers OAuth clients with a zone (RFC 7591), for tools that bootstrap themselves rather than
 * being provisioned by an operator. The {@code registration_endpoint} is discovered.
 *
 * <pre>{@code
 * RegisteredClient client = ClientRegistrationClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .build()
 *         .register(ClientRegistrationRequest.builder().clientName("Payments CLI").build());
 * }</pre>
 *
 * <p>Safe to share between threads.
 */
public final class ClientRegistrationClient {

    /**
     * The RFC 7591 §3.2.2 codes, which describe the request's metadata: sending it again unchanged
     * can't succeed, so they're never retryable.
     */
    static final java.util.Set<String> REGISTRATION_ERRORS = java.util.Set.of(
            "invalid_redirect_uri",
            "invalid_client_metadata",
            "invalid_software_statement",
            "unapproved_software_statement");

    private final URI issuer;
    private final @Nullable String initialAccessToken;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final AuthorizationServerMetadataCache metadata;

    private ClientRegistrationClient(Builder builder) {
        this.issuer = builder.issuer;
        this.initialAccessToken = builder.initialAccessToken;
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
                        .build();
    }

    /**
     * A builder for a zone.
     *
     * @param issuer the zone's issuer
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
        return new Builder(issuer);
    }

    /**
     * Registers a client.
     *
     * @param request the client metadata
     * @return the registered client
     * @throws ConfigurationException when the zone advertises no registration endpoint
     * @throws OAuthErrorException for an RFC 7591 §3.2.2 error, such as {@code
     *     invalid_redirect_uri} or {@code invalid_client_metadata}, which are never retryable
     * @throws OAuthProtocolException with code {@code invalid_response} when the response has no
     *     {@code client_id} or isn't JSON
     * @throws KeycardException for discovery, HTTP and network failures
     */
    public RegisteredClient register(ClientRegistrationRequest request) {
        URI endpoint = metadata.get(issuer).registrationEndpoint();
        if (endpoint == null) {
            throw new ConfigurationException("the zone " + issuer + " advertises no registration_endpoint");
        }
        TransportRequest post = TransportRequest.post(
                        endpoint, "application/json", JSONObjectUtils.toJSONString(request.metadata()), fetchTimeout)
                .withHeader("Accept", "application/json");
        if (initialAccessToken != null) {
            post = post.withHeader("Authorization", "Bearer " + initialAccessToken);
        }
        TransportResponse response = transport.send(post);
        if (!response.isSuccess()) {
            throw TokenEndpoint.error(response, "client registration", REGISTRATION_ERRORS);
        }
        Map<String, Object> document = TokenEndpoint.parseObjectOrNull(response.body());
        if (document == null) {
            throw invalid("the registration response is not a JSON object");
        }
        if (!(document.get("client_id") instanceof String clientId) || clientId.isEmpty()) {
            throw invalid("the registration response has no client_id");
        }
        Object managementUri = document.get("registration_client_uri");
        return new RegisteredClient(
                clientId,
                string(document, "client_secret"),
                instant(document, "client_id_issued_at"),
                instant(document, "client_secret_expires_at"),
                string(document, "registration_access_token"),
                managementUri instanceof String uri && !uri.isEmpty() ? URI.create(uri) : null,
                document);
    }

    private static @Nullable String string(Map<String, Object> document, String field) {
        return document.get(field) instanceof String value ? value : null;
    }

    private static @Nullable Instant instant(Map<String, Object> document, String field) {
        return document.get(field) instanceof Number seconds ? Instant.ofEpochSecond(seconds.longValue()) : null;
    }

    private static OAuthProtocolException invalid(String message) {
        return new OAuthProtocolException(message, OAuthProtocolException.INVALID_RESPONSE);
    }

    /** Configures a {@link ClientRegistrationClient}. */
    public static final class Builder {

        private final URI issuer;
        private @Nullable String initialAccessToken;
        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer) {
            this.issuer = issuer;
        }

        /**
         * An initial access token (RFC 7591 §3.1), sent as a Bearer credential, for zones that
         * require registration requests to be authenticated.
         *
         * @param initialAccessToken the token
         * @return this builder
         */
        public Builder initialAccessToken(String initialAccessToken) {
            this.initialAccessToken = Objects.requireNonNull(initialAccessToken, "initialAccessToken");
            return this;
        }

        /**
         * The transport for discovery and registration.
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
         * @param fetchTimeout the timeout
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = Objects.requireNonNull(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * The clock for the metadata cache.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * Shares a metadata cache with other clients.
         *
         * @param metadataCache the cache
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
         */
        public ClientRegistrationClient build() {
            return new ClientRegistrationClient(this);
        }
    }
}
