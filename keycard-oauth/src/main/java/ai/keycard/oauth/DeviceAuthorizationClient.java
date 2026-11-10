package ai.keycard.oauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * The OAuth 2.0 device authorization grant (RFC 8628) from the device's side, for a process with
 * no browser and no redirect URI.
 *
 * <pre>{@code
 * DeviceAuthorizationClient device = DeviceAuthorizationClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .credential(WorkloadIdentity.of(source))
 *         .build();
 * DeviceAuthorization authorization = device.requestDeviceAuthorization(
 *         List.of("openid"), List.of(URI.create("https://api.example.com")));
 * System.out.println("Open " + authorization.verificationUri() + " and enter " + authorization.userCode());
 * TokenResponse token = device.pollUntilDone(authorization);
 * }</pre>
 *
 * <p>Every request in a flow authenticates the same way: with a credential's client
 * authentication, called once per request with that request's endpoint, or as a public client
 * sending {@code client_id}. The returned token is never associated with a resource; to get a
 * token for one resource, refresh it with {@link AuthorizationCodeClient#refresh}. Keeps no state
 * between calls and is safe to share between threads.
 */
public final class DeviceAuthorizationClient {

    /** The device code grant type (RFC 8628 §3.4). */
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    private static final Duration SLOW_DOWN_INCREMENT = Duration.ofSeconds(5);

    /** Waits between polls. The default sleeps the calling thread. */
    @FunctionalInterface
    public interface Sleeper {

        /**
         * Waits.
         *
         * @param duration how long
         * @throws InterruptedException when the thread is interrupted while waiting
         */
        void sleep(Duration duration) throws InterruptedException;

        /**
         * Sleeps the calling thread.
         *
         * @return the system sleeper
         */
        static Sleeper system() {
            return duration -> Thread.sleep(duration.toMillis());
        }
    }

    private final URI issuer;
    private final @Nullable AuthorizationServerMetadata fixedMetadata;
    private final @Nullable String clientId;
    private final @Nullable ClientAuthenticator credential;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final Clock clock;
    private final Sleeper sleeper;
    private final AuthorizationServerMetadataCache metadata;

    private DeviceAuthorizationClient(Builder builder) {
        this.issuer = builder.issuer;
        this.fixedMetadata = builder.fixedMetadata;
        this.clientId = builder.clientId;
        this.credential = builder.credential;
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
        this.clock = builder.clock;
        this.sleeper = builder.sleeper;
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
     * A builder that resolves the zone's endpoints by discovery.
     *
     * @param issuer the zone's issuer
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
        return new Builder(issuer, null);
    }

    /**
     * A builder that uses metadata the caller already holds; no discovery request is made.
     *
     * @param metadata the zone's authorization server metadata
     * @return a new builder
     */
    public static Builder builder(AuthorizationServerMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata");
        return new Builder(metadata.issuer(), metadata);
    }

    /**
     * Requests a device code and a user code (RFC 8628 §3.1).
     *
     * @param scopes requested scopes, sent space-joined; empty sends none
     * @param resources RFC 8707 resources, one {@code resource} parameter each
     * @return the authorization to show the person and poll with
     * @throws ConfigurationException when the zone advertises no device authorization endpoint
     * @throws OAuthErrorException such as {@code invalid_target}, {@code invalid_scope}, {@code
     *     unauthorized_client} or {@code invalid_client}
     * @throws OAuthProtocolException with code {@code invalid_response} for a malformed response
     * @throws KeycardException for discovery, HTTP and network failures
     */
    public DeviceAuthorization requestDeviceAuthorization(List<String> scopes, List<URI> resources) {
        AuthorizationServerMetadata meta = metadata();
        URI endpoint = meta.deviceAuthorizationEndpoint();
        if (endpoint == null) {
            throw new ConfigurationException("the zone " + issuer + " advertises no device_authorization_endpoint");
        }
        Map<String, List<String>> form = new LinkedHashMap<>();
        if (!scopes.isEmpty()) {
            form.put("scope", List.of(String.join(" ", scopes)));
        }
        if (!resources.isEmpty()) {
            List<String> values = new ArrayList<>();
            resources.forEach(resource -> values.add(resource.toString()));
            form.put("resource", values);
        }
        TransportResponse response =
                TokenEndpoint.send(transport, endpoint, form, clientAuthentication(endpoint), fetchTimeout);
        if (!response.isSuccess()) {
            throw TokenEndpoint.error(response, "device authorization request");
        }
        return parse(response.body(), clock.instant());
    }

    /**
     * Polls the token endpoint once (RFC 8628 §3.4). {@code authorization_pending} and {@code
     * slow_down} come back as retryable {@link OAuthErrorException}s; a caller looping on this
     * itself must wait the interval, add 5 seconds on {@code slow_down}, and wait longer after a
     * connection timeout (RFC 8628 §3.5).
     *
     * @param authorization the device authorization; only its device code is read
     * @return the token
     * @throws OAuthErrorException for every OAuth error, including the pending states; {@code
     *     expired_token}, {@code access_denied} and {@code invalid_grant} are not retryable
     * @throws KeycardException for discovery, HTTP, network and response-format failures
     */
    public TokenResponse pollOnce(DeviceAuthorization authorization) {
        AuthorizationServerMetadata meta = metadata();
        URI endpoint = meta.tokenEndpoint();
        if (endpoint == null) {
            throw new ConfigurationException("the zone " + issuer + " advertises no token_endpoint");
        }
        Map<String, List<String>> form = new LinkedHashMap<>();
        form.put("grant_type", List.of(GRANT_TYPE));
        form.put("device_code", List.of(authorization.deviceCode()));
        return TokenEndpoint.post(
                transport,
                endpoint,
                form,
                clientAuthentication(endpoint),
                fetchTimeout,
                "device code poll",
                Set.of("invalid_grant"));
    }

    /**
     * Polls until the person approves or denies, starting at the authorization's interval.
     *
     * @param authorization the device authorization
     * @return the token
     * @throws InterruptedException when the thread is interrupted while waiting or while a poll is
     *     in flight; no further request is sent
     * @throws OAuthErrorException for a terminal OAuth error, such as {@code access_denied}, or
     *     {@code expired_token} when the next poll would start after the codes expire
     * @throws DevicePollException after a network error, a 5xx or a 429; resume with its interval
     * @throws KeycardException for any other failure, returned as is
     */
    public TokenResponse pollUntilDone(DeviceAuthorization authorization) throws InterruptedException {
        return pollUntilDone(authorization, authorization.interval());
    }

    /**
     * Polls until the person approves or denies, waiting {@code interval} before the first poll.
     * Waits {@code interval} before each poll, polls again on {@code authorization_pending}, and
     * adds 5 seconds to the interval on {@code slow_down} (RFC 8628 §3.5). Every request is bounded
     * by the fetch timeout; the waits and the loop are not.
     *
     * @param authorization the device authorization
     * @param interval the starting interval, such as the one from a {@link DevicePollException}
     * @return the token
     * @throws ConfigurationException when {@code interval} is shorter than the authorization's
     * @throws InterruptedException when the thread is interrupted while waiting or while a poll is
     *     in flight; no further request is sent
     * @throws OAuthErrorException for a terminal OAuth error, such as {@code access_denied}, or
     *     {@code expired_token} when the next poll would start after the codes expire
     * @throws DevicePollException after a network error, a 5xx or a 429; resume with its interval
     * @throws KeycardException for any other failure, returned as is
     */
    public TokenResponse pollUntilDone(DeviceAuthorization authorization, Duration interval)
            throws InterruptedException {
        Objects.requireNonNull(authorization, "authorization");
        Objects.requireNonNull(interval, "interval");
        if (interval.compareTo(authorization.interval()) < 0) {
            throw new ConfigurationException(
                    "interval " + interval + " is shorter than the authorization's " + authorization.interval());
        }
        Duration current = interval;
        while (true) {
            Instant now = clock.instant();
            if (now.plus(current).isAfter(authorization.expiresAt())) {
                throw expired(authorization);
            }
            sleeper.sleep(current);
            if (Thread.interrupted()) {
                throw new InterruptedException("device polling was interrupted");
            }
            try {
                return pollOnce(authorization);
            } catch (OAuthErrorException e) {
                if (isServerSide(e.status())) {
                    throw stopped(e, current);
                }
                switch (e.error()) {
                    case "authorization_pending" -> {
                        // the person hasn't confirmed yet
                    }
                    case "slow_down" -> current = current.plus(SLOW_DOWN_INCREMENT);
                    default -> throw e;
                }
            } catch (HttpStatusException e) {
                if (isServerSide(e.status())) {
                    throw stopped(e, current);
                }
                throw e;
            } catch (NetworkException e) {
                boolean interruptFlag = Thread.interrupted();
                if (interruptFlag || e.getCause() instanceof InterruptedException) {
                    InterruptedException interrupted = new InterruptedException("device polling was interrupted");
                    interrupted.initCause(e);
                    throw interrupted;
                }
                throw stopped(e, current.multipliedBy(2));
            }
        }
    }

    private static boolean isServerSide(int status) {
        return status == 429 || status >= 500;
    }

    private static DevicePollException stopped(KeycardException cause, Duration interval) {
        return new DevicePollException(
                "device polling stopped: " + cause.getMessage() + "; resume with interval " + interval,
                interval,
                cause);
    }

    private static OAuthErrorException expired(DeviceAuthorization authorization) {
        return new OAuthErrorException(
                "the device code expires at " + authorization.expiresAt() + ", before the next poll",
                0,
                "",
                "expired_token",
                "the device code expired before the person confirmed",
                null,
                false);
    }

    private AuthorizationServerMetadata metadata() {
        return fixedMetadata != null ? fixedMetadata : metadata.get(issuer);
    }

    private ClientAuthentication clientAuthentication(URI endpoint) {
        if (credential != null) {
            return credential.authenticate(issuer, endpoint);
        }
        return ClientAuthentication.formFields(Map.of("client_id", Objects.requireNonNull(clientId)));
    }

    static DeviceAuthorization parse(String body, Instant received) {
        Map<String, Object> document = TokenEndpoint.parseObjectOrNull(body);
        if (document == null) {
            throw invalid("the device authorization response is not a JSON object");
        }
        String deviceCode = requiredString(document, "device_code");
        String userCode = requiredString(document, "user_code");
        URI verificationUri = uri(requiredString(document, "verification_uri"), "verification_uri");
        Object complete = document.get("verification_uri_complete");
        URI verificationUriComplete = null;
        if (complete != null) {
            if (!(complete instanceof String value) || value.isEmpty()) {
                throw invalid("the device authorization response has an invalid verification_uri_complete");
            }
            verificationUriComplete = uri(value, "verification_uri_complete");
        }
        Duration expiresIn = positiveSeconds(document, "expires_in", null);
        Duration interval = positiveSeconds(document, "interval", DeviceAuthorization.DEFAULT_INTERVAL);
        return new DeviceAuthorization(
                deviceCode,
                userCode,
                verificationUri,
                verificationUriComplete,
                expiresIn,
                interval,
                received.plus(expiresIn));
    }

    private static String requiredString(Map<String, Object> document, String field) {
        if (document.get(field) instanceof String value && !value.isEmpty()) {
            return value;
        }
        throw invalid("the device authorization response has no " + field);
    }

    private static URI uri(String value, String field) {
        try {
            URI uri = URI.create(value);
            if (uri.isAbsolute()) {
                return uri;
            }
        } catch (IllegalArgumentException e) {
            // falls through to the typed error
        }
        throw invalid("the device authorization response has an invalid " + field);
    }

    private static Duration positiveSeconds(Map<String, Object> document, String field, @Nullable Duration fallback) {
        Object value = document.get(field);
        if (value == null && fallback != null) {
            return fallback;
        }
        if ((value instanceof Long || value instanceof Integer) && ((Number) value).longValue() > 0) {
            return Duration.ofSeconds(((Number) value).longValue());
        }
        throw invalid("the device authorization response has " + (value == null ? "no " : "an invalid ") + field);
    }

    private static OAuthProtocolException invalid(String message) {
        return new OAuthProtocolException(message, OAuthProtocolException.INVALID_RESPONSE);
    }

    /** Configures a {@link DeviceAuthorizationClient}. Set a credential or a client id, not both. */
    public static final class Builder {

        private final URI issuer;
        private final @Nullable AuthorizationServerMetadata fixedMetadata;
        private @Nullable String clientId;
        private @Nullable ClientAuthenticator credential;
        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration discoveryTtl = AuthorizationServerMetadataCache.DEFAULT_DISCOVERY_TTL;
        private Duration negativeTtl = AuthorizationServerMetadataCache.DEFAULT_NEGATIVE_TTL;
        private Clock clock = Clock.systemUTC();
        private Sleeper sleeper = Sleeper.system();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer, @Nullable AuthorizationServerMetadata fixedMetadata) {
            this.issuer = issuer;
            this.fixedMetadata = fixedMetadata;
        }

        /**
         * Authenticates every request with the credential's client authentication.
         *
         * @param credential the credential
         * @return this builder
         * @throws ConfigurationException when the credential doesn't provide client authentication
         */
        public Builder credential(Credential credential) {
            if (!(Objects.requireNonNull(credential, "credential") instanceof ClientAuthenticator authenticator)) {
                throw new ConfigurationException(
                        credential.getClass().getName() + " does not provide client authentication");
            }
            this.credential = authenticator;
            return this;
        }

        /**
         * Runs as a public client, sending {@code client_id} in the body.
         *
         * @param clientId the client id
         * @return this builder
         */
        public Builder clientId(String clientId) {
            Objects.requireNonNull(clientId, "clientId");
            if (clientId.isEmpty()) {
                throw new ConfigurationException("clientId must not be empty");
            }
            this.clientId = clientId;
            return this;
        }

        /**
         * The transport for discovery and the grant's requests.
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
         * The bound on each request, including each poll.
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
         * How long discovered metadata is cached.
         *
         * @param discoveryTtl the lifetime
         * @return this builder
         */
        public Builder discoveryTtl(Duration discoveryTtl) {
            this.discoveryTtl = Objects.requireNonNull(discoveryTtl, "discoveryTtl");
            return this;
        }

        /**
         * How long a failed discovery is cached.
         *
         * @param negativeTtl the lifetime
         * @return this builder
         */
        public Builder negativeTtl(Duration negativeTtl) {
            this.negativeTtl = Objects.requireNonNull(negativeTtl, "negativeTtl");
            return this;
        }

        /**
         * The clock that stamps {@link DeviceAuthorization#expiresAt()} and ends the loop. Pair a
         * test clock with a {@linkplain #sleeper sleeper} that advances it.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * How the loop waits between polls.
         *
         * @param sleeper the sleeper; defaults to {@link Sleeper#system()}
         * @return this builder
         */
        public Builder sleeper(Sleeper sleeper) {
            this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
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
         * @throws ConfigurationException unless exactly one of a credential and a client id is set
         */
        public DeviceAuthorizationClient build() {
            if ((credential == null) == (clientId == null)) {
                throw new ConfigurationException(
                        "a device authorization client needs a credential or a client id, not both");
            }
            return new DeviceAuthorizationClient(this);
        }
    }
}
