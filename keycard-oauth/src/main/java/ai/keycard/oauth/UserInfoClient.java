package ai.keycard.oauth;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * Fetches the signed-in user's claims from a zone's UserInfo endpoint. Zone access tokens carry no
 * identity claims such as {@code email} or {@code groups}; they live here.
 *
 * <pre>{@code
 * UserInfo user = UserInfoClient.builder(URI.create("https://acme.keycard.cloud")).build()
 *         .userInfo(accessToken);
 * }</pre>
 *
 * <p>Each call is one request; claims can change server side, so caching is the caller's choice.
 */
public final class UserInfoClient {

    private static final Pattern ERROR_PARAM = Pattern.compile("error=\"([^\"]*)\"");
    private static final Pattern ERROR_DESCRIPTION_PARAM = Pattern.compile("error_description=\"([^\"]*)\"");

    private final URI issuer;
    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;
    private final AuthorizationServerMetadataCache metadata;

    private UserInfoClient(Builder builder) {
        this.issuer = builder.issuer;
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
     * A builder for a client against one zone.
     *
     * @param issuer the zone's issuer
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    /**
     * The user's claims for an access token.
     *
     * @param accessToken the user's access token
     * @return the claims
     * @throws ConfigurationException when the zone advertises no UserInfo endpoint, before any
     *     request
     * @throws OAuthErrorException with {@code invalid_token} when the endpoint answers 401
     * @throws OAuthProtocolException for a body without {@code sub}, a body that isn't JSON, or a
     *     signed ({@code application/jwt}) response
     * @throws KeycardException for discovery, HTTP and network failures
     */
    public UserInfo userInfo(String accessToken) {
        Objects.requireNonNull(accessToken, "accessToken");
        URI endpoint = metadata.get(issuer).userinfoEndpoint();
        if (endpoint == null) {
            throw new ConfigurationException("the zone at " + issuer + " advertises no userinfo_endpoint");
        }
        TransportResponse response = transport.send(TransportRequest.get(endpoint, fetchTimeout)
                .withHeader("Authorization", "Bearer " + accessToken)
                .withHeader("Accept", "application/json"));
        if (response.status() == 401) {
            String challenge = response.header("WWW-Authenticate");
            String error = match(ERROR_PARAM, challenge);
            String description = match(ERROR_DESCRIPTION_PARAM, challenge);
            throw new OAuthErrorException(
                    "the UserInfo endpoint rejected the token" + (description == null ? "" : ": " + description),
                    401,
                    response.body(),
                    error == null ? "invalid_token" : error,
                    description,
                    null);
        }
        if (!response.isSuccess()) {
            throw TokenEndpoint.error(response, "UserInfo request");
        }
        String contentType = response.header("Content-Type");
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).startsWith("application/jwt")) {
            throw new OAuthProtocolException(
                    "signed UserInfo responses (application/jwt) are not supported", "unsupported_content_type");
        }
        Map<String, Object> claims;
        try {
            claims = JSONObjectUtils.parse(response.body());
        } catch (ParseException e) {
            throw new OAuthProtocolException("the UserInfo response is not a JSON object", "invalid_response", e);
        }
        if (claims == null) {
            throw new OAuthProtocolException("the UserInfo response is not a JSON object", "invalid_response");
        }
        if (!(claims.get("sub") instanceof String sub) || sub.isEmpty()) {
            throw new OAuthProtocolException("the UserInfo response has no sub", "invalid_response");
        }
        return new UserInfo(sub, claims);
    }

    private static @Nullable String match(Pattern pattern, @Nullable String value) {
        if (value == null) {
            return null;
        }
        Matcher matcher = pattern.matcher(value);
        return matcher.find() ? matcher.group(1) : null;
    }

    /** Configures a {@link UserInfoClient}. */
    public static final class Builder {

        private final URI issuer;
        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Clock clock = Clock.systemUTC();
        private @Nullable AuthorizationServerMetadataCache metadataCache;

        private Builder(URI issuer) {
            AuthorizationServerDiscovery.metadataUrl(Objects.requireNonNull(issuer, "issuer"));
            this.issuer = issuer;
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The transport for discovery and UserInfo requests.
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
         * The bound on each request. Defaults to 10 seconds.
         *
         * @param fetchTimeout a positive duration
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
         * The clock for discovery TTLs.
         *
         * @param clock the clock
         * @return this builder
         */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        /**
         * A metadata cache to share, such as the one an {@link AuthorizationCodeClient} uses.
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
         */
        public UserInfoClient build() {
            return new UserInfoClient(this);
        }
    }
}
