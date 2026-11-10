package ai.keycard.oauth;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Authorization server discovery (RFC 8414): fetches an issuer's metadata document.
 *
 * <p>Each {@link #discover} call performs one fetch and caches nothing. Callers that need the
 * metadata on every request share an {@link AuthorizationServerMetadataCache} instead.
 *
 * <pre>{@code
 * AuthorizationServerMetadata metadata =
 *         AuthorizationServerDiscovery.create().discover(URI.create("https://acme.keycard.cloud"));
 * }</pre>
 */
public final class AuthorizationServerDiscovery {

    /** The RFC 8414 well-known path, inserted between the issuer's host and path. */
    public static final String WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";

    private final KeycardHttpTransport transport;
    private final Duration fetchTimeout;

    private AuthorizationServerDiscovery(Builder builder) {
        this.transport = builder.transport;
        this.fetchTimeout = builder.fetchTimeout;
    }

    /**
     * Discovery over the default transport with the default 10 second fetch timeout.
     *
     * @return a new instance
     */
    public static AuthorizationServerDiscovery create() {
        return builder().build();
    }

    /**
     * A builder for a configured instance.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Fetches and validates the issuer's metadata.
     *
     * @param issuer the authorization server's issuer identifier, such as {@code
     *     https://acme.keycard.cloud}
     * @return the parsed metadata
     * @throws ConfigurationException when the issuer is empty or not an absolute http(s) URL
     * @throws HttpStatusException on a non-2xx response
     * @throws OAuthProtocolException on an issuer mismatch ({@link
     *     OAuthProtocolException#ISSUER_MISMATCH}) or a malformed document ({@link
     *     OAuthProtocolException#INVALID_METADATA})
     * @throws NetworkException on a transport failure or timeout
     */
    public AuthorizationServerMetadata discover(String issuer) {
        if (issuer.isBlank()) {
            throw new ConfigurationException("issuer must be a non-empty URL");
        }
        URI uri;
        try {
            uri = new URI(issuer);
        } catch (URISyntaxException e) {
            throw new ConfigurationException("issuer is not a valid URL: " + issuer, e);
        }
        return discover(uri);
    }

    /**
     * Fetches and validates the issuer's metadata.
     *
     * @param issuer the authorization server's issuer identifier
     * @return the parsed metadata
     * @throws ConfigurationException when the issuer is not an absolute http(s) URL
     * @throws HttpStatusException on a non-2xx response
     * @throws OAuthProtocolException on an issuer mismatch or a malformed document
     * @throws NetworkException on a transport failure or timeout
     */
    public AuthorizationServerMetadata discover(URI issuer) {
        URI url = metadataUrl(issuer);
        TransportResponse response =
                transport.send(TransportRequest.get(url, fetchTimeout).withHeader("Accept", "application/json"));
        if (!response.isSuccess()) {
            throw new HttpStatusException(
                    "discovery for " + issuer + " returned HTTP " + response.status(),
                    response.status(),
                    response.body());
        }
        return parse(issuer, response.body());
    }

    /**
     * The metadata URL for an issuer: the well-known segment goes between the host and any issuer
     * path (RFC 8414 §3.1).
     */
    static URI metadataUrl(URI issuer) {
        String scheme = issuer.getScheme();
        if (!issuer.isAbsolute()
                || scheme == null
                || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))
                || issuer.getRawAuthority() == null
                || issuer.getHost() == null) {
            throw new ConfigurationException("issuer must be an absolute http(s) URL, got " + issuer);
        }
        if (issuer.getRawQuery() != null || issuer.getRawFragment() != null) {
            throw new ConfigurationException("issuer must not carry a query or fragment, got " + issuer);
        }
        String path = issuer.getRawPath() == null ? "" : stripTrailingSlash(issuer.getRawPath());
        return URI.create(scheme.toLowerCase(Locale.ROOT) + "://" + issuer.getRawAuthority() + WELL_KNOWN_PATH + path);
    }

    static AuthorizationServerMetadata parse(URI issuer, String body) {
        Map<String, Object> document;
        try {
            document = JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            throw new OAuthProtocolException(
                    "metadata for " + issuer + " is not a JSON object", OAuthProtocolException.INVALID_METADATA, e);
        }

        Object documentIssuer = document.get("issuer");
        if (!(documentIssuer instanceof String issuerString) || issuerString.isEmpty()) {
            throw new OAuthProtocolException(
                    "metadata for " + issuer + " has no issuer", OAuthProtocolException.INVALID_METADATA);
        }
        // RFC 8414 §3.3: the response issuer must equal the requested one. A trailing slash is
        // ignored on both sides.
        if (!stripTrailingSlash(issuerString).equals(stripTrailingSlash(issuer.toString()))) {
            throw new OAuthProtocolException(
                    "metadata issuer " + issuerString + " does not match requested issuer " + issuer,
                    OAuthProtocolException.ISSUER_MISMATCH);
        }

        return new AuthorizationServerMetadata(
                parseUri(issuer, document, "issuer"),
                optionalUri(issuer, document, "token_endpoint"),
                optionalUri(issuer, document, "authorization_endpoint"),
                optionalUri(issuer, document, "jwks_uri"),
                optionalUri(issuer, document, "registration_endpoint"),
                optionalUri(issuer, document, "userinfo_endpoint"),
                optionalUri(issuer, document, "end_session_endpoint"),
                optionalUri(issuer, document, "device_authorization_endpoint"),
                stringList(issuer, document, "grant_types_supported"),
                stringList(issuer, document, "token_endpoint_auth_methods_supported"),
                stringList(issuer, document, "response_types_supported"),
                document);
    }

    private static @Nullable URI optionalUri(URI issuer, Map<String, Object> document, String field) {
        return document.get(field) == null ? null : parseUri(issuer, document, field);
    }

    private static URI parseUri(URI issuer, Map<String, Object> document, String field) {
        if (document.get(field) instanceof String value) {
            try {
                URI uri = new URI(value);
                if (uri.isAbsolute()) {
                    return uri;
                }
            } catch (URISyntaxException e) {
                // fall through to the typed error
            }
        }
        throw new OAuthProtocolException(
                "metadata for " + issuer + " has an invalid " + field, OAuthProtocolException.INVALID_METADATA);
    }

    private static List<String> stringList(URI issuer, Map<String, Object> document, String field) {
        Object value = document.get(field);
        if (value == null) {
            return List.of();
        }
        if (value instanceof List<?> list) {
            List<String> strings = new ArrayList<>(list.size());
            for (Object element : list) {
                if (!(element instanceof String string)) {
                    break;
                }
                strings.add(string);
            }
            if (strings.size() == list.size()) {
                return strings;
            }
        }
        throw new OAuthProtocolException(
                "metadata for " + issuer + " has a " + field + " that is not a list of strings",
                OAuthProtocolException.INVALID_METADATA);
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    /** Configures an {@link AuthorizationServerDiscovery}. */
    public static final class Builder {

        private KeycardHttpTransport transport;
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;

        private Builder() {
            this.transport = KeycardHttpTransport.create();
        }

        /**
         * The transport to send requests through. Defaults to {@link KeycardHttpTransport#create()}.
         *
         * @param transport the transport
         * @return this builder
         */
        public Builder transport(KeycardHttpTransport transport) {
            this.transport = Objects.requireNonNull(transport, "transport");
            return this;
        }

        /**
         * Sends requests through a caller-configured JDK client (proxy, truststore, mTLS).
         *
         * @param client the client
         * @return this builder
         */
        public Builder httpClient(HttpClient client) {
            return transport(KeycardHttpTransport.of(client));
        }

        /**
         * The bound on each discovery request. Defaults to 10 seconds.
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
         * Builds the discovery instance.
         *
         * @return the instance
         */
        public AuthorizationServerDiscovery build() {
            return new AuthorizationServerDiscovery(this);
        }
    }
}
