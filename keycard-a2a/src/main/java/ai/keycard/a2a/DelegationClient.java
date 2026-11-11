package ai.keycard.a2a;

import ai.keycard.oauth.Credential;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TransportRequest;
import ai.keycard.oauth.TransportResponse;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Calls another agent on the user's behalf (a2a-delegation.md): discovers the target's card,
 * exchanges the user's token for one scoped to the target (RFC 8693; the user stays the subject
 * and the zone records this agent in {@code act}), and sends the message over JSON-RPC.
 *
 * <pre>{@code
 * DelegationClient delegation = DelegationClient.builder(URI.create("https://acme.keycard.cloud"))
 *         .credential(ClientSecret.of(agentClientId, agentSecret))
 *         .build();
 * DelegationResult result = delegation.invoke(
 *         URI.create("https://agent-b.example"), userAccessToken, A2aProtocol.textMessage("hello"));
 * }</pre>
 *
 * <p>Speaks A2A 1.0 ({@code SendMessage}, {@code A2A-Version: 1.0}) unless built with the 0.3
 * opt-in, which switches the method, header, roles, part shape and preferred card interface
 * together. Safe to share between threads.
 *
 * <p>The exchanged token is scoped to the target, so it is only ever sent to the target's own
 * origin. A card that names a JSON-RPC endpoint on another origin is refused before any exchange,
 * unless that origin is listed with {@link Builder#trustedEndpointOrigins}.
 */
public final class DelegationClient {

    private final TokenExchangeClient exchange;
    private final ServiceDiscovery discovery;
    private final KeycardHttpTransport transport;
    private final Duration invokeTimeout;
    private final Wire wire;
    private final Set<String> trustedOrigins;

    private DelegationClient(Builder builder) {
        this.wire = Wire.of(builder.protocolVersion);
        this.exchange = TokenExchangeClient.builder(builder.issuer)
                .credential(Objects.requireNonNull(builder.credential, "credential"))
                .transport(builder.transport)
                .fetchTimeout(builder.fetchTimeout)
                .build();
        this.discovery = builder.discovery != null
                ? builder.discovery
                : ServiceDiscovery.builder()
                        .transport(builder.transport)
                        .fetchTimeout(builder.fetchTimeout)
                        .build();
        this.transport = builder.transport;
        this.invokeTimeout = builder.invokeTimeout;
        this.trustedOrigins = Set.copyOf(builder.trustedOrigins);
    }

    /**
     * A builder for an agent's delegation client in one zone.
     *
     * @param issuer the zone's issuer, where the exchange is performed
     * @return a new builder
     */
    public static Builder builder(URI issuer) {
        return new Builder(issuer);
    }

    /**
     * Discovers the target, exchanges the user's token for one scoped to it, and sends the message.
     *
     * @param target the target agent's base URL; also the exchange's {@code resource}
     * @param subjectToken the user's verified access token
     * @param params the {@code message/send} params in the 1.0 shape, such as {@link
     *     A2aProtocol#textMessage(String)}
     * @return the JSON-RPC result (a {@code message} or a {@code task}) and the card
     * @throws A2aDiscoveryException when the card can't be fetched or is invalid
     * @throws ai.keycard.oauth.OAuthErrorException when the zone refuses the exchange; the target
     *     isn't called
     * @throws A2aInvocationException when the call fails or the target answers with a JSON-RPC
     *     error
     * @throws KeycardException for other exchange failures
     */
    public DelegationResult invoke(URI target, String subjectToken, Map<String, Object> params) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(subjectToken, "subjectToken");
        Objects.requireNonNull(params, "params");
        AgentCard card = discovery.getCard(target);
        String base = ServiceDiscovery.key(target);
        // Resolve and vet the endpoint before exchanging, so a bad card never costs a token.
        URI url = endpoint(target, card, base);
        String token = exchange.exchangeToken(subjectToken, URI.create(base)).accessToken();
        return new DelegationResult(wire.decodeResult(call(url, token, params)), card);
    }

    /**
     * The generation this client speaks.
     *
     * @return {@link A2aProtocol#PROTOCOL_VERSION} or {@link A2aProtocol#LEGACY_PROTOCOL_VERSION}
     */
    public String protocolVersion() {
        return wire.version();
    }

    private URI endpoint(URI target, AgentCard card, String base) {
        String advertised = wire.endpointFrom(card);
        if (advertised == null) {
            return URI.create(base + A2aProtocol.JSONRPC_PATH);
        }
        URI url;
        try {
            url = new URI(advertised);
        } catch (URISyntaxException e) {
            throw new A2aDiscoveryException(
                    "the agent card for " + base + " names an endpoint that is not a URL", e, false);
        }
        String scheme = url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
        if (!url.isAbsolute() || url.getHost() == null || !(scheme.equals("https") || scheme.equals("http"))) {
            throw new A2aDiscoveryException(
                    "the agent card for " + base + " names an endpoint that is not an absolute http(s) URL",
                    null,
                    false);
        }
        String origin = origin(url);
        if (!origin.equals(origin(target)) && !trustedOrigins.contains(origin)) {
            throw new A2aDiscoveryException(
                    "the agent card for " + base + " names an endpoint on " + origin
                            + ", another origin; the token scoped to the target is only sent to the target's origin"
                            + " or one listed in trustedEndpointOrigins",
                    null,
                    false);
        }
        return url;
    }

    /** {@code scheme://host:port}, lowercased, with the default port written out. */
    static String origin(URI url) {
        String scheme = url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
        String host = url.getHost() == null ? "" : url.getHost().toLowerCase(Locale.ROOT);
        int port = url.getPort() != -1 ? url.getPort() : scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
        return scheme + "://" + host + ":" + port;
    }

    private Map<String, Object> call(URI url, String token, Map<String, Object> params) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("jsonrpc", "2.0");
        payload.put("id", UUID.randomUUID().toString());
        payload.put("method", wire.method());
        payload.put("params", wire.encodeParams(params));
        TransportRequest request = TransportRequest.post(
                        url, "application/json", JSONObjectUtils.toJSONString(payload), invokeTimeout)
                .withHeader("Accept", "application/json")
                .withHeader("Authorization", "Bearer " + token)
                .withHeader(wire.header(), wire.version());
        TransportResponse response;
        try {
            response = transport.send(request);
        } catch (KeycardException e) {
            throw new A2aInvocationException(
                    "invocation of " + url + " failed: " + e.getMessage(), e, e.retryable(), 0, null);
        }
        Map<String, Object> document = parse(response.body());
        Map<String, Object> rpcError =
                document != null && document.get("error") instanceof Map<?, ?> error ? stringKeys(error) : null;
        if (!response.isSuccess()) {
            // Agents often answer a JSON-RPC error with a 4xx or 5xx; keep the error object.
            throw new A2aInvocationException(
                    "invocation of " + url + " returned HTTP " + response.status()
                            + (rpcError == null ? "" : " with a JSON-RPC error: " + rpcError.get("message")),
                    null,
                    HttpStatusException.isRetryableStatus(response.status()),
                    response.status(),
                    rpcError);
        }
        if (document == null) {
            throw new A2aInvocationException(
                    "invocation of " + url + " returned a body that is not a JSON object",
                    null,
                    false,
                    response.status(),
                    null);
        }
        if (rpcError != null) {
            throw new A2aInvocationException(
                    "invocation of " + url + " returned a JSON-RPC error: " + rpcError.get("message"),
                    null,
                    false,
                    response.status(),
                    rpcError);
        }
        if (!(document.get("result") instanceof Map<?, ?> result)) {
            throw new A2aInvocationException(
                    "invocation of " + url + " returned no JSON-RPC result", null, false, response.status(), null);
        }
        return stringKeys(result);
    }

    /** The body as a JSON object, or null when it is not one (including a JSON {@code null}). */
    private static @Nullable Map<String, Object> parse(String body) {
        try {
            return JSONObjectUtils.parse(body);
        } catch (ParseException | RuntimeException e) {
            return null;
        }
    }

    private static Map<String, Object> stringKeys(Map<?, ?> map) {
        Map<String, Object> out = new LinkedHashMap<>();
        map.forEach((key, value) -> out.put(String.valueOf(key), value));
        return out;
    }

    /** Configures a {@link DelegationClient}. */
    public static final class Builder {

        private final URI issuer;
        private @Nullable Credential credential;
        private KeycardHttpTransport transport = KeycardHttpTransport.create();
        private Duration fetchTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private Duration invokeTimeout = KeycardHttpTransport.DEFAULT_TIMEOUT;
        private @Nullable ServiceDiscovery discovery;
        private String protocolVersion = A2aProtocol.PROTOCOL_VERSION;
        private final Set<String> trustedOrigins = new LinkedHashSet<>();

        private Builder(URI issuer) {
            this.issuer = Objects.requireNonNull(issuer, "issuer");
        }

        /**
         * This agent's application credential. It authenticates the exchange and identifies the
         * agent the zone records in {@code act}. Required.
         *
         * @param credential the credential
         * @return this builder
         */
        public Builder credential(Credential credential) {
            this.credential = Objects.requireNonNull(credential, "credential");
            return this;
        }

        /**
         * The transport for discovery, the exchange and the call.
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
         * The bound on each discovery and exchange request.
         *
         * @param fetchTimeout the timeout
         * @return this builder
         */
        public Builder fetchTimeout(Duration fetchTimeout) {
            this.fetchTimeout = Objects.requireNonNull(fetchTimeout, "fetchTimeout");
            return this;
        }

        /**
         * The bound on the call to the target agent, which may run longer than the zone requests.
         *
         * @param invokeTimeout the timeout; defaults to {@link KeycardHttpTransport#DEFAULT_TIMEOUT}
         * @return this builder
         */
        public Builder invokeTimeout(Duration invokeTimeout) {
            this.invokeTimeout = Objects.requireNonNull(invokeTimeout, "invokeTimeout");
            return this;
        }

        /**
         * Shares a discovery helper, and its card cache, with other clients.
         *
         * @param discovery the helper
         * @return this builder
         */
        public Builder discovery(ServiceDiscovery discovery) {
            this.discovery = Objects.requireNonNull(discovery, "discovery");
            return this;
        }

        /**
         * The A2A generation to speak.
         *
         * @param protocolVersion {@link A2aProtocol#PROTOCOL_VERSION} (the default) or {@link
         *     A2aProtocol#LEGACY_PROTOCOL_VERSION}
         * @return this builder
         */
        public Builder protocolVersion(String protocolVersion) {
            this.protocolVersion = Objects.requireNonNull(protocolVersion, "protocolVersion");
            return this;
        }

        /**
         * Builds the client.
         *
         * @return the client
         * @throws ai.keycard.oauth.ConfigurationException when the credential is missing or the
         *     protocol version is unknown
         */
        /**
         * Origins, other than each target's own, that a card may name as its JSON-RPC endpoint,
         * such as a gateway in front of several agents. The token exchanged for a target is sent
         * there, so list only origins you trust with every target's token.
         *
         * @param origins origins such as {@code https://gateway.example}; any path is ignored
         * @return this builder
         */
        public Builder trustedEndpointOrigins(URI... origins) {
            for (URI origin : origins) {
                Objects.requireNonNull(origin, "origin");
                if (!origin.isAbsolute() || origin.getHost() == null) {
                    throw new ai.keycard.oauth.ConfigurationException(
                            "a trusted endpoint origin must be an absolute URL, got " + origin);
                }
                trustedOrigins.add(origin(origin));
            }
            return this;
        }

        public DelegationClient build() {
            if (credential == null) {
                throw new ai.keycard.oauth.ConfigurationException("a delegation client needs the agent's credential");
            }
            return new DelegationClient(this);
        }
    }
}
