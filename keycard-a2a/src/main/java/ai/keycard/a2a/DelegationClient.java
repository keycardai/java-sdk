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
import java.net.http.HttpClient;
import java.text.ParseException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
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
 */
public final class DelegationClient {

    private final TokenExchangeClient exchange;
    private final ServiceDiscovery discovery;
    private final KeycardHttpTransport transport;
    private final Duration invokeTimeout;
    private final Wire wire;

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
        String token = exchange.exchangeToken(subjectToken, URI.create(base)).accessToken();
        String endpoint = wire.endpointFrom(card);
        URI url = URI.create(endpoint != null ? endpoint : base + A2aProtocol.JSONRPC_PATH);
        return new DelegationResult(call(url, token, params), card);
    }

    /**
     * The generation this client speaks.
     *
     * @return {@link A2aProtocol#PROTOCOL_VERSION} or {@link A2aProtocol#LEGACY_PROTOCOL_VERSION}
     */
    public String protocolVersion() {
        return wire.version();
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
        if (!response.isSuccess()) {
            throw new A2aInvocationException(
                    "invocation of " + url + " returned HTTP " + response.status(),
                    null,
                    HttpStatusException.isRetryableStatus(response.status()),
                    response.status(),
                    null);
        }
        Map<String, Object> document;
        try {
            document = JSONObjectUtils.parse(response.body());
        } catch (ParseException e) {
            throw new A2aInvocationException(
                    "invocation of " + url + " returned a body that is not JSON", e, false, response.status(), null);
        }
        if (document.get("error") instanceof Map<?, ?> error) {
            Map<String, Object> rpcError = new LinkedHashMap<>();
            error.forEach((key, value) -> rpcError.put(String.valueOf(key), value));
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
        Map<String, Object> out = new LinkedHashMap<>();
        result.forEach((key, value) -> out.put(String.valueOf(key), value));
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
        public DelegationClient build() {
            if (credential == null) {
                throw new ai.keycard.oauth.ConfigurationException("a delegation client needs the agent's credential");
            }
            return new DelegationClient(this);
        }
    }
}
