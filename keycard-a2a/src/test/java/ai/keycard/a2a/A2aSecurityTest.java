package ai.keycard.a2a;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.testing.StubZone;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Regression tests for the pre-release adversarial review of keycard-a2a. */
class A2aSecurityTest {

    private static final String REPLY = "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"message\":{"
            + "\"role\":\"ROLE_AGENT\",\"parts\":[{\"text\":\"hi from B\"}],\"messageId\":\"m-2\"}}}";

    @Test
    @DisplayName("a card naming an endpoint on another origin is refused before the exchange")
    void crossOriginEndpointRefused() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start();
                StubZone elsewhere = StubZone.start()) {
            agent.respond(
                    "GET",
                    A2aProtocol.AGENT_CARD_PATH,
                    200,
                    card(elsewhere.url("/rpc").toString()));
            elsewhere.respond("POST", "/rpc", 200, REPLY);

            assertThatThrownBy(() ->
                            client(zone).build().invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOf(A2aDiscoveryException.class)
                    .hasMessageContaining("another origin");
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
            assertThat(elsewhere.requests("/rpc")).isEmpty();
        }
    }

    @Test
    @DisplayName("an origin listed in trustedEndpointOrigins may serve the endpoint")
    void trustedOriginAllowed() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start();
                StubZone gateway = StubZone.start()) {
            agent.respond(
                    "GET",
                    A2aProtocol.AGENT_CARD_PATH,
                    200,
                    card(gateway.url("/rpc").toString()));
            gateway.respond("POST", "/rpc", 200, REPLY);

            DelegationResult result = client(zone)
                    .trustedEndpointOrigins(gateway.url("/anything"))
                    .build()
                    .invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi"));
            assertThat(result.text()).hasValue("hi from B");
            assertThat(gateway.requests("/rpc").get(0).header("Authorization")).isEqualTo("Bearer token-for-b");
        }
    }

    @Test
    @DisplayName("a card endpoint that isn't an absolute http(s) URL is a discovery error before the exchange")
    void malformedEndpoint() {
        for (String endpoint : new String[] {"not a url", "/relative/rpc", "ftp://agent.example/rpc"}) {
            try (StubZone zone = zone();
                    StubZone agent = StubZone.start()) {
                agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, card(endpoint));
                assertThatThrownBy(() -> client(zone)
                                .build()
                                .invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                        .as(endpoint)
                        .isInstanceOf(A2aDiscoveryException.class);
                assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
            }
        }
    }

    @Test
    @DisplayName("a JSON null card or reply is a typed error, never a NullPointerException")
    void jsonNull() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, "null");
            assertThatThrownBy(() ->
                            client(zone).build().invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOf(A2aDiscoveryException.class);
        }
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, "{\"name\":\"Agent B\"}");
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, "null");
            assertThatThrownBy(() ->
                            client(zone).build().invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOf(A2aInvocationException.class);
        }
    }

    @Test
    @DisplayName("a JSON-RPC error carried by a non-2xx response keeps its error object")
    void rpcErrorOnNon2xx() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, "{\"name\":\"Agent B\"}");
            agent.respond(
                    "POST",
                    A2aProtocol.JSONRPC_PATH,
                    400,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}");
            assertThatThrownBy(() ->
                            client(zone).build().invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOfSatisfying(A2aInvocationException.class, e -> {
                        assertThat(e.status()).isEqualTo(400);
                        assertThat(e.rpcError())
                                .hasValueSatisfying(error -> assertThat(error).containsEntry("code", -32602L));
                    });
        }
    }

    @Test
    @DisplayName("a 0.3 reply, the message itself tagged with kind, reads through message() and text()")
    void legacyResultDecoded() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, "{\"name\":\"Agent B\"}");
            agent.respond(
                    "POST",
                    A2aProtocol.JSONRPC_PATH,
                    200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"kind\":\"message\",\"role\":\"agent\","
                            + "\"parts\":[{\"kind\":\"text\",\"text\":\"hi from 0.3\"}],\"messageId\":\"m-3\"}}");
            DelegationResult result = client(zone)
                    .protocolVersion(A2aProtocol.LEGACY_PROTOCOL_VERSION)
                    .build()
                    .invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi"));
            assertThat(result.text()).hasValue("hi from 0.3");
            assertThat(result.task()).isEmpty();
        }
    }

    private static String card(String endpoint) {
        return "{\"name\":\"Agent B\",\"supportedInterfaces\":[{\"protocolBinding\":\"JSONRPC\","
                + "\"protocolVersion\":\"1.0\",\"url\":\"" + endpoint + "\"}]}";
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond(
                "POST",
                StubZone.TOKEN_PATH,
                200,
                "{\"access_token\":\"token-for-b\",\"token_type\":\"Bearer\",\"expires_in\":300}");
        return zone;
    }

    private static DelegationClient.Builder client(StubZone zone) {
        return DelegationClient.builder(zone.issuer()).credential(ClientSecret.of("agent-a", "secret"));
    }
}
