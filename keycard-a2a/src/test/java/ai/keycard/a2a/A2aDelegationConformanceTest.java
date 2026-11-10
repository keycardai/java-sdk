package ai.keycard.a2a;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** a2a-delegation.md (spec-version 2), Unit Tests table. */
class A2aDelegationConformanceTest {

    private static final String REPLY = "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"message\":{"
            + "\"role\":\"ROLE_AGENT\",\"parts\":[{\"text\":\"hi from B\"}],\"messageId\":\"m-2\"}}}";

    @Test
    @DisplayName("row 1: a healthy agent's card is returned and cached; a second lookup is served from cache")
    void row1() {
        try (StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            TestClock clock = TestClock.start();
            ServiceDiscovery discovery = ServiceDiscovery.builder().clock(clock).build();

            AgentCard first = discovery.getCard(agent.issuer());
            AgentCard second = discovery.getCard(URI.create(agent.issuer() + "/"));

            assertThat(first.name()).isEqualTo("Agent B");
            assertThat(second).isSameAs(first);
            assertThat(agent.requests(A2aProtocol.AGENT_CARD_PATH)).hasSize(1);

            clock.advance(Duration.ofMinutes(16));
            discovery.getCard(agent.issuer());
            assertThat(agent.requests(A2aProtocol.AGENT_CARD_PATH)).hasSize(2);

            discovery.refresh(agent.issuer());
            assertThat(agent.requests(A2aProtocol.AGENT_CARD_PATH)).hasSize(3);
        }
    }

    @Test
    @DisplayName("row 2: a card missing name is a discovery error")
    void row2() {
        try (StubZone agent = agent("{\"description\":\"no name\"}")) {
            assertThatThrownBy(() -> ServiceDiscovery.create().getCard(agent.issuer()))
                    .isInstanceOf(A2aDiscoveryException.class)
                    .hasMessageContaining("name");
        }
        try (StubZone agent = StubZone.start()) {
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 503, "{}");
            assertThatThrownBy(() -> ServiceDiscovery.create().getCard(agent.issuer()))
                    .isInstanceOfSatisfying(
                            A2aDiscoveryException.class,
                            e -> assertThat(e.retryable()).isTrue());
        }
    }

    @Test
    @DisplayName("row 3: the user token is exchanged for a target-scoped token and the agent is invoked with it")
    void row3() {
        try (StubZone zone = zone();
                StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY);

            DelegationResult result =
                    client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hello"));

            Map<String, List<String>> exchange =
                    zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            assertThat(exchange.get("grant_type")).containsExactly(TokenTypes.TOKEN_EXCHANGE_GRANT);
            assertThat(exchange.get("subject_token")).containsExactly("user-token");
            assertThat(exchange.get("subject_token_type")).containsExactly(TokenTypes.ACCESS_TOKEN);
            assertThat(exchange.get("resource")).containsExactly(agent.issuer().toString());
            assertThat(agent.requests(A2aProtocol.JSONRPC_PATH).get(0).header("Authorization"))
                    .isEqualTo("Bearer token-for-b");
            assertThat(result.text()).hasValue("hi from B");
            assertThat(result.agentCard().name()).isEqualTo("Agent B");
        }
    }

    @Test
    @DisplayName("row 4: a rejected exchange surfaces the OAuth error and the agent is not invoked")
    void row4() {
        try (StubZone zone = StubZone.start().serveDiscovery();
                StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"invalid_target\"}");

            assertThatThrownBy(() -> client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOfSatisfying(
                            OAuthErrorException.class,
                            e -> assertThat(e.error()).isEqualTo("invalid_target"));
            assertThat(agent.requests(A2aProtocol.JSONRPC_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 5: a JSON-RPC error from the target is an invocation error")
    void row5() {
        try (StubZone zone = zone();
                StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            agent.respond(
                    "POST",
                    A2aProtocol.JSONRPC_PATH,
                    200,
                    "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}");

            assertThatThrownBy(() -> client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOfSatisfying(A2aInvocationException.class, e -> {
                        assertThat(e.rpcError())
                                .hasValueSatisfying(error -> assertThat(error).containsEntry("code", -32601L));
                        assertThat(e.retryable()).isFalse();
                    });

            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 502, "bad gateway");
            assertThatThrownBy(() -> client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi")))
                    .isInstanceOfSatisfying(A2aInvocationException.class, e -> {
                        assertThat(e.status()).isEqualTo(502);
                        assertThat(e.retryable()).isTrue();
                    });
        }
    }

    @Test
    @DisplayName(
            "row 6: the default generation sends SendMessage under A2A-Version 1.0 with ROLE_USER and untagged parts")
    void row6() throws Exception {
        try (StubZone zone = zone();
                StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY);
            DelegationClient client = client(zone);

            client.invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hello"));

            RecordedRequest call = agent.requests(A2aProtocol.JSONRPC_PATH).get(0);
            Map<String, Object> body = JSONObjectUtils.parse(call.body());
            assertThat(client.protocolVersion()).isEqualTo("1.0");
            assertThat(body).containsEntry("method", "SendMessage").containsEntry("jsonrpc", "2.0");
            assertThat(call.header("A2A-Version")).isEqualTo("1.0");
            assertThat(call.header("X-A2A-Protocol-Version")).isNull();
            Map<String, Object> message = message(body);
            assertThat(message).containsEntry("role", "ROLE_USER");
            assertThat(message.get("parts")).isEqualTo(List.of(Map.of("text", "hello")));
            assertThat(call.body()).doesNotContain("message/send");
        }
    }

    @Test
    @DisplayName("row 7: the 0.3 opt-in switches the whole envelope; an unknown generation fails at construction")
    void row7() throws Exception {
        try (StubZone zone = zone();
                StubZone agent = agent("{\"name\":\"Agent B\"}")) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY);
            DelegationClient client = DelegationClient.builder(zone.issuer())
                    .credential(ClientSecret.of("agent-a", "secret"))
                    .protocolVersion(A2aProtocol.LEGACY_PROTOCOL_VERSION)
                    .build();

            client.invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hello"));

            RecordedRequest call = agent.requests(A2aProtocol.JSONRPC_PATH).get(0);
            Map<String, Object> body = JSONObjectUtils.parse(call.body());
            assertThat(body).containsEntry("method", "message/send");
            assertThat(call.header("X-A2A-Protocol-Version")).isEqualTo("0.3");
            assertThat(call.header("A2A-Version")).isNull();
            Map<String, Object> message = message(body);
            assertThat(message).containsEntry("role", "user");
            assertThat(message.get("parts")).isEqualTo(List.of(Map.of("kind", "text", "text", "hello")));
        }
        assertThatThrownBy(() -> DelegationClient.builder(URI.create("https://zone.example"))
                        .credential(ClientSecret.of("agent-a", "secret"))
                        .protocolVersion("2.0")
                        .build())
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 8: a card advertising JSONRPC interfaces is called at the one matching the client's version")
    void row8() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            String card = "{\"name\":\"Agent B\",\"supportedInterfaces\":["
                    + "{\"protocolBinding\":\"JSONRPC\",\"protocolVersion\":\"0.3\",\"url\":\"" + agent.url("/rpc/v03")
                    + "\"},"
                    + "{\"protocolBinding\":\"GRPC\",\"protocolVersion\":\"1.0\",\"url\":\"" + agent.url("/grpc")
                    + "\"},"
                    + "{\"protocolBinding\":\"JSONRPC\",\"protocolVersion\":\"1.0\",\"url\":\"" + agent.url("/rpc/v1")
                    + "\"}]}";
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, card);
            agent.respond("POST", "/rpc/v1", 200, REPLY);
            agent.respond("POST", "/rpc/v03", 200, REPLY);

            client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi"));
            DelegationClient.builder(zone.issuer())
                    .credential(ClientSecret.of("agent-a", "secret"))
                    .protocolVersion(A2aProtocol.LEGACY_PROTOCOL_VERSION)
                    .build()
                    .invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi"));

            assertThat(agent.requests("/rpc/v1")).hasSize(1);
            assertThat(agent.requests("/rpc/v03")).hasSize(1);
            assertThat(agent.requests(A2aProtocol.JSONRPC_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("a 0.3 card's top-level url is used when it lists no interfaces")
    void legacyCardUrl() {
        try (StubZone zone = zone();
                StubZone agent = StubZone.start()) {
            agent.respond(
                    "GET",
                    A2aProtocol.AGENT_CARD_PATH,
                    200,
                    "{\"name\":\"Agent B\",\"url\":\"" + agent.url("/legacy") + "\"}");
            agent.respond("POST", "/legacy", 200, REPLY);

            client(zone).invoke(agent.issuer(), "user-token", A2aProtocol.textMessage("hi"));

            assertThat(agent.requests("/legacy")).hasSize(1);
        }
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

    private static StubZone agent(String card) {
        StubZone agent = StubZone.start();
        agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, card);
        return agent;
    }

    private static DelegationClient client(StubZone zone) {
        return DelegationClient.builder(zone.issuer())
                .credential(ClientSecret.of("agent-a", "secret"))
                .build();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> message(Map<String, Object> body) {
        return (Map<String, Object>) ((Map<String, Object>) body.get("params")).get("message");
    }
}
