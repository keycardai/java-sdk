package ai.keycard.a2a;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.ResponseBodyTooLargeException;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** a2a-delegation.md (spec-version 3), Unit Tests table. */
class A2aDelegationConformanceTest {

    private static final int MIB = 1024 * 1024;
    private static final String CARD = "{\"name\":\"Agent B\"}";
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

    @Test
    @DisplayName("row 9: default discovery and invocation accept decoded peer replies larger than 1 MiB")
    void row9() {
        String padding = " ".repeat(MIB);
        try (StubZone zone = zone();
                StubZone agent = agent(CARD + padding)) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY + padding);
            assertThat(ServiceDiscovery.create().getCard(agent.issuer()).name()).isEqualTo("Agent B");
            assertThat(invoke(client(zone), agent.issuer()).text()).hasValue("hi from B");
        }
    }

    @Test
    @DisplayName("row 10: a gzip reply stops at the decoded peer limit")
    void row10() throws IOException {
        byte[] card = gzip(CARD, 2048);
        byte[] reply = gzip(REPLY, 2048);
        assertThat(card.length).isLessThan(512);
        assertThat(reply.length).isLessThan(512);
        HttpServer peer = gzipPeer(card, reply);
        URI target = URI.create("http://127.0.0.1:" + peer.getAddress().getPort());
        try {
            assertOverflow(
                    () -> ServiceDiscovery.builder()
                            .maxPeerResponseBytes(512)
                            .build()
                            .getCard(target),
                    200,
                    512,
                    true);
        } finally {
            peer.stop(0);
        }
        HttpServer rpcPeer = gzipPeer(gzip(CARD, 0), reply);
        URI rpcTarget = URI.create("http://127.0.0.1:" + rpcPeer.getAddress().getPort());
        try (StubZone zone = zone()) {
            assertOverflow(
                    () -> invoke(clientBuilder(zone).maxPeerResponseBytes(512).build(), rpcTarget), 200, 512, false);
        } finally {
            rpcPeer.stop(0);
        }
    }

    @Test
    @DisplayName("row 10a: overflow preserves HTTP status and successful invocations are not retryable")
    void row10a() {
        String padding = " ".repeat(1024);
        try (StubZone zone = zone();
                StubZone agent = agent(CARD)) {
            for (int status : new int[] {200, 429, 503}) {
                agent.respond("POST", A2aProtocol.JSONRPC_PATH, status, REPLY + padding);
                assertOverflow(
                        () -> invoke(
                                clientBuilder(zone).maxPeerResponseBytes(512).build(), agent.issuer()),
                        status,
                        512,
                        status != 200);
            }
            for (int status : new int[] {200, 429, 503}) {
                agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, status, CARD + padding);
                assertOverflow(
                        () -> ServiceDiscovery.builder()
                                .maxPeerResponseBytes(512)
                                .build()
                                .getCard(agent.issuer()),
                        status,
                        512,
                        true);
            }
        }
    }

    @Test
    @DisplayName("row 11: a custom peer limit can lower or raise the default")
    void row11() throws IOException {
        String padding = " ".repeat(512);
        try (StubZone zone = zone();
                StubZone agent = agent(CARD + padding)) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY + padding);
            assertThat(ServiceDiscovery.create().getCard(agent.issuer()).name()).isEqualTo("Agent B");
            assertThat(invoke(client(zone), agent.issuer()).text()).hasValue("hi from B");
            assertOverflow(
                    () -> ServiceDiscovery.builder()
                            .maxPeerResponseBytes(256)
                            .build()
                            .getCard(agent.issuer()),
                    200,
                    256,
                    true);
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, CARD);
            assertOverflow(
                    () -> invoke(clientBuilder(zone).maxPeerResponseBytes(256).build(), agent.issuer()),
                    200,
                    256,
                    false);
            int defaultLimit = 64 * MIB;
            int raised = 65 * MIB;
            byte[] reply = gzip(REPLY, defaultLimit);
            HttpServer peer = gzipPeer(gzip(CARD, defaultLimit), reply);
            URI target = URI.create("http://127.0.0.1:" + peer.getAddress().getPort());
            try {
                assertOverflow(() -> ServiceDiscovery.create().getCard(target), 200, defaultLimit, true);
                assertThat(ServiceDiscovery.builder()
                                .maxPeerResponseBytes(raised)
                                .build()
                                .getCard(target)
                                .name())
                        .isEqualTo("Agent B");
            } finally {
                peer.stop(0);
            }
            HttpServer rpcPeer = gzipPeer(gzip(CARD, 0), reply);
            URI rpcTarget =
                    URI.create("http://127.0.0.1:" + rpcPeer.getAddress().getPort());
            try {
                assertOverflow(() -> invoke(client(zone), rpcTarget), 200, defaultLimit, false);
                assertThat(invoke(
                                        clientBuilder(zone)
                                                .maxPeerResponseBytes(raised)
                                                .build(),
                                        rpcTarget)
                                .text())
                        .hasValue("hi from B");
            } finally {
                rpcPeer.stop(0);
            }
        }
    }

    @Test
    @DisplayName("a JDK transport built with httpClient keeps the peer limit")
    void httpClientKeepsPeerLimit() {
        String padding = " ".repeat(1024);
        try (StubZone zone = zone();
                StubZone agent = agent(CARD + padding)) {
            agent.respond("POST", A2aProtocol.JSONRPC_PATH, 200, REPLY + padding);
            assertOverflow(
                    () -> ServiceDiscovery.builder()
                            .httpClient(HttpClient.newHttpClient())
                            .maxPeerResponseBytes(512)
                            .build()
                            .getCard(agent.issuer()),
                    200,
                    512,
                    true);
            agent.respond("GET", A2aProtocol.AGENT_CARD_PATH, 200, CARD);
            assertOverflow(
                    () -> invoke(
                            clientBuilder(zone)
                                    .httpClient(HttpClient.newHttpClient())
                                    .maxPeerResponseBytes(512)
                                    .build(),
                            agent.issuer()),
                    200,
                    512,
                    false);
        }
    }

    @Test
    @DisplayName("row 11: changing the peer limit does not change the token exchange cap")
    void row11TokenExchange() {
        try (StubZone zone = zone();
                StubZone agent = agent(CARD)) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"token-for-b\"}" + " ".repeat(MIB));
            for (int limit : new int[] {512, 65 * MIB}) {
                DelegationClient client =
                        clientBuilder(zone).maxPeerResponseBytes(limit).build();
                assertOverflow(
                        () -> invoke(client, agent.issuer()), 200, KeycardHttpTransport.MAX_RESPONSE_BODY_BYTES, true);
            }
            assertThat(agent.requests(A2aProtocol.JSONRPC_PATH)).isEmpty();
        }
    }

    private static void assertOverflow(ThrowingCallable action, int status, int limit, boolean retryable) {
        assertThatThrownBy(action).isInstanceOfSatisfying(ResponseBodyTooLargeException.class, e -> {
            assertThat(e.code()).isEqualTo("invalid_response");
            assertThat(e.status()).isEqualTo(status);
            assertThat(e.limit()).isEqualTo(limit);
            assertThat(e.retryable()).isEqualTo(retryable);
        });
    }

    private static HttpServer gzipPeer(byte[] card, byte[] reply) throws IOException {
        HttpServer peer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        peer.createContext("/", exchange -> {
            try (exchange) {
                exchange.getRequestBody().readAllBytes();
                byte[] body = exchange.getRequestURI().getPath().equals(A2aProtocol.AGENT_CARD_PATH) ? card : reply;
                exchange.getResponseHeaders().set("Content-Encoding", "gzip");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
            }
        });
        peer.start();
        return peer;
    }

    private static byte[] gzip(String json, int padding) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            gzip.write(json.getBytes(StandardCharsets.UTF_8));
            byte[] spaces = " ".repeat(8192).getBytes(StandardCharsets.UTF_8);
            for (int remaining = padding; remaining > 0; remaining -= spaces.length) {
                gzip.write(spaces, 0, Math.min(remaining, spaces.length));
            }
        }
        return bytes.toByteArray();
    }

    private static DelegationResult invoke(DelegationClient client, URI target) {
        return client.invoke(target, "user-token", A2aProtocol.textMessage("hi"));
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
        return clientBuilder(zone).build();
    }

    private static DelegationClient.Builder clientBuilder(StubZone zone) {
        return DelegationClient.builder(zone.issuer()).credential(ClientSecret.of("agent-a", "secret"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> message(Map<String, Object> body) {
        return (Map<String, Object>) ((Map<String, Object>) body.get("params")).get("message");
    }
}
