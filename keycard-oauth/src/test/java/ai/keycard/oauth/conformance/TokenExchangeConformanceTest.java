package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorCodes;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.TestClock;
import java.net.ConnectException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** token-exchange.md (spec-version 4), Unit Tests table, including the retryability rows. */
class TokenExchangeConformanceTest {

    private static final URI RESOURCE = URI.create("https://api.example.com");
    private static final String TOKEN_JSON = "{\"access_token\":\"xt\",\"token_type\":\"Bearer\",\"expires_in\":300,"
            + "\"scope\":\"read\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}";
    private static final String METADATA =
            "{\"issuer\":\"https://acme.keycard.cloud\",\"token_endpoint\":\"https://acme.keycard.cloud/token\"}";

    private final TestClock clock = TestClock.start();

    @Test
    @DisplayName("row 1: a request with only subject_token defaults grant_type and subject_token_type")
    void row1() {
        try (StubZone zone = zone()) {
            client(zone).exchangeToken(TokenExchangeRequest.builder("subject").build());

            assertThat(form(zone))
                    .containsEntry("grant_type", List.of(TokenTypes.TOKEN_EXCHANGE_GRANT))
                    .containsEntry("subject_token", List.of("subject"))
                    .containsEntry("subject_token_type", List.of(TokenTypes.ACCESS_TOKEN))
                    .doesNotContainKeys("resource", "scope", "actor_token", "actor_token_type", "audience");
        }
    }

    @Test
    @DisplayName("row 2: resource, scope and actor_token with actor_token_type are form-encoded")
    void row2() {
        try (StubZone zone = zone()) {
            client(zone)
                    .exchangeToken(TokenExchangeRequest.builder("subject")
                            .resource(RESOURCE)
                            .scope("read write")
                            .audience("aud-1")
                            .requestedTokenType(TokenTypes.ACCESS_TOKEN)
                            .actorToken("actor.jwt", TokenTypes.JWT)
                            .build());

            assertThat(form(zone))
                    .containsEntry("resource", List.of(RESOURCE.toString()))
                    .containsEntry("scope", List.of("read write"))
                    .containsEntry("audience", List.of("aud-1"))
                    .containsEntry("requested_token_type", List.of(TokenTypes.ACCESS_TOKEN))
                    .containsEntry("actor_token", List.of("actor.jwt"))
                    .containsEntry("actor_token_type", List.of(TokenTypes.JWT));
        }
    }

    @Test
    @DisplayName("row 2: actor_token without actor_token_type is rejected before any request")
    void row2ActorTypeRequired() {
        assertThatThrownBy(() -> new TokenExchangeRequest(
                        TokenTypes.TOKEN_EXCHANGE_GRANT,
                        "s",
                        TokenTypes.ACCESS_TOKEN,
                        null,
                        null,
                        null,
                        null,
                        "actor",
                        null,
                        null,
                        null,
                        null))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 3: a shared-secret credential sends an HTTP Basic Authorization header")
    void row3() {
        try (StubZone zone = zone()) {
            client(zone).exchangeToken("subject", RESOURCE);

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.header("Authorization"))
                    .isEqualTo("Basic " + ClientSecretConformanceTest.basic("gw", "gw-secret"));
            assertThat(request.formParams()).doesNotContainKeys("client_id", "client_secret", "client_assertion");
        }
    }

    @Test
    @DisplayName("row 4: a request carrying client_assertion, with no secret configured, has no Basic header")
    void row4() {
        try (StubZone zone = zone()) {
            TokenExchangeClient.builder(zone.issuer())
                    .build()
                    .exchangeToken(TokenExchangeRequest.builder("subject")
                            .clientAssertion("assertion.jwt", TokenTypes.JWT_BEARER_ASSERTION)
                            .build());

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("client_assertion", List.of("assertion.jwt"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION));
            assertThat(request.header("Authorization")).isNull();
        }
    }

    @Test
    @DisplayName("row 4: an assertion-based credential's prepared request authenticates in the body")
    void row4PreparedByCredential() {
        try (StubZone zone = zone()) {
            TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.builder(() -> "svid.jwt")
                            .clientId("engine")
                            .build())
                    .build()
                    .exchangeToken("subject", RESOURCE);

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("client_assertion", List.of("svid.jwt"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION))
                    .containsEntry("client_id", List.of("engine"))
                    .containsEntry("resource", List.of(RESOURCE.toString()));
            assertThat(request.header("Authorization")).isNull();
        }
    }

    @Test
    @DisplayName("row 5: a 2xx response parses access_token, token_type, expires_in, scope, issued_token_type")
    void row5() {
        try (StubZone zone = zone()) {
            TokenResponse token = client(zone).exchangeToken("subject", RESOURCE);

            assertThat(token.accessToken()).isEqualTo("xt");
            assertThat(token.tokenType()).isEqualTo("Bearer");
            assertThat(token.expiresIn()).isEqualTo(Duration.ofMinutes(5));
            assertThat(token.scope()).containsExactly("read");
            assertThat(token.issuedTokenType()).isEqualTo(TokenTypes.ACCESS_TOKEN);
        }
    }

    @Test
    @DisplayName("row 6: an OAuth error response is a typed error carrying error and error_description")
    void row6() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            for (String code : List.of("invalid_grant", "invalid_target", "invalid_scope", "unauthorized_client")) {
                zone.respond(
                        "POST",
                        StubZone.TOKEN_PATH,
                        400,
                        "{\"error\":\"" + code + "\",\"error_description\":\"nope\"}");

                assertThatThrownBy(() -> client(zone).exchangeToken("subject", RESOURCE))
                        .as(code)
                        .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                            assertThat(e.error()).isEqualTo(code);
                            assertThat(e.errorDescription()).isEqualTo("nope");
                        });
            }
        }
    }

    @Test
    @DisplayName("row 7: a response missing access_token is an error")
    void row7() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"token_type\":\"Bearer\"}");

            assertThatThrownBy(() -> client(zone).exchangeToken("subject", RESOURCE))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE));
        }
    }

    @Test
    @DisplayName("row 8: a discovery network error caches nothing; the next call discovers again")
    void row8() {
        AtomicInteger discoveries = new AtomicInteger();
        KeycardHttpTransport transport = request -> {
            if (request.uri().getPath().startsWith("/.well-known")) {
                if (discoveries.incrementAndGet() == 1) {
                    throw new NetworkException("refused", new ConnectException("refused"));
                }
                return json(METADATA);
            }
            return json(TOKEN_JSON);
        };
        TokenExchangeClient client = transportClient(transport);

        assertThatThrownBy(() -> client.exchangeToken("subject", RESOURCE)).isInstanceOf(NetworkException.class);
        assertThat(client.exchangeToken("subject", RESOURCE).accessToken()).isEqualTo("xt");
        assertThat(discoveries).hasValue(2);
    }

    @Test
    @DisplayName("row 9: discovery 404 is a typed error; a call after negative_ttl discovers again")
    void row9() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 404, "{}");
            TokenExchangeClient client = client(zone);

            assertThatThrownBy(() -> client.exchangeToken("subject", RESOURCE)).isInstanceOf(HttpStatusException.class);
            assertThatThrownBy(() -> client.exchangeToken("subject", RESOURCE)).isInstanceOf(HttpStatusException.class);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

            clock.advance(Duration.ofMinutes(1));
            zone.serveDiscovery();
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
            assertThat(client.exchangeToken("subject", RESOURCE).accessToken()).isEqualTo("xt");
        }
    }

    @Test
    @DisplayName("row 10: a call cancelled during discovery doesn't stop the next one")
    void row10() throws Exception {
        AtomicInteger discoveries = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        KeycardHttpTransport transport = request -> {
            if (request.uri().getPath().startsWith("/.well-known")) {
                if (discoveries.incrementAndGet() == 1) {
                    entered.countDown();
                    try {
                        new CountDownLatch(1).await();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new NetworkException("interrupted", e);
                    }
                }
                return json(METADATA);
            }
            return json(TOKEN_JSON);
        };
        TokenExchangeClient client = transportClient(transport);

        AtomicReference<Throwable> cancelled = new AtomicReference<>();
        Thread first = new Thread(() -> {
            try {
                client.exchangeToken("subject", RESOURCE);
            } catch (RuntimeException e) {
                cancelled.set(e);
            }
        });
        first.start();
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        first.interrupt();
        first.join(5000);

        assertThat(cancelled.get()).isInstanceOf(NetworkException.class);
        assertThat(client.exchangeToken("subject", RESOURCE).accessToken()).isEqualTo("xt");
    }

    @Test
    @DisplayName("row 11: concurrent cold-cache calls make a single discovery request")
    void row11() throws Exception {
        AtomicInteger discoveries = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        KeycardHttpTransport transport = request -> {
            if (request.uri().getPath().startsWith("/.well-known")) {
                discoveries.incrementAndGet();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new NetworkException("interrupted", e);
                }
                return json(METADATA);
            }
            return json(TOKEN_JSON);
        };
        TokenExchangeClient client = transportClient(transport);

        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Future<TokenResponse>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(pool.submit(() -> client.exchangeToken("subject", RESOURCE)));
            }
            Thread.sleep(200);
            release.countDown();
            for (Future<TokenResponse> call : calls) {
                assertThat(call.get(5, TimeUnit.SECONDS).accessToken()).isEqualTo("xt");
            }
            assertThat(discoveries).hasValue(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("row 12: a call after discovery_ttl discovers again")
    void row12() {
        try (StubZone zone = zone()) {
            TokenExchangeClient client = client(zone);

            client.exchangeToken("subject", RESOURCE);
            clock.advance(Duration.ofMinutes(59));
            client.exchangeToken("subject", RESOURCE);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);
            clock.advance(Duration.ofMinutes(1));
            client.exchangeToken("subject", RESOURCE);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 13: metadata without token_endpoint is a typed error, remembered for at most negative_ttl")
    void row13() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, "{\"issuer\":\"" + zone.issuer() + "\"}");
            TokenExchangeClient client = client(zone);

            assertThatThrownBy(() -> client.exchangeToken("subject", RESOURCE))
                    .isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                        assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_METADATA);
                        assertThat(e.retryable()).isFalse();
                    });
            clock.advance(Duration.ofMinutes(1));
            zone.serveDiscovery();
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
            assertThat(client.exchangeToken("subject", RESOURCE).accessToken()).isEqualTo("xt");
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("rows 14 to 18: exchange-path errors carry retryable from their code or status")
    void rows14To18() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            for (String code : OAuthErrorCodes.PERMANENT) {
                zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"" + code + "\"}");
                assertThat(caught(zone).retryable()).as(code).isFalse();
            }
            for (String code :
                    List.of("invalid_response", "server_error", "temporarily_unavailable", "invalid_grant")) {
                zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"" + code + "\"}");
                assertThat(caught(zone).retryable()).as(code).isTrue();
            }
            for (int status : List.of(429, 500, 502, 503)) {
                zone.respond("POST", StubZone.TOKEN_PATH, status, "");
                assertThat(caught(zone).retryable()).as("%d", status).isTrue();
            }
            zone.respond("POST", StubZone.TOKEN_PATH, 400, "");
            assertThat(caught(zone).retryable()).isFalse();
        }
    }

    @Test
    @DisplayName("rows 19 and 20: a connection failure through the real transport is a retryable network error")
    void rows19And20() throws Exception {
        URI closed = AuthorizationServerDiscoveryConformanceTest.closedPort();
        TokenExchangeClient client = TokenExchangeClient.builder(closed)
                .credential(ClientSecret.of("gw", "gw-secret"))
                .build();

        assertThatThrownBy(() -> client.exchangeToken("subject", RESOURCE))
                .isInstanceOfSatisfying(
                        NetworkException.class, e -> assertThat(e.retryable()).isTrue());
    }

    @Test
    @DisplayName("row 21: configuration errors are not retryable, and nothing is sent")
    void row21() {
        try (StubZone zone = zone()) {
            TokenExchangeClient noCredential =
                    TokenExchangeClient.builder(zone.issuer()).build();

            assertThatThrownBy(() -> noCredential.exchangeToken(
                            TokenExchangeRequest.builder("subject").build()))
                    .isInstanceOfSatisfying(
                            ConfigurationException.class,
                            e -> assertThat(e.retryable()).isFalse());
            assertThatThrownBy(() -> noCredential.exchangeToken("subject", RESOURCE))
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    private KeycardException caught(StubZone zone) {
        try {
            client(zone).exchangeToken("subject", RESOURCE);
        } catch (KeycardException e) {
            return e;
        }
        throw new AssertionError("expected an exception");
    }

    private StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
        return zone;
    }

    private TokenExchangeClient client(StubZone zone) {
        return TokenExchangeClient.builder(zone.issuer())
                .credential(ClientSecret.of("gw", "gw-secret"))
                .clock(clock)
                .build();
    }

    private TokenExchangeClient transportClient(KeycardHttpTransport transport) {
        return TokenExchangeClient.builder(URI.create("https://acme.keycard.cloud"))
                .credential(ClientSecret.of("gw", "gw-secret"))
                .transport(transport)
                .clock(clock)
                .build();
    }

    private static Map<String, List<String>> form(StubZone zone) {
        return zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
    }

    private static TransportResponse json(String body) {
        return new TransportResponse(200, Map.of("content-type", List.of("application/json")), body);
    }
}
