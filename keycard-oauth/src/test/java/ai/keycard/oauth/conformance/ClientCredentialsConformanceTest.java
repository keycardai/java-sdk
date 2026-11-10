package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientCredentialsClient;
import ai.keycard.oauth.ClientCredentialsRequest;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
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

/** client-credentials.md (spec-version 4), Unit Tests table. */
class ClientCredentialsConformanceTest {

    private static final String TOKEN_JSON =
            "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read write\"}";

    private final TestClock clock = TestClock.start();

    @Test
    @DisplayName("row 1: a request with a scope sends grant_type=client_credentials and scope")
    void row1() {
        try (StubZone zone = zone()) {
            client(zone)
                    .requestToken(ClientCredentialsRequest.builder()
                            .scope("read write")
                            .build());

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.header("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
            assertThat(request.formParams())
                    .containsEntry("grant_type", List.of("client_credentials"))
                    .containsEntry("scope", List.of("read write"))
                    .doesNotContainKeys("resource", "client_assertion", "client_assertion_type");
        }
    }

    @Test
    @DisplayName("row 2: a resource is form-encoded in the body")
    void row2() {
        try (StubZone zone = zone()) {
            client(zone)
                    .requestToken(ClientCredentialsRequest.builder()
                            .resource(URI.create("https://api.example.com/v1?x=1"))
                            .build());

            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams())
                    .containsEntry("resource", List.of("https://api.example.com/v1?x=1"));
        }
    }

    @Test
    @DisplayName("row 3: a shared-secret client sends an HTTP Basic Authorization header")
    void row3() {
        try (StubZone zone = zone()) {
            client(zone).requestToken();

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.header("Authorization"))
                    .isEqualTo("Basic " + ClientSecretConformanceTest.basic("cc-client", "cc-secret"));
            assertThat(request.formParams()).doesNotContainKeys("client_id", "client_secret");
        }
    }

    @Test
    @DisplayName("row 4: client_assertion and client_assertion_type are form-encoded in the body")
    void row4() {
        try (StubZone zone = zone()) {
            ClientCredentialsClient.builder(zone.issuer())
                    .build()
                    .requestToken(ClientCredentialsRequest.builder()
                            .clientAssertion("eyJ.assertion.sig", TokenTypes.JWT_BEARER_ASSERTION)
                            .build());

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("client_assertion", List.of("eyJ.assertion.sig"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION));
            assertThat(request.header("Authorization")).isNull();
        }
    }

    @Test
    @DisplayName("row 5: a 2xx response parses into access_token, token_type, expires_in and scope")
    void row5() {
        try (StubZone zone = zone()) {
            TokenResponse token = client(zone).requestToken();

            assertThat(token.accessToken()).isEqualTo("at");
            assertThat(token.tokenType()).isEqualTo("Bearer");
            assertThat(token.expiresIn()).isEqualTo(Duration.ofHours(1));
            assertThat(token.scope()).containsExactly("read", "write");
            assertThat(token.toString()).doesNotContain("\"at\"").doesNotContain("=at,");
        }
    }

    @Test
    @DisplayName("row 6: an OAuth error response is a typed error carrying error and error_description")
    void row6() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "POST",
                    StubZone.TOKEN_PATH,
                    401,
                    "{\"error\":\"invalid_client\",\"error_description\":\"bad secret\",\"error_uri\":\"https://docs\"}");

            assertThatThrownBy(() -> client(zone).requestToken())
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("invalid_client");
                        assertThat(e.errorDescription()).isEqualTo("bad secret");
                        assertThat(e.errorUri()).isEqualTo("https://docs");
                        assertThat(e.status()).isEqualTo(401);
                        assertThat(e.retryable()).isFalse();
                    });

            zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"invalid_scope\"}");
            assertThatThrownBy(() -> client(zone).requestToken())
                    .isInstanceOfSatisfying(
                            OAuthErrorException.class,
                            e -> assertThat(e.error()).isEqualTo("invalid_scope"));
        }
    }

    @Test
    @DisplayName("row 6: a non-OAuth error body is an HTTP error")
    void row6NonOAuthBody() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, new StubResponse(502, Map.of(), "<html>bad gateway</html>"));

            assertThatThrownBy(() -> client(zone).requestToken())
                    .isInstanceOfSatisfying(HttpStatusException.class, e -> {
                        assertThat(e).isNotInstanceOf(OAuthErrorException.class);
                        assertThat(e.status()).isEqualTo(502);
                        assertThat(e.retryable()).isTrue();
                    });
        }
    }

    @Test
    @DisplayName("row 6: a 2xx response without an access token is a retryable invalid_response")
    void row6MissingAccessToken() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            for (String body : List.of("{\"token_type\":\"Bearer\"}", "not json", "{\"access_token\":\"\"}")) {
                zone.respond("POST", StubZone.TOKEN_PATH, 200, body);

                assertThatThrownBy(() -> client(zone).requestToken())
                        .as(body)
                        .isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                            assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                            assertThat(e.retryable()).isTrue();
                        });
            }
        }
    }

    @Test
    @DisplayName("row 5: token_type defaults to Bearer when the server omits it")
    void tokenTypeDefault() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"at\"}");

            TokenResponse token = client(zone).requestToken();

            assertThat(token.tokenType()).isEqualTo("Bearer");
            assertThat(token.expiresIn()).isNull();
            assertThat(token.scope()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 7: a discovery network error caches nothing; the next call discovers again and succeeds")
    void row7() {
        AtomicInteger discoveries = new AtomicInteger();
        KeycardHttpTransport transport = request -> {
            if (request.uri().getPath().startsWith("/.well-known")) {
                if (discoveries.incrementAndGet() == 1) {
                    throw new NetworkException("refused", new ConnectException("refused"));
                }
                return json(
                        "{\"issuer\":\"https://acme.keycard.cloud\",\"token_endpoint\":\"https://acme.keycard.cloud/token\"}");
            }
            return json(TOKEN_JSON);
        };
        ClientCredentialsClient client = ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
                .credential(ClientSecret.of("cc-client", "cc-secret"))
                .transport(transport)
                .clock(clock)
                .build();

        assertThatThrownBy(client::requestToken).isInstanceOf(NetworkException.class);
        assertThat(client.requestToken().accessToken()).isEqualTo("at");
        assertThat(discoveries).hasValue(2);
    }

    @Test
    @DisplayName("row 8: discovery 404 is a typed error; a call after negative_ttl discovers again")
    void row8() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 404, "{}");
            ClientCredentialsClient client = client(zone);

            assertThatThrownBy(client::requestToken).isInstanceOfSatisfying(HttpStatusException.class, e -> {
                assertThat(e.status()).isEqualTo(404);
                assertThat(e.retryable()).isFalse();
            });
            assertThatThrownBy(client::requestToken).isInstanceOf(HttpStatusException.class);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

            clock.advance(Duration.ofMinutes(1));
            zone.serveDiscovery();
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
            assertThat(client.requestToken().accessToken()).isEqualTo("at");
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 9: a call cancelled during discovery doesn't stop the next call from discovering and succeeding")
    void row9() throws Exception {
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
                return json(
                        "{\"issuer\":\"https://acme.keycard.cloud\",\"token_endpoint\":\"https://acme.keycard.cloud/token\"}");
            }
            return json(TOKEN_JSON);
        };
        ClientCredentialsClient client = ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
                .credential(ClientSecret.of("cc-client", "cc-secret"))
                .transport(transport)
                .build();

        AtomicReference<Throwable> cancelled = new AtomicReference<>();
        Thread first = new Thread(() -> {
            try {
                client.requestToken();
            } catch (RuntimeException e) {
                cancelled.set(e);
            }
        });
        first.start();
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        first.interrupt();
        first.join(5000);

        assertThat(cancelled.get()).isInstanceOf(NetworkException.class);
        assertThat(client.requestToken().accessToken()).isEqualTo("at");
        assertThat(discoveries).hasValue(2);
    }

    @Test
    @DisplayName("row 10: concurrent cold-cache calls make a single discovery request")
    void row10() throws Exception {
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
                return json(
                        "{\"issuer\":\"https://acme.keycard.cloud\",\"token_endpoint\":\"https://acme.keycard.cloud/token\"}");
            }
            return json(TOKEN_JSON);
        };
        ClientCredentialsClient client = ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
                .credential(ClientSecret.of("cc-client", "cc-secret"))
                .transport(transport)
                .build();

        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Future<TokenResponse>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(pool.submit(() -> client.requestToken()));
            }
            Thread.sleep(200);
            release.countDown();
            for (Future<TokenResponse> call : calls) {
                assertThat(call.get(5, TimeUnit.SECONDS).accessToken()).isEqualTo("at");
            }
            assertThat(discoveries).hasValue(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("row 11: a call after discovery_ttl discovers again")
    void row11() {
        try (StubZone zone = zone()) {
            ClientCredentialsClient client = client(zone);

            client.requestToken();
            clock.advance(Duration.ofMinutes(59));
            client.requestToken();
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

            clock.advance(Duration.ofMinutes(1));
            client.requestToken();
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(3);
        }
    }

    @Test
    @DisplayName("row 12: metadata without token_endpoint is a typed error, remembered for at most negative_ttl")
    void row12() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, "{\"issuer\":\"" + zone.issuer() + "\"}");
            ClientCredentialsClient client = client(zone);

            assertThatThrownBy(client::requestToken).isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_METADATA);
                assertThat(e.retryable()).isFalse();
            });
            clock.advance(Duration.ofSeconds(59));
            assertThatThrownBy(client::requestToken).isInstanceOf(OAuthProtocolException.class);
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(1);

            clock.advance(Duration.ofSeconds(1));
            zone.serveDiscovery();
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
            assertThat(client.requestToken().accessToken()).isEqualTo("at");
            assertThat(zone.requests(StubZone.DISCOVERY_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("credential operations: a credential without client authentication is rejected before any request")
    void credentialWithoutClientAuthentication() {
        Credential exchangeOnly =
                context -> TokenExchangeRequest.builder(context.subjectToken()).build();

        assertThatThrownBy(() -> ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
                        .credential(exchangeOnly))
                .isInstanceOf(ConfigurationException.class);
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            assertThatThrownBy(() -> ClientCredentialsClient.builder(zone.issuer())
                            .build()
                            .requestToken())
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("bounded requests: the token request carries the client's fetch timeout")
    void tokenRequestIsBounded() {
        List<Duration> timeouts = new ArrayList<>();
        KeycardHttpTransport transport = request -> {
            timeouts.add(request.timeout());
            return request.uri().getPath().startsWith("/.well-known")
                    ? json(
                            "{\"issuer\":\"https://acme.keycard.cloud\",\"token_endpoint\":\"https://acme.keycard.cloud/token\"}")
                    : json(TOKEN_JSON);
        };
        ClientCredentialsClient.builder(URI.create("https://acme.keycard.cloud"))
                .credential(ClientSecret.of("cc-client", "cc-secret"))
                .transport(transport)
                .fetchTimeout(Duration.ofSeconds(4))
                .build()
                .requestToken();

        assertThat(timeouts).containsExactly(Duration.ofSeconds(4), Duration.ofSeconds(4));
    }

    private StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN_JSON);
        return zone;
    }

    private ClientCredentialsClient client(StubZone zone) {
        return ClientCredentialsClient.builder(zone.issuer())
                .credential(ClientSecret.of("cc-client", "cc-secret"))
                .clock(clock)
                .build();
    }

    private static TransportResponse json(String body) {
        return new TransportResponse(200, Map.of("content-type", List.of("application/json")), body);
    }
}
