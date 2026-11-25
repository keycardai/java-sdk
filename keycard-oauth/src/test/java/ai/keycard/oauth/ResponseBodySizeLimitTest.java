package ai.keycard.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Conformance tests for response body size limits (base.md rows 1, 1a, 1b, 1c and device-authorization.md row 36). */
class ResponseBodySizeLimitTest {

    private static final int LIMIT = KeycardHttpTransport.MAX_RESPONSE_BODY_BYTES;

    private static byte[] makeTokenJson(int extraBytes) {
        String prefix = "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"pad\":\"";
        String suffix = "\"}";
        int padLen = LIMIT - prefix.length() - suffix.length() + extraBytes;
        return (prefix + "a".repeat(padLen) + suffix).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] gzip(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(data);
        }
        return out.toByteArray();
    }

    private static HttpServer startServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        return server;
    }

    private static URI baseUri(HttpServer server) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    private static void send(com.sun.net.httpserver.HttpExchange ex, int status, byte[] body, String encoding)
            throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json");
        if (encoding != null) {
            ex.getResponseHeaders().set("Content-Encoding", encoding);
        }
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    @Test
    @DisplayName("row 1: gzip token response inflating above 1 MiB fails with retryable invalid_response")
    void row1_gzipTokenOverflow() throws Exception {
        byte[] compressed = gzip(makeTokenJson(1024));
        assertThat(compressed.length).isLessThan(LIMIT);

        HttpServer server = startServer();
        try {
            URI issuer = baseUri(server);
            server.createContext("/.well-known/oauth-authorization-server", ex -> {
                byte[] md = ("{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\"}")
                        .getBytes(StandardCharsets.UTF_8);
                send(ex, 200, md, null);
            });
            server.createContext("/token", ex -> send(ex, 200, compressed, "gzip"));

            ClientCredentialsClient client = ClientCredentialsClient.builder(issuer)
                    .credential(ClientSecret.of("cid", "csec"))
                    .build();

            assertThatThrownBy(() -> client.requestToken(
                            ClientCredentialsRequest.builder().build()))
                    .isInstanceOf(ResponseBodyTooLargeException.class)
                    .satisfies(err -> {
                        ResponseBodyTooLargeException e = (ResponseBodyTooLargeException) err;
                        assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                        assertThat(e.status()).isEqualTo(200);
                        assertThat(e.retryable()).isTrue();
                    });
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("row 1: exact 1 MiB decoded body succeeds and 1 MiB + 1 byte fails")
    void row1_exactBoundary() throws Exception {
        byte[] exact = makeTokenJson(0);
        byte[] over = makeTokenJson(1);
        AtomicBoolean sendOver = new AtomicBoolean(false);

        HttpServer server = startServer();
        try {
            URI issuer = baseUri(server);
            server.createContext("/.well-known/oauth-authorization-server", ex -> {
                byte[] md = ("{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\"}")
                        .getBytes(StandardCharsets.UTF_8);
                send(ex, 200, md, null);
            });
            server.createContext("/token", ex -> send(ex, 200, sendOver.get() ? over : exact, null));

            ClientCredentialsClient client = ClientCredentialsClient.builder(issuer)
                    .credential(ClientSecret.of("cid", "csec"))
                    .build();

            TokenResponse tok =
                    client.requestToken(ClientCredentialsRequest.builder().build());
            assertThat(tok.accessToken()).isEqualTo("tok");

            sendOver.set(true);
            assertThatThrownBy(() -> client.requestToken(
                            ClientCredentialsRequest.builder().build()))
                    .isInstanceOf(ResponseBodyTooLargeException.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("row 1a: discovery overflow on 200, 429, 503 is not negatively cached while 400 is")
    void row1a_discoveryNegativeCaching() throws Exception {
        record Case(int status, boolean expectNegativeCached) {}
        for (Case tc : List.of(new Case(200, false), new Case(429, false), new Case(503, false), new Case(400, true))) {
            AtomicInteger calls = new AtomicInteger();
            AtomicBoolean failFirst = new AtomicBoolean(true);
            HttpServer server = startServer();
            try {
                URI issuer = baseUri(server);
                server.createContext("/.well-known/oauth-authorization-server", ex -> {
                    calls.incrementAndGet();
                    if (failFirst.get()) {
                        send(ex, tc.status(), makeTokenJson(512), null);
                    } else {
                        byte[] md = ("{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\"}")
                                .getBytes(StandardCharsets.UTF_8);
                        send(ex, 200, md, null);
                    }
                });

                AuthorizationServerMetadataCache cache = AuthorizationServerMetadataCache.builder()
                        .negativeTtl(Duration.ofMinutes(1))
                        .build();

                assertThatThrownBy(() -> cache.get(issuer)).isInstanceOf(ResponseBodyTooLargeException.class);
                assertThat(calls.get()).isEqualTo(1);

                failFirst.set(false);
                if (tc.expectNegativeCached()) {
                    assertThatThrownBy(() -> cache.get(issuer)).isInstanceOf(ResponseBodyTooLargeException.class);
                    assertThat(calls.get()).isEqualTo(1);
                } else {
                    AuthorizationServerMetadata md = cache.get(issuer);
                    assertThat(md.tokenEndpoint()).isEqualTo(URI.create(issuer + "/token"));
                    assertThat(calls.get()).isEqualTo(2);
                }
            } finally {
                server.stop(0);
            }
        }
    }

    @Test
    @DisplayName(
            "row 1a: JWKS discovery overflow maps to JwksException.Discovery and fetch overflow to JwksException.Fetch")
    void row1a_jwksErrorMapping() throws Exception {
        AtomicBoolean failDiscovery = new AtomicBoolean(true);
        HttpServer server = startServer();
        try {
            URI issuer = baseUri(server);
            server.createContext("/.well-known/oauth-authorization-server", ex -> {
                if (failDiscovery.get()) {
                    send(ex, 200, makeTokenJson(512), null);
                } else {
                    byte[] md = ("{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + issuer + "/jwks\"}")
                            .getBytes(StandardCharsets.UTF_8);
                    send(ex, 200, md, null);
                }
            });
            server.createContext("/jwks", ex -> send(ex, 200, makeTokenJson(512), null));

            JwksKeyring keyring = JwksKeyring.create();
            assertThatThrownBy(() -> keyring.resolve(issuer, "k1"))
                    .isInstanceOf(JwksException.Discovery.class)
                    .satisfies(
                            e -> assertThat(((KeycardException) e).retryable()).isTrue());

            failDiscovery.set(false);
            assertThatThrownBy(() -> keyring.resolve(issuer, "k1"))
                    .isInstanceOf(JwksException.Fetch.class)
                    .satisfies(
                            e -> assertThat(((KeycardException) e).retryable()).isTrue());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName(
            "row 1c: 400 token response with oversized body returns non-retryable invalid_response without parsing OAuth error")
    void row1c_tokenEndpoint400Oversized() throws Exception {
        String prefix = "{\"error\":\"invalid_grant\",\"error_description\":\"";
        String suffix = "\"}";
        byte[] body = (prefix + "x".repeat(LIMIT - prefix.length() - suffix.length() + 256) + suffix)
                .getBytes(StandardCharsets.UTF_8);

        HttpServer server = startServer();
        try {
            URI issuer = baseUri(server);
            server.createContext("/.well-known/oauth-authorization-server", ex -> {
                byte[] md = ("{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\"}")
                        .getBytes(StandardCharsets.UTF_8);
                send(ex, 200, md, null);
            });
            server.createContext("/token", ex -> send(ex, 400, body, null));

            ClientCredentialsClient client = ClientCredentialsClient.builder(issuer)
                    .credential(ClientSecret.of("cid", "csec"))
                    .build();

            assertThatThrownBy(() -> client.requestToken(
                            ClientCredentialsRequest.builder().build()))
                    .isInstanceOf(ResponseBodyTooLargeException.class)
                    .satisfies(err -> {
                        ResponseBodyTooLargeException e = (ResponseBodyTooLargeException) err;
                        assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                        assertThat(e.status()).isEqualTo(400);
                        assertThat(e.retryable()).isFalse();
                    });
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName(
            "row 1b and row 36: oversized device poll responses wrap 429/503 with undoubled interval and fail PollToken on 200/400/429/503")
    void row1bAndRow36_devicePolling() throws Exception {
        for (int status : List.of(429, 503)) {
            AtomicInteger pollCount = new AtomicInteger();
            HttpServer server = startServer();
            try {
                URI issuer = baseUri(server);
                server.createContext("/token", ex -> {
                    if (pollCount.incrementAndGet() == 1) {
                        send(ex, 400, "{\"error\":\"slow_down\"}".getBytes(StandardCharsets.UTF_8), null);
                    } else {
                        send(ex, status, makeTokenJson(512), null);
                    }
                });

                AtomicReference<Instant> now = new AtomicReference<>(Instant.ofEpochSecond(1_000_000));
                Clock clock = new Clock() {
                    @Override
                    public java.time.ZoneId getZone() {
                        return ZoneOffset.UTC;
                    }

                    @Override
                    public Clock withZone(java.time.ZoneId zone) {
                        return this;
                    }

                    @Override
                    public Instant instant() {
                        return now.get();
                    }
                };
                AuthorizationServerMetadata md = new AuthorizationServerMetadata(
                        issuer,
                        URI.create(issuer + "/token"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        URI.create(issuer + "/device"),
                        List.of(),
                        List.of(),
                        List.of(),
                        java.util.Map.of());
                DeviceAuthorizationClient client = DeviceAuthorizationClient.builder(md)
                        .clientId("cid")
                        .clock(clock)
                        .sleeper(d -> now.set(now.get().plus(d)))
                        .build();

                DeviceAuthorization auth = new DeviceAuthorization(
                        "dev-1",
                        "ABCD-1234",
                        URI.create(issuer + "/verify"),
                        null,
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(5),
                        now.get().plusSeconds(600));

                assertThatThrownBy(() -> client.pollUntilDone(auth))
                        .isInstanceOf(DevicePollException.class)
                        .satisfies(err -> {
                            DevicePollException e = (DevicePollException) err;
                            assertThat(e.interval()).isEqualTo(Duration.ofSeconds(10));
                            assertThat(e.getCause()).isInstanceOf(ResponseBodyTooLargeException.class);
                            assertThat(((ResponseBodyTooLargeException) e.getCause()).status())
                                    .isEqualTo(status);
                        });
            } finally {
                server.stop(0);
            }
        }

        for (int status : List.of(200, 400, 429, 503)) {
            HttpServer server = startServer();
            try {
                URI issuer = baseUri(server);
                server.createContext("/token", ex -> send(ex, status, makeTokenJson(512), null));
                AuthorizationServerMetadata md = new AuthorizationServerMetadata(
                        issuer,
                        URI.create(issuer + "/token"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        URI.create(issuer + "/device"),
                        List.of(),
                        List.of(),
                        List.of(),
                        java.util.Map.of());
                DeviceAuthorizationClient client =
                        DeviceAuthorizationClient.builder(md).clientId("cid").build();
                DeviceAuthorization auth = new DeviceAuthorization(
                        "dev-1",
                        "ABCD-1234",
                        URI.create(issuer + "/verify"),
                        null,
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(5),
                        Instant.now().plusSeconds(600));

                assertThatThrownBy(() -> client.pollOnce(auth))
                        .isInstanceOf(ResponseBodyTooLargeException.class)
                        .satisfies(err -> {
                            ResponseBodyTooLargeException e = (ResponseBodyTooLargeException) err;
                            assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                            assertThat(e.status()).isEqualTo(status);
                        });
            } finally {
                server.stop(0);
            }
        }
    }

    @Test
    @DisplayName("row 36: pollUntilDone returns invalid_response directly for an oversized 200 or 400")
    void row36_pollUntilDoneOversized200And400() throws Exception {
        for (int status : List.of(200, 400)) {
            AtomicInteger pollCount = new AtomicInteger();
            HttpServer server = startServer();
            try {
                URI issuer = baseUri(server);
                server.createContext("/token", ex -> {
                    pollCount.incrementAndGet();
                    send(ex, status, makeTokenJson(512), null);
                });
                AtomicReference<Instant> now = new AtomicReference<>(Instant.ofEpochSecond(1_000_000));
                Clock clock = new Clock() {
                    @Override
                    public java.time.ZoneId getZone() {
                        return ZoneOffset.UTC;
                    }

                    @Override
                    public Clock withZone(java.time.ZoneId zone) {
                        return this;
                    }

                    @Override
                    public Instant instant() {
                        return now.get();
                    }
                };
                AuthorizationServerMetadata md = new AuthorizationServerMetadata(
                        issuer,
                        URI.create(issuer + "/token"),
                        null,
                        null,
                        null,
                        null,
                        null,
                        URI.create(issuer + "/device"),
                        List.of(),
                        List.of(),
                        List.of(),
                        java.util.Map.of());
                DeviceAuthorizationClient client = DeviceAuthorizationClient.builder(md)
                        .clientId("cid")
                        .clock(clock)
                        .sleeper(d -> now.set(now.get().plus(d)))
                        .build();
                DeviceAuthorization auth = new DeviceAuthorization(
                        "dev-1",
                        "ABCD-1234",
                        URI.create(issuer + "/verify"),
                        null,
                        Duration.ofSeconds(600),
                        Duration.ofSeconds(5),
                        now.get().plusSeconds(600));

                assertThatThrownBy(() -> client.pollUntilDone(auth))
                        .isExactlyInstanceOf(ResponseBodyTooLargeException.class)
                        .satisfies(err -> {
                            ResponseBodyTooLargeException e = (ResponseBodyTooLargeException) err;
                            assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                            assertThat(e.status()).isEqualTo(status);
                        });
                assertThat(pollCount).hasValue(1);
            } finally {
                server.stop(0);
            }
        }
    }

    @Test
    @DisplayName("an empty gzip-encoded 204 body reads as empty instead of failing")
    void emptyGzipBody() throws Exception {
        HttpServer server = startServer();
        try {
            server.createContext("/empty", ex -> {
                ex.getResponseHeaders().set("Content-Encoding", "gzip");
                ex.sendResponseHeaders(204, -1);
                ex.close();
            });
            TransportResponse response = new JdkHttpTransport(java.net.http.HttpClient.newHttpClient())
                    .send(TransportRequest.get(URI.create(baseUri(server) + "/empty"), Duration.ofSeconds(5)));
            assertThat(response.status()).isEqualTo(204);
            assertThat(response.body()).isEmpty();
        } finally {
            server.stop(0);
        }
    }
}
