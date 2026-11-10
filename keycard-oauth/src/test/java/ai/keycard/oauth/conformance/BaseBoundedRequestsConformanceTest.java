package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.TransportRequest;
import ai.keycard.oauth.TransportResponse;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** base.md (spec-version 5), Operational principles: bounded requests, pluggable HTTP, no hidden retries. */
class BaseBoundedRequestsConformanceTest {

    private static final URI ISSUER = URI.create("https://acme.keycard.cloud");

    @Test
    @DisplayName("bounded requests: discovery defaults to a 10 second timeout")
    void defaultTimeoutIsTenSeconds() {
        AtomicReference<TransportRequest> seen = new AtomicReference<>();
        AuthorizationServerDiscovery discovery = AuthorizationServerDiscovery.builder()
                .transport(request -> {
                    seen.set(request);
                    return metadata();
                })
                .build();

        discovery.discover(ISSUER);

        assertThat(KeycardHttpTransport.DEFAULT_TIMEOUT).isEqualTo(Duration.ofSeconds(10));
        assertThat(seen.get().timeout()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    @DisplayName("bounded requests: the caller can change the timeout")
    void callerSetsTimeout() {
        AtomicReference<TransportRequest> seen = new AtomicReference<>();
        AuthorizationServerDiscovery discovery = AuthorizationServerDiscovery.builder()
                .transport(request -> {
                    seen.set(request);
                    return metadata();
                })
                .fetchTimeout(Duration.ofSeconds(3))
                .build();

        discovery.discover(ISSUER);

        assertThat(seen.get().timeout()).isEqualTo(Duration.ofSeconds(3));
        assertThatThrownBy(() -> AuthorizationServerDiscovery.builder().fetchTimeout(Duration.ZERO))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("bounded requests: a server that never answers times out as a retryable network error")
    void slowServerTimesOut() throws Exception {
        HttpServer server = server((exchange, out) -> sleep(1200));
        try {
            long start = System.nanoTime();
            assertThatThrownBy(() -> discovery(Duration.ofMillis(300)).discover(issuer(server)))
                    .isInstanceOfSatisfying(NetworkException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.getCause()).isInstanceOf(HttpTimeoutException.class);
                    });
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1100));
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("bounded requests: the bound covers the body, not only the response headers")
    void stalledBodyTimesOut() throws Exception {
        HttpServer server = server((exchange, out) -> {
            exchange.sendResponseHeaders(200, 0);
            out.write("{\"issuer\":".getBytes(StandardCharsets.UTF_8));
            out.flush();
            sleep(1200);
        });
        try {
            long start = System.nanoTime();
            assertThatThrownBy(() -> discovery(Duration.ofMillis(300)).discover(issuer(server)))
                    .isInstanceOf(NetworkException.class)
                    .hasCauseInstanceOf(HttpTimeoutException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1100));
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("an interrupted caller gets a network error and keeps its interrupt flag")
    void interruptionIsReported() throws Exception {
        HttpServer server = server((exchange, out) -> sleep(1200));
        try {
            AtomicReference<Throwable> outcome = new AtomicReference<>();
            AtomicReference<Boolean> flag = new AtomicReference<>();
            Thread caller = new Thread(() -> {
                try {
                    discovery(Duration.ofSeconds(10)).discover(issuer(server));
                } catch (RuntimeException e) {
                    outcome.set(e);
                    flag.set(Thread.currentThread().isInterrupted());
                }
            });
            caller.start();
            Thread.sleep(300);
            caller.interrupt();
            caller.join(5000);

            assertThat(outcome.get())
                    .isInstanceOf(NetworkException.class)
                    .hasCauseInstanceOf(InterruptedException.class);
            assertThat(flag.get()).isTrue();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("no hidden retries: a failed request is sent once")
    void noHiddenRetries() throws Exception {
        int[] hits = {0};
        HttpServer server = server((exchange, out) -> {
            hits[0]++;
            exchange.sendResponseHeaders(503, -1);
        });
        try {
            assertThatThrownBy(() -> discovery(Duration.ofSeconds(5)).discover(issuer(server)))
                    .isInstanceOf(RuntimeException.class);
            assertThat(hits[0]).isEqualTo(1);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("pluggable HTTP: a caller-configured JDK client carries the requests")
    void callerSuppliedHttpClient() throws Exception {
        HttpServer server = server((exchange, out) -> {
            byte[] body =
                    ("{\"issuer\":\"" + issuer(exchange.getLocalAddress()) + "\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            out.write(body);
        });
        try {
            AuthorizationServerDiscovery discovery = AuthorizationServerDiscovery.builder()
                    .httpClient(java.net.http.HttpClient.newBuilder()
                            .version(java.net.http.HttpClient.Version.HTTP_1_1)
                            .build())
                    .build();

            assertThat(discovery.discover(issuer(server)).issuer()).isEqualTo(issuer(server));
        } finally {
            server.stop(0);
        }
    }

    private interface Handler {
        void handle(com.sun.net.httpserver.HttpExchange exchange, OutputStream out) throws Exception;
    }

    private static HttpServer server(Handler handler) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            try (exchange;
                    OutputStream out = exchange.getResponseBody()) {
                handler.handle(exchange, out);
            } catch (Exception e) {
                // the client has gone away; nothing to report
            }
        });
        server.start();
        return server;
    }

    private static URI issuer(HttpServer server) {
        return issuer(server.getAddress());
    }

    private static URI issuer(InetSocketAddress address) {
        return URI.create("http://127.0.0.1:" + address.getPort());
    }

    private static AuthorizationServerDiscovery discovery(Duration timeout) {
        return AuthorizationServerDiscovery.builder().fetchTimeout(timeout).build();
    }

    private static TransportResponse metadata() {
        return new TransportResponse(
                200, Map.of("content-type", List.of("application/json")), "{\"issuer\":\"" + ISSUER + "\"}");
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
