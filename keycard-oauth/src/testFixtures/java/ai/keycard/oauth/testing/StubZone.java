package ai.keycard.oauth.testing;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * An in-process Keycard zone for tests: a loopback HTTP server that answers scripted routes and
 * records every request it receives.
 *
 * <p>Built on the JDK's {@code com.sun.net.httpserver} so the test classpath carries nothing the
 * runtime one doesn't. Unscripted routes answer 404 with an OAuth error body.
 *
 * <pre>{@code
 * try (StubZone zone = StubZone.start().serveDiscovery()) {
 *     zone.respond("POST", "/oauth/token", 200, "{\"access_token\":\"t\",\"token_type\":\"Bearer\"}");
 *     // point the client under test at zone.issuer()
 *     assertThat(zone.requests("/oauth/token")).hasSize(1);
 * }
 * }</pre>
 */
public final class StubZone implements AutoCloseable {

    /** Path of the RFC 8414 authorization server metadata document. */
    public static final String DISCOVERY_PATH = "/.well-known/oauth-authorization-server";

    /** Token endpoint path advertised by {@link #serveDiscovery()}. */
    public static final String TOKEN_PATH = "/oauth/token";

    /** JWKS path advertised by {@link #serveDiscovery()}. */
    public static final String JWKS_PATH = "/openidconnect/jwks";

    private final HttpServer server;
    private final URI issuer;
    private final Map<String, Function<RecordedRequest, StubResponse>> routes = new ConcurrentHashMap<>();
    private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();

    private StubZone(HttpServer server) {
        this.server = server;
        this.issuer = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    /**
     * Starts a zone on an ephemeral loopback port.
     *
     * @return the running zone; close it when the test ends
     */
    public static StubZone start() {
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException("could not bind the stub zone", e);
        }
        StubZone zone = new StubZone(server);
        server.createContext("/", zone::handle);
        server.start();
        return zone;
    }

    /**
     * The zone's issuer, which is also its base URL.
     *
     * @return the issuer URI, without a trailing slash
     */
    public URI issuer() {
        return issuer;
    }

    /**
     * Resolves a path against the issuer.
     *
     * @param path an absolute path such as {@code /oauth/token}
     * @return the full URL
     */
    public URI url(String path) {
        return issuer.resolve(path);
    }

    /**
     * Serves an RFC 8414 metadata document advertising this zone's token endpoint and JWKS.
     *
     * @return this zone
     */
    public StubZone serveDiscovery() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", issuer.toString());
        metadata.put("token_endpoint", url(TOKEN_PATH).toString());
        metadata.put("jwks_uri", url(JWKS_PATH).toString());
        metadata.put(
                "grant_types_supported",
                List.of("client_credentials", "authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"));
        return respond("GET", DISCOVERY_PATH, StubResponse.json(200, JSONObjectUtils.toJSONString(metadata)));
    }

    /**
     * Answers {@code method path} with a fixed JSON body, replacing any earlier script for it.
     *
     * @param method the HTTP method, such as {@code POST}
     * @param path the request path, without a query string
     * @param status the response status
     * @param jsonBody the response body
     * @return this zone
     */
    public StubZone respond(String method, String path, int status, String jsonBody) {
        return respond(method, path, StubResponse.json(status, jsonBody));
    }

    /**
     * Answers {@code method path} with a fixed response, replacing any earlier script for it.
     *
     * @param method the HTTP method
     * @param path the request path, without a query string
     * @param response the response to send
     * @return this zone
     */
    public StubZone respond(String method, String path, StubResponse response) {
        return respondWith(method, path, request -> response);
    }

    /**
     * Answers {@code method path} by calling {@code handler} with each request, replacing any
     * earlier script for it. Use this when a test needs to vary the response or assert on the
     * request as it arrives.
     *
     * @param method the HTTP method
     * @param path the request path, without a query string
     * @param handler computes the response
     * @return this zone
     */
    public StubZone respondWith(String method, String path, Function<RecordedRequest, StubResponse> handler) {
        routes.put(key(method, path), handler);
        return this;
    }

    /**
     * Every request received so far, in arrival order.
     *
     * @return an immutable snapshot
     */
    public List<RecordedRequest> requests() {
        return List.copyOf(requests);
    }

    /**
     * The requests received so far for one path, in arrival order.
     *
     * @param path the request path, without a query string
     * @return an immutable snapshot
     */
    public List<RecordedRequest> requests(String path) {
        return requests.stream().filter(r -> r.path().equals(path)).toList();
    }

    /** Stops the server immediately. */
    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            Map<String, List<String>> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders()
                    .forEach((name, values) -> headers.put(name.toLowerCase(Locale.ROOT), List.copyOf(values)));
            RecordedRequest request = new RecordedRequest(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestURI().getRawQuery(),
                    Map.copyOf(headers),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            requests.add(request);

            Function<RecordedRequest, StubResponse> handler = routes.get(key(request.method(), request.path()));
            StubResponse response = handler != null
                    ? handler.apply(request)
                    : StubResponse.json(
                            404,
                            "{\"error\":\"not_found\",\"error_description\":\"no stub for " + request.method() + " "
                                    + request.path() + "\"}");

            response.headers()
                    .forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
            byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(response.status(), body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                exchange.getResponseBody().write(body);
            }
        }
    }

    private static String key(String method, String path) {
        return method.toUpperCase(Locale.ROOT) + " " + path;
    }

    /**
     * A request the zone received.
     *
     * @param method the HTTP method
     * @param path the request path
     * @param rawQuery the raw query string, or {@code null} when there was none
     * @param headers header values keyed by lowercase name
     * @param body the request body as UTF-8
     */
    public record RecordedRequest(
            String method, String path, @Nullable String rawQuery, Map<String, List<String>> headers, String body) {

        /**
         * The first value of a header.
         *
         * @param name the header name, in any case
         * @return the value, or {@code null} when the header is absent
         */
        public @Nullable String header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        /**
         * Decodes an {@code application/x-www-form-urlencoded} body, the shape of every OAuth
         * token request.
         *
         * @return parameter values keyed by name, in body order
         */
        public Map<String, List<String>> formParams() {
            Map<String, List<String>> params = new LinkedHashMap<>();
            if (body.isEmpty()) {
                return params;
            }
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                params.computeIfAbsent(name, n -> new ArrayList<>()).add(value);
            }
            return params;
        }
    }

    /**
     * A scripted response.
     *
     * @param status the HTTP status
     * @param headers response headers
     * @param body the response body
     */
    public record StubResponse(int status, Map<String, String> headers, String body) {

        /**
         * A JSON response.
         *
         * @param status the HTTP status
         * @param body the JSON body
         * @return the response
         */
        public static StubResponse json(int status, String body) {
            return new StubResponse(status, Map.of("Content-Type", "application/json"), body);
        }
    }
}
