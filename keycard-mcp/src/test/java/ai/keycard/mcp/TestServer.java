package ai.keycard.mcp;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/** An embedded Jetty 12 server for servlet-layer tests, plus token helpers. */
final class TestServer implements AutoCloseable {

    static final RSAKey KEY = key("test-key");
    static final String AUDIENCE = "https://mcp.example.com/mcp";

    private final Server server;
    private final ServletContextHandler context;
    private final HttpClient client =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    TestServer() {
        this.server = new Server(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        this.context = new ServletContextHandler();
        server.setHandler(context);
    }

    TestServer servlet(String path, HttpServlet servlet) {
        context.addServlet(new ServletHolder(servlet), path);
        return this;
    }

    TestServer filter(String path, Filter filter) {
        context.addFilter(new FilterHolder(filter), path, EnumSet.of(DispatcherType.REQUEST));
        return this;
    }

    TestServer filter(String path, Filter filter, DispatcherType first, DispatcherType... rest) {
        context.addFilter(new FilterHolder(filter), path, EnumSet.of(first, rest));
        return this;
    }

    TestServer contextPath(String contextPath) {
        context.setContextPath(contextPath);
        return this;
    }

    TestServer start() {
        try {
            server.start();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    URI url(String path) {
        int port = ((ServerConnector) server.getConnectors()[0]).getLocalPort();
        return URI.create("http://127.0.0.1:" + port + path);
    }

    HttpResponse<String> get(String path, String... headers) {
        return send(HttpRequest.newBuilder(url(path)).GET(), headers);
    }

    HttpResponse<String> options(String path) {
        return send(HttpRequest.newBuilder(url(path)).method("OPTIONS", HttpRequest.BodyPublishers.noBody()));
    }

    private HttpResponse<String> send(HttpRequest.Builder builder, String... headers) {
        for (int i = 0; i < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        try {
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        try {
            server.stop();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes the verified caller back as plain text. */
    static final class Echo extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            AccessToken token = KeycardRequest.accessToken(request).orElse(null);
            String body = token == null
                    ? "anonymous"
                    : String.join(
                            "|",
                            token.subject(),
                            String.valueOf(token.subjectProfile()),
                            token.clientId(),
                            String.valueOf(token.keycardAppId()),
                            String.join(" ", token.scopes()),
                            String.join(" ", token.audiences()),
                            String.valueOf(token.expiresAt().getEpochSecond()));
            response.setContentType("text/plain");
            response.getWriter().write(body);
        }
    }

    static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(KEY.toPublicJWK()).toString());
        return zone;
    }

    static String token(StubZone zone, String scope) {
        return token(zone, scope, AUDIENCE, KEY.getKeyID());
    }

    static String token(StubZone zone, String scope, String audience, String kid) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", zone.issuer().toString());
        claims.put("sub", "user-1");
        claims.put("sub_profile", "user");
        claims.put("keycard_app_id", "app-1");
        claims.put("client_id", "client-1");
        claims.put("aud", List.of(audience));
        claims.put("scope", scope);
        claims.put("iat", now);
        claims.put("exp", now + 300);
        try {
            return JwtSigner.of(new SigningKey(KEY.toRSAPrivateKey(), kid, null))
                    .sign(claims);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey key(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
