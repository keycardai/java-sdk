package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.testing.StubZone;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Regression tests for the pre-release adversarial review of the servlet layer. */
class ServletSecurityTest {

    private static final String RESOURCE = "https://api.example.com";

    @Test
    @DisplayName("an X-Forwarded-Proto other than http or https never reaches the challenge")
    void forwardedProtoAllowlist() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protectedServer(zone, "")) {
            HttpResponse<String> hostile = server.get("/mcp", "X-Forwarded-Proto", "javascript\", x=\"y");
            assertThat(hostile.statusCode()).isEqualTo(401);
            assertThat(challenge(hostile))
                    .contains("resource_metadata=\"http://")
                    .doesNotContain("javascript");

            HttpResponse<String> https = server.get("/mcp", "X-Forwarded-Proto", "HTTPS");
            assertThat(challenge(https)).contains("resource_metadata=\"https://");
        }
    }

    @Test
    @DisplayName("the challenge's metadata URL carries the application's context path")
    void contextPathInChallenge() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protectedServer(zone, "/app")) {
            HttpResponse<String> response = server.get("/app/mcp");
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(challenge(response)).endsWith("/app/.well-known/oauth-protected-resource\"");
        }
    }

    @Test
    @DisplayName("an invalid token's challenge has a fixed description that names no issuer or audience")
    void fixedInvalidTokenDescription() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protectedServer(zone, "")) {
            String wrongAudience = TestServer.token(zone, "read", "https://other.example", TestServer.KEY.getKeyID());
            HttpResponse<String> response = server.get("/mcp", "Authorization", "Bearer " + wrongAudience);
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(challenge(response))
                    .contains("error=\"invalid_token\"")
                    .contains("error_description=\"the access token is invalid or expired\"")
                    .doesNotContain(TestServer.AUDIENCE)
                    .doesNotContain("other.example");
        }
    }

    @Test
    @DisplayName("on a forward, the bearer filter still applies its own scopes and the grant doesn't exchange twice")
    void forwardIsCheckedOnce() {
        try (StubZone zone = TestServer.zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}");
            AuthProvider provider = AuthProvider.builder(zone.issuer())
                    .credential(ClientSecret.of("cid", "csecret"))
                    .audiences(TestServer.AUDIENCE)
                    .build();
            Probe probe = new Probe();
            try (TestServer server = new TestServer()
                    .filter(
                            "/*",
                            RequireBearerAuthFilter.builder(provider.tokenVerifier())
                                    .build(),
                            DispatcherType.REQUEST,
                            DispatcherType.FORWARD)
                    .filter("/*", provider.grant(RESOURCE), DispatcherType.REQUEST, DispatcherType.FORWARD)
                    .filter(
                            "/admin/*",
                            RequireBearerAuthFilter.builder(provider.tokenVerifier())
                                    .requiredScopes("admin")
                                    .build(),
                            DispatcherType.REQUEST,
                            DispatcherType.FORWARD)
                    .servlet("/front/*", new Forward("/mcp"))
                    .servlet("/sneak/*", new Forward("/admin"))
                    .servlet("/mcp/*", probe)
                    .servlet("/admin/*", probe)
                    .start()) {
                String read = "Bearer " + TestServer.token(zone, "read");
                assertThat(server.get("/front", "Authorization", read).statusCode())
                        .isEqualTo(200);
                assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
                assertThat(probe.context.successfulResources()).containsExactly(RESOURCE);

                HttpResponse<String> sneak = server.get("/sneak", "Authorization", read);
                assertThat(sneak.statusCode()).isEqualTo(403);
                assertThat(challenge(sneak)).contains("insufficient_scope");
            }
        }
    }

    @Test
    @DisplayName("a bearer filter over a multi-zone verifier needs a zone resolver")
    void multiZoneNeedsResolver() {
        TokenVerifier verifier = TokenVerifier.builder(
                        java.net.URI.create("https://a.example"), java.net.URI.create("https://b.example"))
                .audiences(TestServer.AUDIENCE)
                .build();
        assertThatThrownBy(() -> RequireBearerAuthFilter.builder(verifier).build())
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("zoneResolver");
        RequireBearerAuthFilter.builder(verifier)
                .zoneResolver(request -> java.net.URI.create("https://a.example"))
                .build();
    }

    private static TestServer protectedServer(StubZone zone, String contextPath) {
        return new TestServer()
                .contextPath(contextPath)
                .filter(
                        "/mcp/*",
                        RequireBearerAuthFilter.builder(TokenVerifier.builder(zone.issuer())
                                        .audiences(TestServer.AUDIENCE)
                                        .build())
                                .build())
                .servlet("/mcp/*", new Probe())
                .start();
    }

    private static String challenge(HttpResponse<String> response) {
        return response.headers().firstValue("WWW-Authenticate").orElse("");
    }

    /** Forwards every request to another path in the same application. */
    private static final class Forward extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final String target;

        Forward(String target) {
            this.target = target;
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            request.getRequestDispatcher(target).forward(request, response);
        }
    }

    /** Answers 200 and remembers the last AccessContext it saw. */
    private static final class Probe extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private transient AccessContext context = new AccessContext(Map.of());

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            KeycardRequest.accessContext(request).ifPresent(found -> context = found);
            response.setStatus(200);
            response.getWriter().write("ok");
        }
    }
}
