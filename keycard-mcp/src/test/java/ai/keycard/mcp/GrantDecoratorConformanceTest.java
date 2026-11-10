package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** grant-decorator.md, Unit Tests table, plus the Java filter's own edges. */
class GrantDecoratorConformanceTest {

    private static final String A = "https://a.test";
    private static final String B = "https://b.test";

    @Test
    @DisplayName("row 1: two successful exchanges expose a token per resource with no errors")
    void row1() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            try (TestServer server = serve(zone, provider, probe, provider.grant(A, B))) {
                assertThat(call(server, zone).statusCode()).isEqualTo(200);
            }
            AccessContext context = probe.context();
            assertThat(context.hasErrors()).isFalse();
            assertThat(context.access(A).accessToken()).isEqualTo("at_" + A);
            assertThat(context.access(B).accessToken()).isEqualTo("at_" + B);
            assertThat(zone.requests(StubZone.TOKEN_PATH))
                    .allSatisfy(
                            r -> assertThat(r.formParams().get("subject_token")).containsExactly(probe.callerToken()));
        }
    }

    @Test
    @DisplayName("row 2: a failing resource records an error while the handler still runs")
    void row2() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            zone.respondWith(
                    "POST",
                    StubZone.TOKEN_PATH,
                    r -> resource(r).equals(A)
                            ? StubResponse.json(400, "{\"error\":\"invalid_target\"}")
                            : token(resource(r)));
            AuthProvider provider = provider(zone);
            try (TestServer server = serve(zone, provider, probe, provider.grant(A, B))) {
                assertThat(call(server, zone).statusCode()).isEqualTo(200);
            }
            AccessContext context = probe.context();
            assertThat(context.status()).isEqualTo(AccessContext.Status.PARTIAL_ERROR);
            assertThat(context.access(B).accessToken()).isEqualTo("at_" + B);
            assertThat(context.resourceError(A))
                    .get()
                    .isInstanceOfSatisfying(
                            OAuthErrorException.class,
                            e -> assertThat(e.error()).isEqualTo("invalid_target"));
        }
    }

    @Test
    @DisplayName("row 3: an unauthenticated request is rejected 401 fail-fast and the handler does not run")
    void row3() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            try (TestServer server = new TestServer()
                    .filter("/tools/*", provider.grant(A))
                    .servlet("/tools/*", probe)
                    .start()) {
                HttpResponse<String> response = server.get("/tools/x");

                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                        .startsWith("Bearer")
                        .contains("resource_metadata=");
            }
            assertThat(probe.ran()).isFalse();
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 4: a user identifier turns the exchange into a substitute-user impersonation")
    void row4() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            GrantFilter grant = provider.grant(A).withUserIdentifier(r -> r.getHeader("X-User"));
            try (TestServer server = serve(zone, provider, probe, grant)) {
                HttpResponse<String> response = server.get(
                        "/tools/x", "Authorization", "Bearer " + TestServer.token(zone, "read"), "X-User", "usr_777");
                assertThat(response.statusCode()).isEqualTo(200);
            }
            Map<String, List<String>> form =
                    zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            assertThat(form.get("subject_token_type")).containsExactly(TokenTypes.SUBSTITUTE_USER);
            String[] parts = form.get("subject_token").get(0).split("\\.", -1);
            assertThat(decode(parts[0])).contains("\"typ\":\"vnd.kc.su+jwt\"");
            assertThat(decode(parts[1])).isEqualTo("{\"sub\":\"usr_777\"}");
            assertThat(probe.context().access(A).accessToken()).isEqualTo("at_" + A);
        }
    }

    @Test
    @DisplayName("row 5: stacked grants union their resources into one merged AccessContext")
    void row5() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            try (TestServer server = new TestServer()
                    .filter(
                            "/*",
                            RequireBearerAuthFilter.builder(provider.tokenVerifier())
                                    .build())
                    .filter("/tools/*", provider.grant(A).withRequestScopes("read"))
                    .filter("/tools/*", provider.grant(B))
                    .servlet("/tools/*", probe)
                    .start()) {
                assertThat(call(server, zone).statusCode()).isEqualTo(200);
            }
            assertThat(probe.context().successfulResources()).containsExactly(A, B);
        }
    }

    @Test
    @DisplayName("request scopes go on each exchange: one value for all, or a map per resource")
    void requestScopes() {
        Probe probe = new Probe();
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            GrantFilter grant = provider.grant(A, B).withRequestScopes(Map.of(A, "mail.read mail.send"));
            try (TestServer server = serve(zone, provider, probe, grant)) {
                assertThat(call(server, zone).statusCode()).isEqualTo(200);
            }
            Map<String, List<String>> forA = formFor(zone, A);
            Map<String, List<String>> forB = formFor(zone, B);
            assertThat(forA.get("scope")).containsExactly("mail.read mail.send");
            assertThat(forB).doesNotContainKey("scope");

            assertThatThrownBy(() -> provider.grant(A).withRequestScopes(Map.of(B, "read")))
                    .isInstanceOf(ConfigurationException.class);
        }
    }

    @Test
    @DisplayName("a multi-zone provider exchanges at the zone that issued the caller's token")
    void multiZone() {
        Probe probe = new Probe();
        try (StubZone home = zone();
                StubZone other = zone()) {
            AuthProvider provider = AuthProvider.builder(home.issuer())
                    .credential(ClientSecret.perZone(Map.of(
                            home.issuer(), ClientSecret.of("home-client", "home-secret"),
                            other.issuer(), ClientSecret.of("other-client", "other-secret"))))
                    .audiences(TestServer.AUDIENCE)
                    .build();
            assertThat(provider.issuers()).containsExactlyInAnyOrder(home.issuer(), other.issuer());
            try (TestServer server = serve(other, provider, probe, provider.grant(A))) {
                assertThat(call(server, other).statusCode()).isEqualTo(200);
            }
            assertThat(home.requests(StubZone.TOKEN_PATH)).isEmpty();
            RecordedRequest exchange = other.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(exchange.header("Authorization")).isEqualTo(basic("other-client", "other-secret"));
            assertThat(probe.context().access(A).accessToken()).isEqualTo("at_" + A);
        }
    }

    @Test
    @DisplayName("a token from a zone the provider doesn't serve is a context-wide error, not a 500")
    void unservedZone() {
        Probe probe = new Probe();
        try (StubZone home = zone();
                StubZone stranger = zone()) {
            AuthProvider provider = provider(home);
            AuthProvider strangerProvider = provider(stranger);
            try (TestServer server = new TestServer()
                    .filter(
                            "/*",
                            RequireBearerAuthFilter.builder(strangerProvider.tokenVerifier())
                                    .build())
                    .filter("/tools/*", provider.grant(A))
                    .servlet("/tools/*", probe)
                    .start()) {
                assertThat(call(server, stranger).statusCode()).isEqualTo(200);
            }
            AccessContext context = probe.context();
            assertThat(context.status()).isEqualTo(AccessContext.Status.ERROR);
            assertThat(context.error()).get().isInstanceOf(ConfigurationException.class);
            assertThat(home.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("a grant needs at least one absolute resource URI")
    void resourceValidation() {
        try (StubZone zone = zone()) {
            AuthProvider provider = provider(zone);
            assertThatThrownBy(provider::grant).isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> provider.grant("not a uri")).isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> provider.grant("/relative")).isInstanceOf(ConfigurationException.class);
        }
    }

    @Test
    @DisplayName("imperative exchangeTokens never throws for a failed exchange")
    void imperative() {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"invalid_grant\"}");
            AccessContext context = provider(zone).exchangeTokens("subject", A);
            assertThat(context.resourceError(A)).get().isInstanceOf(KeycardException.class);
            assertThat(context.hasError()).isFalse();
        }
    }

    private static StubZone zone() {
        StubZone zone = TestServer.zone();
        zone.respondWith("POST", StubZone.TOKEN_PATH, r -> token(resource(r)));
        return zone;
    }

    private static AuthProvider provider(StubZone zone) {
        return AuthProvider.builder(zone.issuer())
                .credential(ClientSecret.of("cid", "csecret"))
                .audiences(TestServer.AUDIENCE)
                .build();
    }

    private static TestServer serve(StubZone zone, AuthProvider provider, Probe probe, GrantFilter grant) {
        return new TestServer()
                .filter(
                        "/*",
                        RequireBearerAuthFilter.builder(provider.tokenVerifier())
                                .build())
                .filter("/tools/*", grant)
                .servlet("/tools/*", probe)
                .start();
    }

    private static HttpResponse<String> call(TestServer server, StubZone zone) {
        return server.get("/tools/x", "Authorization", "Bearer " + TestServer.token(zone, "read"));
    }

    private static String resource(RecordedRequest request) {
        return request.formParams().get("resource").get(0);
    }

    private static StubResponse token(String resource) {
        return StubResponse.json(
                200, "{\"access_token\":\"at_" + resource + "\",\"token_type\":\"Bearer\",\"expires_in\":300}");
    }

    private static Map<String, List<String>> formFor(StubZone zone, String resource) {
        return zone.requests(StubZone.TOKEN_PATH).stream()
                .map(RecordedRequest::formParams)
                .filter(form -> form.get("resource").contains(resource))
                .findFirst()
                .orElseThrow();
    }

    private static String decode(String part) {
        return new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8);
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    /** Records what the grant left on the request; a no-op handler otherwise. */
    static final class Probe extends HttpServlet {

        private static final long serialVersionUID = 1L;

        /** The context the last request carried. */
        private final transient AtomicReference<AccessContext> seen = new AtomicReference<>();

        /** The caller's raw token from the last request. */
        private final transient AtomicReference<String> caller = new AtomicReference<>();

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            seen.set(KeycardRequest.accessContext(request).orElse(null));
            caller.set(KeycardRequest.accessToken(request).map(t -> t.token()).orElse(null));
            response.setStatus(200);
            response.getWriter().write("ok");
        }

        boolean ran() {
            return seen.get() != null || caller.get() != null;
        }

        AccessContext context() {
            AccessContext context = seen.get();
            assertThat(context).as("the handler saw an AccessContext").isNotNull();
            return context;
        }

        String callerToken() {
            return caller.get();
        }
    }
}
