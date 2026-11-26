package ai.keycard.mcp;

import static ai.keycard.mcp.TestServer.AUDIENCE;
import static ai.keycard.oauth.testing.IntrospectionStub.PATH;
import static ai.keycard.oauth.testing.IntrospectionStub.issuer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.testing.IntrospectionStub;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** bearer-token-verification-middleware.md (spec-version 8). */
class BearerTokenIntrospectionConformanceTest {

    private static final ClientSecret OWNER = ClientSecret.of("owner", "secret");
    private static final String OWNER_BASIC = "Basic b3duZXI6c2VjcmV0";

    @Test
    @DisplayName("row 18: an active response lets the verified caller reach the handler")
    void row18() {
        try (StubZone zone = zone()) {
            String token = token(zone, AUDIENCE);
            Duration timeout = Duration.ofSeconds(3);
            KeycardHttpTransport loopback = IntrospectionStub.transport(zone);
            try (TestServer server =
                    server(filter(zone).introspectionTimeout(timeout).introspectionTransport(request -> {
                        assertThat(request.timeout()).isEqualTo(timeout);
                        return loopback.send(request);
                    }))) {
                assertThat(request(server, token).body()).startsWith("user-1|user|client-1|app-1|");
            }
            assertThat(zone.requests(PATH)).singleElement().satisfies(call -> {
                assertThat(call.header("Authorization")).isEqualTo(OWNER_BASIC);
                assertThat(call.formParams()).containsExactlyEntriesOf(Map.of("token", List.of(token)));
            });
        }
    }

    @Test
    @DisplayName("row 19: an inactive token receives an invalid_token challenge with applicable metadata")
    void row19() {
        try (StubZone zone = zone();
                TestServer server = server(filter(zone))) {
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            assertInactive(request(server, token(zone, AUDIENCE)));
        }
    }

    @Test
    @DisplayName("row 20: transport, metadata, HTTP, OAuth and response failures return 503 without a challenge")
    void row20() {
        try (StubZone zone = zone();
                TestServer server = server(filter(zone))) {
            String token = token(zone, AUDIENCE);
            IntrospectionStub.discovery(zone, false);
            assertUnavailable(request(server, token));
            assertThat(zone.requests(PATH)).isEmpty();
        }
        try (StubZone zone = zone();
                TestServer server = server(filter(zone))) {
            for (Failure failure : List.of(
                    new Failure(401, "{\"error\":\"invalid_client\"}"),
                    new Failure(500, "{\"error\":\"server_error\"}"),
                    new Failure(502, "gateway error"),
                    new Failure(200, "{\"active\":\"true\"}"),
                    new Failure(200, "not JSON"))) {
                zone.respond("POST", PATH, failure.status(), failure.body());
                assertUnavailable(request(server, token(zone, AUDIENCE)));
            }
            assertThat(zone.requests(PATH)).hasSize(5);
        }
        try (StubZone zone = zone();
                TestServer server = server(filter(zone).introspectionTransport(request -> {
                    throw new NetworkException("zone is unavailable", new IOException());
                }))) {
            assertUnavailable(request(server, token(zone, AUDIENCE)));
            assertThat(zone.requests(PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 21: invalid local tokens and default or disabled introspection make no introspection call")
    void row21() {
        try (StubZone zone = zone();
                TestServer enabled = server(filter(zone));
                TestServer omitted =
                        server(RequireBearerAuthFilter.builder(verifier(zone)).resourceIdentifier(AUDIENCE));
                TestServer disabled = server(filter(zone).introspect(false))) {
            assertThat(request(enabled, token(zone, "https://unrelated.example"))
                            .statusCode())
                    .isEqualTo(401);
            assertThat(request(omitted, token(zone, AUDIENCE)).statusCode()).isEqualTo(200);
            assertThat(request(disabled, token(zone, AUDIENCE)).statusCode()).isEqualTo(200);
            assertThat(zone.requests(PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 22: the same token is introspected again and can become inactive")
    void row22() {
        try (StubZone zone = zone();
                TestServer server = server(filter(zone))) {
            String token = token(zone, AUDIENCE);
            assertThat(request(server, token).statusCode()).isEqualTo(200);
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            assertInactive(request(server, token));
            assertThat(zone.requests(PATH))
                    .hasSize(2)
                    .allSatisfy(
                            call -> assertThat(call.formParams().get("token")).containsExactly(token));
        }
    }

    @Test
    @DisplayName("row 23: missing, non-authenticating and unkeyed multi-zone credentials fail at construction")
    void row23() {
        try (StubZone a = zone();
                StubZone b = zone()) {
            assertThatThrownBy(() -> RequireBearerAuthFilter.builder(verifier(a))
                            .resourceIdentifier(AUDIENCE)
                            .introspect(true)
                            .build())
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("client authentication");
            Credential exchangeOnly = context -> OWNER.prepareTokenExchangeRequest(context);
            assertThatThrownBy(() -> filter(a).credential(exchangeOnly).build())
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("client authentication");
            assertThatThrownBy(() -> multiZone(a, b).credential(OWNER).build())
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("zone-keyed credential");
        }
    }

    @Test
    @DisplayName("a redirect-following JDK transport fails at construction")
    void rejectsRedirectFollowingTransport() {
        try (StubZone zone = zone()) {
            KeycardHttpTransport redirects = KeycardHttpTransport.of(HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build());
            assertThatThrownBy(
                            () -> filter(zone).introspectionTransport(redirects).build())
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("redirects to be disabled");
        }
    }

    @Test
    @DisplayName("row 24: a missing zone credential fails closed and configured issuers use their own credentials")
    void row24() {
        try (StubZone a = zone();
                StubZone b = zone();
                TestServer partial =
                        server(multiZone(a, b).credential(ClientSecret.perZone(Map.of(issuer(a), OWNER))));
                TestServer complete = server(multiZone(a, b)
                        .credential(ClientSecret.perZone(
                                Map.of(issuer(a), OWNER, issuer(b), ClientSecret.of("other", "secret")))))) {
            assertUnavailable(requestZoneB(partial, token(b, AUDIENCE)));
            assertThat(a.requests(PATH)).isEmpty();
            assertThat(b.requests(PATH)).isEmpty();
            assertThat(request(complete, token(a, AUDIENCE)).statusCode()).isEqualTo(200);
            assertThat(requestZoneB(complete, token(b, AUDIENCE)).statusCode()).isEqualTo(200);
            assertThat(a.requests(PATH))
                    .singleElement()
                    .satisfies(call -> assertThat(call.header("Authorization")).isEqualTo(OWNER_BASIC));
            assertThat(b.requests(PATH))
                    .singleElement()
                    .satisfies(call -> assertThat(call.header("Authorization")).isEqualTo("Basic b3RoZXI6c2VjcmV0"));
        }
    }

    @Test
    @DisplayName("row 25: a token that lacks a required scope is rejected without introspection")
    void row25() {
        try (StubZone zone = zone();
                TestServer server = server(filter(zone).requiredScopes("admin"))) {
            var response = request(server, token(zone, AUDIENCE));
            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(response.headers().firstValue("WWW-Authenticate"))
                    .hasValueSatisfying(value -> assertThat(value).contains("error=\"insufficient_scope\""));
            assertThat(zone.requests(PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("integration rows 3, 4 and 5 (stub zone): the resource owner sees active tokens only")
    void resourceOwnerVisibility() {
        try (StubZone zone = zone();
                TestServer server = server(filter(zone))) {
            String first = token(zone, List.of(AUDIENCE, "https://unrelated.example"));
            String later = token(zone, List.of("https://unrelated.example", AUDIENCE));
            zone.respondWith(
                    "POST",
                    PATH,
                    call -> StubResponse.json(
                            200,
                            OWNER_BASIC.equals(call.header("Authorization"))
                                            && call.formParams().get("token").equals(List.of(first))
                                    ? "{\"active\":true}"
                                    : "{\"active\":false}"));
            assertThat(request(server, first).statusCode()).isEqualTo(200);
            assertInactive(request(server, later));
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            assertInactive(request(server, first));
            assertThat(zone.requests(PATH)).hasSize(3);
        }
    }

    private static StubZone zone() {
        StubZone zone = TestServer.zone();
        IntrospectionStub.discovery(zone, true);
        return zone.respond("POST", PATH, 200, "{\"active\":true}");
    }

    private static TokenVerifier verifier(StubZone zone) {
        return TokenVerifier.builder(issuer(zone))
                .audiences(AUDIENCE)
                .transport(IntrospectionStub.transport(zone))
                .build();
    }

    private static RequireBearerAuthFilter.Builder filter(StubZone zone) {
        return RequireBearerAuthFilter.builder(verifier(zone))
                .resourceIdentifier(AUDIENCE)
                .introspect(true)
                .credential(OWNER)
                .introspectionTransport(IntrospectionStub.transport(zone));
    }

    private static RequireBearerAuthFilter.Builder multiZone(StubZone a, StubZone b) {
        KeycardHttpTransport transport = IntrospectionStub.transport(a, b);
        TokenVerifier verifier = TokenVerifier.builder(issuer(a), issuer(b))
                .audiences(AUDIENCE)
                .transport(transport)
                .build();
        return RequireBearerAuthFilter.builder(verifier)
                .multiResource(true)
                .zoneResolver(request -> "b".equals(request.getHeader("X-Test-Zone")) ? issuer(b) : issuer(a))
                .introspect(true)
                .introspectionTransport(transport);
    }

    private static TestServer server(RequireBearerAuthFilter.Builder filter) {
        return new TestServer()
                .servlet("/mcp", new TestServer.Echo())
                .filter("/mcp", filter.build())
                .start();
    }

    private static String token(StubZone zone, Object audience) {
        return TestServer.tokenWithAudienceClaim(issuer(zone), "read", audience, TestServer.KEY.getKeyID());
    }

    private static HttpResponse<String> request(TestServer server, String token) {
        return server.get("/mcp", "Authorization", "Bearer " + token);
    }

    private static HttpResponse<String> requestZoneB(TestServer server, String token) {
        return server.get("/mcp", "Authorization", "Bearer " + token, "X-Test-Zone", "b");
    }

    private static void assertUnavailable(HttpResponse<String> response) {
        assertThat(response.statusCode()).isEqualTo(503);
        assertThat(response.body()).isEqualTo("{\"error\":\"temporarily_unavailable\"}");
        assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
    }

    private static void assertInactive(HttpResponse<String> response) {
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).isEqualTo("{\"error\":\"invalid_token\"}");
        assertThat(response.headers().firstValue("WWW-Authenticate"))
                .hasValueSatisfying(
                        value -> assertThat(value)
                                .contains(
                                        "error=\"invalid_token\"",
                                        "resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource/mcp\""));
    }

    private record Failure(int status, String body) {}
}
