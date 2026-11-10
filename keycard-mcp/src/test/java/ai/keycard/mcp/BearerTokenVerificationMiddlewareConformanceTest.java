package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.testing.StubZone;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** bearer-token-verification-middleware.md (spec-version 3), Unit Tests table. */
class BearerTokenVerificationMiddlewareConformanceTest {

    @Test
    @DisplayName("row 1: no Authorization header is 401 with a resource_metadata challenge")
    void row1() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            HttpResponse<String> response = server.get("/mcp");

            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate"))
                    .hasValue(
                            "Bearer resource_metadata=\"" + server.url("/.well-known/oauth-protected-resource") + "\"");
        }
    }

    @Test
    @DisplayName("row 2: a header that is not two parts is 400")
    void row2() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            for (String header : List.of("Bearer", "Bearer a b", "garbage")) {
                assertThat(server.get("/mcp", "Authorization", header).statusCode())
                        .as(header)
                        .isEqualTo(400);
            }
        }
    }

    @Test
    @DisplayName("row 3: a non-bearer scheme is 401 invalid_token")
    void row3() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            HttpResponse<String> response = server.get("/mcp", "Authorization", "Basic dXNlcjpwYXNz");

            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("error=\"invalid_token\"")
                    .contains("resource_metadata=");
        }
    }

    @Test
    @DisplayName("row 4: a valid token proceeds with the auth context populated")
    void row4() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            HttpResponse<String> response =
                    server.get("/mcp", "Authorization", "bearer " + TestServer.token(zone, "read write"));

            assertThat(response.statusCode()).isEqualTo(200);
            String[] fields = response.body().split("\\|");
            assertThat(fields[0]).isEqualTo("user-1");
            assertThat(fields[1]).isEqualTo("user");
            assertThat(fields[2]).isEqualTo("client-1");
            assertThat(fields[3]).isEqualTo("app-1");
            assertThat(fields[4]).isEqualTo("read write");
            assertThat(fields[5]).isEqualTo(TestServer.AUDIENCE);
            assertThat(Long.parseLong(fields[6])).isPositive();
        }
    }

    @Test
    @DisplayName("row 5: an invalid, expired or wrong-issuer token is 401 invalid_token")
    void row5() {
        try (StubZone zone = TestServer.zone();
                StubZone other = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            for (String token : List.of("not.a.jwt", TestServer.token(other, "read"))) {
                HttpResponse<String> response = server.get("/mcp", "Authorization", "Bearer " + token);

                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                        .contains("error=\"invalid_token\"");
            }
        }
    }

    @Test
    @DisplayName("row 6: a valid token missing a required scope is 403 insufficient_scope")
    void row6() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[] {"write"})) {
            HttpResponse<String> response =
                    server.get("/mcp", "Authorization", "Bearer " + TestServer.token(zone, "read"));

            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("error=\"insufficient_scope\"");
        }
    }

    @Test
    @DisplayName(
            "rows 7 and 8: no audience warns once and accepts any resource; an audience doesn't warn and rejects others")
    void rows7And8() {
        List<LogRecord> warnings = new ArrayList<>();
        Logger logger = Logger.getLogger(TokenVerifier.class.getName());
        Handler capture = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    warnings.add(record);
                }
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        logger.addHandler(capture);
        try (StubZone zone = TestServer.zone()) {
            TokenVerifier open = TokenVerifier.builder(zone.issuer()).build();
            assertThat(warnings).hasSize(1);
            assertThat(warnings.get(0).getMessage()).contains("audiences(");

            String otherResource = TestServer.token(zone, "read", "https://other.example", TestServer.KEY.getKeyID());
            try (TestServer server = new TestServer()
                    .filter("/mcp", RequireBearerAuthFilter.builder(open).build())
                    .servlet("/mcp", new TestServer.Echo())
                    .start()) {
                assertThat(server.get("/mcp", "Authorization", "Bearer " + otherResource)
                                .statusCode())
                        .isEqualTo(200);
            }
            assertThat(warnings).hasSize(1);

            TokenVerifier pinned = TokenVerifier.builder(zone.issuer())
                    .audiences(TestServer.AUDIENCE)
                    .build();
            assertThat(warnings).hasSize(1);
            try (TestServer server = new TestServer()
                    .filter("/mcp", RequireBearerAuthFilter.builder(pinned).build())
                    .servlet("/mcp", new TestServer.Echo())
                    .start()) {
                HttpResponse<String> response = server.get("/mcp", "Authorization", "Bearer " + otherResource);
                assertThat(response.statusCode()).isEqualTo(401);
                assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                        .contains("error=\"invalid_token\"");
            }
        } finally {
            logger.removeHandler(capture);
        }
    }

    @Test
    @DisplayName("row 9: a JWKS fetch failure is 503 temporarily_unavailable with no challenge")
    void row9() {
        try (StubZone zone = StubZone.start().serveDiscovery();
                TestServer server = protect(zone, new String[0])) {
            zone.respond("GET", StubZone.JWKS_PATH, 500, "{}");

            HttpResponse<String> response =
                    server.get("/mcp", "Authorization", "Bearer " + TestServer.token(zone, "read"));

            assertThat(response.statusCode()).isEqualTo(503);
            assertThat(response.body()).isEqualTo("{\"error\":\"temporarily_unavailable\"}");
            assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
        }
    }

    @Test
    @DisplayName("row 10: a discovery failure is 503 temporarily_unavailable with no challenge")
    void row10() {
        try (StubZone zone = StubZone.start();
                TestServer server = protect(zone, new String[0])) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 503, "{}");

            HttpResponse<String> response =
                    server.get("/mcp", "Authorization", "Bearer " + TestServer.token(zone, "read"));

            assertThat(response.statusCode()).isEqualTo(503);
            assertThat(response.headers().firstValue("WWW-Authenticate")).isEmpty();
        }
    }

    @Test
    @DisplayName("row 11: a kid absent from a JWKS that loaded is 401 invalid_token")
    void row11() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            String unknownKid = TestServer.token(zone, "read", TestServer.AUDIENCE, "rotated-away");

            HttpResponse<String> response = server.get("/mcp", "Authorization", "Bearer " + unknownKid);

            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("error=\"invalid_token\"");
        }
    }

    @Test
    @DisplayName("multi-zone: a request whose zone can't be resolved is rejected")
    void unresolvedZone() {
        try (StubZone zone = TestServer.zone();
                TestServer server = new TestServer()
                        .filter(
                                "/mcp",
                                RequireBearerAuthFilter.builder(verifier(zone))
                                        .zoneResolver(request -> null)
                                        .build())
                        .servlet("/mcp", new TestServer.Echo())
                        .start()) {
            HttpResponse<String> response =
                    server.get("/mcp", "Authorization", "Bearer " + TestServer.token(zone, "read"));

            assertThat(response.statusCode()).isEqualTo(401);
        }
    }

    @Test
    @DisplayName("the challenge URL follows X-Forwarded-Proto and Host")
    void forwardedOrigin() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(zone, new String[0])) {
            HttpResponse<String> response = server.get("/mcp", "X-Forwarded-Proto", "https");

            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("resource_metadata=\"https://127.0.0.1:");
        }
    }

    private static TokenVerifier verifier(StubZone zone) {
        return TokenVerifier.builder(zone.issuer())
                .audiences(TestServer.AUDIENCE)
                .build();
    }

    private static TestServer protect(StubZone zone, String[] scopes) {
        return new TestServer()
                .filter(
                        "/mcp",
                        RequireBearerAuthFilter.builder(verifier(zone))
                                .requiredScopes(scopes)
                                .build())
                .servlet("/mcp", new TestServer.Echo())
                .start();
    }
}
