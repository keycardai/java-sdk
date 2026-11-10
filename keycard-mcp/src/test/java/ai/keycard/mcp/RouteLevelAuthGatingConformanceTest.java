package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.testing.StubZone;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** route-level-auth-gating.md, Unit Tests table. */
class RouteLevelAuthGatingConformanceTest {

    @Test
    @DisplayName("row 1: a caller holding every required scope reaches the handler")
    void row1() {
        try (StubZone zone = TestServer.zone();
                TestServer server = gated(zone, RequireScopesFilter.of("read", "write"))) {
            assertThat(server.get("/tools/admin", "Authorization", "Bearer " + TestServer.token(zone, "read write"))
                            .statusCode())
                    .isEqualTo(200);
        }
    }

    @Test
    @DisplayName("row 2: an anonymous caller on a gated route is 401 with a resource_metadata challenge")
    void row2() {
        try (TestServer server = new TestServer()
                .filter("/open/*", RequireScopesFilter.of("read"))
                .servlet("/open/*", new TestServer.Echo())
                .start()) {
            HttpResponse<String> response = server.get("/open/x");

            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("resource_metadata=");
        }
    }

    @Test
    @DisplayName("row 3: a caller missing a required scope is 403 insufficient_scope")
    void row3() {
        try (StubZone zone = TestServer.zone();
                TestServer server = gated(zone, RequireScopesFilter.of("admin"))) {
            HttpResponse<String> response =
                    server.get("/tools/admin", "Authorization", "Bearer " + TestServer.token(zone, "read write"));

            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(response.headers().firstValue("WWW-Authenticate").orElseThrow())
                    .contains("error=\"insufficient_scope\"");
        }
    }

    @Test
    @DisplayName("row 4: a gate on authentication alone lets an authenticated caller through")
    void row4() {
        try (StubZone zone = TestServer.zone();
                TestServer server = gated(zone, RequireScopesFilter.of())) {
            assertThat(server.get("/tools/admin", "Authorization", "Bearer " + TestServer.token(zone, ""))
                            .statusCode())
                    .isEqualTo(200);
        }
    }

    @Test
    @DisplayName("row 5: stacked gates require the union of their scopes")
    void row5() {
        try (StubZone zone = TestServer.zone();
                TestServer server = new TestServer()
                        .filter("/*", bearer(zone))
                        .filter("/tools/*", RequireScopesFilter.of("read"))
                        .filter("/tools/*", RequireScopesFilter.of("write"))
                        .servlet("/tools/*", new TestServer.Echo())
                        .start()) {
            assertThat(server.get("/tools/x", "Authorization", "Bearer " + TestServer.token(zone, "read write"))
                            .statusCode())
                    .isEqualTo(200);
            assertThat(server.get("/tools/x", "Authorization", "Bearer " + TestServer.token(zone, "read"))
                            .statusCode())
                    .isEqualTo(403);
        }
    }

    private static RequireBearerAuthFilter bearer(StubZone zone) {
        return RequireBearerAuthFilter.builder(TokenVerifier.builder(zone.issuer())
                        .audiences(TestServer.AUDIENCE)
                        .build())
                .build();
    }

    private static TestServer gated(StubZone zone, RequireScopesFilter gate) {
        return new TestServer()
                .filter("/*", bearer(zone))
                .filter("/tools/*", gate)
                .servlet("/tools/*", new TestServer.Echo())
                .start();
    }
}
