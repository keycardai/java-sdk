package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ResourceBindingConformanceTest {

    private static final String ORIGIN = "https://api.example.com";
    private static final String RESOURCE = ORIGIN + "/mcp";
    private static final String METADATA = "/.well-known/oauth-protected-resource";
    private static final String AS_METADATA = "/.well-known/oauth-authorization-server";
    private static final URI BASE = URI.create("https://keycard.example");
    private static final URI ZONE_A = URI.create("https://a.keycard.example");
    private static final URI ZONE_B = URI.create("https://b.keycard.example");
    private static final Map<String, String> ZONAL = Map.of("a", ORIGIN + "/a/mcp", "b", ORIGIN + "/b/mcp");

    @Test
    @DisplayName("bearer rows 1, 8, 12, 12a, 12c, 15 and integration 2: exact audience and request target")
    void exactResource() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(RequireBearerAuthFilter.builder(AuthProvider.builder(zone.issuer())
                        .resourceIdentifier(RESOURCE)
                        .build()))) {
            assertChallenge(server.get("/mcp"), 401, ORIGIN + METADATA + "/mcp");
            assertChallenge(
                    server.get("/mcp", "X-Forwarded-Host", "other.example", "X-Forwarded-Proto", "ftp"),
                    401,
                    ORIGIN + METADATA + "/mcp");
            assertChallenge(server.get("/tools"), 401, null);
            assertChallenge(server.get("/mcp?other=1"), 401, null);
            assertThat(get(server, "/mcp", zone.issuer(), RESOURCE).statusCode())
                    .isEqualTo(200);
            assertInvalid(get(server, "/mcp", zone.issuer(), ORIGIN + "/other"), ORIGIN + METADATA + "/mcp");
        }
    }

    @Test
    @DisplayName("bearer rows 1, 12b and gate rows 2, 2a: raw query and empty configured path")
    void configuredTargets() {
        try (StubZone zone = TestServer.zone();
                TestServer root = gate(zone.issuer(), ORIGIN);
                TestServer query = gate(zone.issuer(), RESOURCE + "?x=a%20b")) {
            assertChallenge(root.get("/"), 401, ORIGIN + METADATA);
            assertInvalid(get(root, "/", zone.issuer(), ORIGIN + "/"), ORIGIN + METADATA);
            assertChallenge(query.get("/mcp?x=a%20b"), 401, ORIGIN + METADATA + "/mcp?x=a%20b");
            assertChallenge(query.get("/mcp?x=a+b"), 401, null);
        }
    }

    @Test
    @DisplayName("bearer row 12d and metadata row 10: a mounted resource uses host-root metadata")
    void mounted() {
        AuthProvider provider = AuthProvider.builder(BASE)
                .resourceIdentifier(ORIGIN + "/app/mcp")
                .build();
        try (TestServer app = new TestServer()
                        .contextPath("/app")
                        .filter(
                                "/mcp",
                                RequireBearerAuthFilter.builder(provider).build())
                        .servlet("/mcp", new TestServer.Echo())
                        .start();
                TestServer root = new TestServer()
                        .servlet(
                                METADATA + "/*",
                                provider.protectedResourceMetadata().build())
                        .start()) {
            assertChallenge(app.get("/app/mcp"), 401, ORIGIN + METADATA + "/app/mcp");
            assertThat(root.get(METADATA + "/app/mcp").body()).contains(ORIGIN + "/app/mcp");
        }
    }

    @Test
    @DisplayName("bearer rows 8a, 8b, 8c, 8d and 8f: list matching without discovery")
    void audienceList() {
        try (StubZone zone = TestServer.zone();
                TestServer server = protect(RequireBearerAuthFilter.builder(AuthProvider.builder(zone.issuer())
                        .multiResource(true)
                        .audiences("resource-a", "resource-b")
                        .build()))) {
            assertThat(get(server, "/mcp", zone.issuer(), "resource-b").statusCode())
                    .isEqualTo(200);
            assertInvalid(get(server, "/mcp", zone.issuer(), "resource-c"), null);
            assertThat(get(server, "/mcp", zone.issuer(), List.of("resource-c", "resource-b"))
                            .statusCode())
                    .isEqualTo(200);
            assertInvalid(get(server, "/mcp", zone.issuer(), List.of("resource-c", "resource-d")), null);
        }
    }

    @Test
    @DisplayName("bearer rows 8g, 8h and gate rows 6, 7: unrestricted, URN and out-of-binding scope denial")
    void verifyWithoutDiscovery() {
        try (StubZone zone = TestServer.zone();
                TestServer unrestricted = protect(RequireBearerAuthFilter.builder(AuthProvider.builder(zone.issuer())
                        .allowAnyAudience(true)
                        .build()));
                TestServer urn = gate(zone.issuer(), "urn:example:service");
                TestServer web = gate(zone.issuer(), RESOURCE)) {
            assertThat(get(unrestricted, "/mcp", zone.issuer(), "another-resource")
                            .statusCode())
                    .isEqualTo(200);
            String token = TestServer.token(zone, "read");
            String damaged = token.substring(0, token.lastIndexOf('.') + 1) + "a".repeat(342);
            assertInvalid(unrestricted.get("/mcp", "Authorization", "Bearer " + damaged), null);
            assertChallenge(urn.get("/mcp"), 401, null);
            assertThat(get(urn, "/mcp", zone.issuer(), "urn:example:service").statusCode())
                    .isEqualTo(200);
            assertInvalid(get(urn, "/mcp", zone.issuer(), "urn:example:other"), null);
            HttpResponse<String> denied = web.get(
                    "/tools",
                    "Authorization",
                    "Bearer " + TestServer.token(zone, "not-read", RESOURCE, TestServer.KEY.getKeyID()));
            assertChallenge(denied, 403, null);
            assertThat(challenge(denied)).contains("error=\"insufficient_scope\"");
        }
    }

    @Test
    @DisplayName("bearer rows 8e, 13, 16b, 16d and 17a: mode conflicts fail at construction")
    void conflicts() {
        assertThatThrownBy(() -> AuthProvider.builder(BASE)
                        .multiResource(true)
                        .audiences()
                        .build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> AuthProvider.builder(BASE).multiResource(true).build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> AuthProvider.builder(BASE)
                        .resourceIdentifier(RESOURCE)
                        .allowAnyAudience(true)
                        .build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> zonal().resourceIdentifier(RESOURCE).build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> zonal().allowAnyAudience(true).build()).isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(
                        () -> RequireBearerAuthFilter.builder(zonal().build()).build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> zonal().multiResource(true).audiences(RESOURCE).build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> RequireBearerAuthFilter.builder(TokenVerifier.builder(BASE)
                                .audiences(RESOURCE + "/")
                                .build())
                        .resourceIdentifier(RESOURCE)
                        .build())
                .isInstanceOf(ConfigurationException.class);
        for (String identifier : List.of(
                "/mcp",
                "https:/mcp",
                "https://user@api.example.com/mcp",
                RESOURCE + "#fragment",
                "urn:",
                "ftp://api.example.com/mcp")) {
            assertThatThrownBy(() -> AuthProvider.builder(BASE)
                            .resourceIdentifier(identifier)
                            .build())
                    .isInstanceOf(ConfigurationException.class);
        }
    }

    @Test
    @DisplayName("bearer rows 16, 16a and 16c: the request selects the zone before verification")
    void distinctZones() {
        try (TestServer server =
                protect(RequireBearerAuthFilter.builder(zonal().build()).zoneResolver(request -> {
                    String path = request.getRequestURI();
                    return path.startsWith("/a/") ? ZONE_A : path.startsWith("/unknown/") ? BASE : null;
                }))) {
            String metadata = ORIGIN + METADATA + "/a/mcp";
            assertChallenge(server.get("/a/mcp"), 401, metadata);
            assertThat(get(server, "/a/mcp", ZONE_A, ZONAL.get("a")).statusCode())
                    .isEqualTo(200);
            assertInvalid(get(server, "/a/mcp", ZONE_A, ZONAL.get("b")), metadata);
            assertInvalid(get(server, "/a/mcp", ZONE_B, ZONAL.get("a")), metadata);
            assertChallenge(server.get("/unknown/mcp"), 401, null);
            assertChallenge(server.get("/mcp"), 401, null);
        }
    }

    @Test
    @DisplayName("bearer row 17: shared discovery precedes token-keyed verification for either zone")
    void sharedZones() {
        AuthProvider provider = zonal().resourceIdentifiersByZone(Map.of("a", RESOURCE, "b", RESOURCE))
                .multiResource(true)
                .audiences(RESOURCE)
                .build();
        try (TestServer server = protect(RequireBearerAuthFilter.builder(provider))) {
            assertChallenge(server.get("/mcp"), 401, ORIGIN + METADATA + "/mcp");
            for (URI issuer : List.of(ZONE_A, ZONE_B)) {
                assertThat(get(server, "/mcp", issuer, RESOURCE).statusCode()).isEqualTo(200);
            }
            assertInvalid(get(server, "/mcp", BASE, RESOURCE), ORIGIN + METADATA + "/mcp");
        }
    }

    private static AuthProvider.Builder zonal() {
        return AuthProvider.builder(BASE).resourceIdentifiersByZone(ZONAL).transport(request -> {
            URI uri = request.uri();
            String issuer = uri.getScheme() + "://" + uri.getAuthority();
            String body = uri.getPath().equals(AS_METADATA)
                    ? JSONObjectUtils.toJSONString(Map.of("issuer", issuer, "jwks_uri", issuer + "/jwks"))
                    : new JWKSet(TestServer.KEY.toPublicJWK()).toString();
            return new TransportResponse(200, Map.of(), body);
        });
    }

    private static TestServer protect(RequireBearerAuthFilter.Builder filter) {
        return new TestServer()
                .filter("/*", filter.build())
                .servlet("/*", new TestServer.Echo())
                .start();
    }

    private static TestServer gate(URI issuer, String identifier) {
        return new TestServer()
                .filter(
                        "/*",
                        RequireBearerAuthFilter.builder(AuthProvider.builder(issuer)
                                        .resourceIdentifier(identifier)
                                        .build())
                                .authenticationRequired(false)
                                .build())
                .filter("/*", RequireScopesFilter.of("read"))
                .servlet("/*", new TestServer.Echo())
                .start();
    }

    private static HttpResponse<String> get(TestServer server, String path, URI issuer, Object audience) {
        return server.get(
                path,
                "Authorization",
                "Bearer " + TestServer.tokenWithAudienceClaim(issuer, "read", audience, TestServer.KEY.getKeyID()));
    }

    private static void assertInvalid(HttpResponse<String> response, String metadata) {
        assertChallenge(response, 401, metadata);
        assertThat(challenge(response)).contains("error=\"invalid_token\"");
    }

    private static void assertChallenge(HttpResponse<String> response, int status, String metadata) {
        assertThat(response.statusCode()).isEqualTo(status);
        assertThat(challenge(response)).startsWith("Bearer");
        if (metadata == null) {
            assertThat(challenge(response)).doesNotContain("resource_metadata");
        } else {
            assertThat(challenge(response)).contains("resource_metadata=\"" + metadata + "\"");
        }
    }

    private static String challenge(HttpResponse<String> response) {
        return response.headers().firstValue("WWW-Authenticate").orElseThrow();
    }
}
