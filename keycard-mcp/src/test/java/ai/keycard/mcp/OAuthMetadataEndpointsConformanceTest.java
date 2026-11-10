package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;

import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** oauth-metadata-endpoints.md, Unit Tests table. */
class OAuthMetadataEndpointsConformanceTest {

    @Test
    @DisplayName("row 1: protected-resource metadata has resource from the request and authorization_servers [issuer]")
    void row1() throws Exception {
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), null)) {
            HttpResponse<String> response = server.get("/.well-known/oauth-protected-resource");

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.headers().firstValue("Content-Type").orElseThrow())
                    .startsWith("application/json");
            Map<String, Object> document = JSONObjectUtils.parse(response.body());
            assertThat(document)
                    .containsEntry("resource", server.url("").toString())
                    .containsEntry("authorization_servers", List.of("https://acme.keycard.cloud"));
        }
    }

    @Test
    @DisplayName("row 1: RFC 9728 path insertion describes the sub-path resource")
    void row1PathInsertion() throws Exception {
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), null)) {
            Map<String, Object> document = JSONObjectUtils.parse(
                    server.get("/.well-known/oauth-protected-resource/mcp").body());

            assertThat(document).containsEntry("resource", server.url("/mcp").toString());
        }
    }

    @Test
    @DisplayName("row 2: configured scopes_supported, resource_name and resource_documentation appear")
    void row2() throws Exception {
        TestServer server = new TestServer()
                .servlet(
                        "/.well-known/oauth-protected-resource/*",
                        ProtectedResourceMetadataServlet.builder(URI.create("https://acme.keycard.cloud"))
                                .scopesSupported("read", "write")
                                .resourceName("Ledger MCP")
                                .resourceDocumentation(URI.create("https://docs.example.com/ledger"))
                                .build())
                .start();
        try (server) {
            Map<String, Object> document = JSONObjectUtils.parse(
                    server.get("/.well-known/oauth-protected-resource").body());

            assertThat(document)
                    .containsEntry("scopes_supported", List.of("read", "write"))
                    .containsEntry("resource_name", "Ledger MCP")
                    .containsEntry("resource_documentation", "https://docs.example.com/ledger");
        }
    }

    @Test
    @DisplayName("row 3: MCP-Protocol-Version 2025-03-26 doesn't change the document")
    void row3() {
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), null)) {
            String plain = server.get("/.well-known/oauth-protected-resource").body();
            String versioned = server.get("/.well-known/oauth-protected-resource", "MCP-Protocol-Version", "2025-03-26")
                    .body();

            assertThat(versioned).isEqualTo(plain);
        }
    }

    @Test
    @DisplayName("row 4: the AS-metadata proxy returns the upstream document unmodified, query included")
    void row4() {
        try (StubZone zone = StubZone.start()) {
            String upstream = "{\"issuer\":\"" + zone.issuer() + "\",\"authorization_endpoint\":\"" + zone.issuer()
                    + "/oauth/authorize?resource=stale&keep=1\",\"x_custom\":[1,2]}";
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, upstream);

            try (TestServer server = metadataServer(zone.issuer(), null)) {
                HttpResponse<String> response = server.get("/.well-known/oauth-authorization-server");

                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.body()).isEqualTo(upstream);
                assertThat(response.headers().firstValue("Access-Control-Allow-Origin"))
                        .hasValue("*");
            }
        }
    }

    @Test
    @DisplayName("row 5: an upstream failure is 502 Bad Gateway")
    void row5() throws Exception {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 500, "{}");
            try (TestServer server = metadataServer(zone.issuer(), null)) {
                assertThat(server.get("/.well-known/oauth-authorization-server").statusCode())
                        .isEqualTo(502);
            }
        }
        URI closed;
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            closed = URI.create("http://127.0.0.1:" + socket.getLocalPort());
        }
        try (TestServer server = metadataServer(closed, null)) {
            assertThat(server.get("/.well-known/oauth-authorization-server").statusCode())
                    .isEqualTo(502);
        }
    }

    @Test
    @DisplayName("row 6: jwks.json serves the public key set when configured, 404 when not")
    void row6() throws Exception {
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), new JWKSet(TestServer.KEY))) {
            HttpResponse<String> response = server.get("/.well-known/jwks.json");

            assertThat(response.statusCode()).isEqualTo(200);
            JWKSet served = JWKSet.parse(response.body());
            assertThat(served.getKeyByKeyId(TestServer.KEY.getKeyID())).isNotNull();
            assertThat(served.getKeyByKeyId(TestServer.KEY.getKeyID()).isPrivate())
                    .isFalse();
            assertThat(response.body()).doesNotContain("\"d\"");
        }
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), null)) {
            assertThat(server.get("/.well-known/jwks.json").statusCode()).isEqualTo(404);
        }
    }

    @Test
    @DisplayName("CORS: documents allow any origin and answer the preflight")
    void cors() {
        try (TestServer server = metadataServer(URI.create("https://acme.keycard.cloud"), null)) {
            assertThat(server.get("/.well-known/oauth-protected-resource")
                            .headers()
                            .firstValue("Access-Control-Allow-Origin"))
                    .hasValue("*");
            HttpResponse<String> preflight = server.options("/.well-known/oauth-protected-resource");
            assertThat(preflight.statusCode()).isEqualTo(204);
            assertThat(preflight.headers().firstValue("Access-Control-Allow-Methods"))
                    .hasValue("GET, OPTIONS");
        }
    }

    private static TestServer metadataServer(URI issuer, JWKSet jwks) {
        TestServer server = new TestServer()
                .servlet(
                        "/.well-known/oauth-protected-resource/*",
                        ProtectedResourceMetadataServlet.builder(issuer).build())
                .servlet("/.well-known/oauth-authorization-server", AuthorizationServerMetadataServlet.of(issuer));
        if (jwks != null) {
            server.servlet("/.well-known/jwks.json", JwksServlet.of(jwks));
        }
        return server.start();
    }
}
