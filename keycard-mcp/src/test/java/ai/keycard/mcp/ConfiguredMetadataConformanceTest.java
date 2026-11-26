package ai.keycard.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.TransportResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ConfiguredMetadataConformanceTest {

    private static final String ORIGIN = "https://api.example.com";
    private static final String RESOURCE = ORIGIN + "/mcp";
    private static final String METADATA = "/.well-known/oauth-protected-resource";
    private static final String AS_METADATA = "/.well-known/oauth-authorization-server";
    private static final URI BASE = URI.create("https://keycard.example");
    private static final Map<String, String> ZONAL = Map.of("a", ORIGIN + "/a/mcp", "b", ORIGIN + "/b/mcp");

    @Test
    @DisplayName("a serialized servlet retains its configured zone and resource document")
    void servletSerialization() throws Exception {
        var servlet = ProtectedResourceMetadataServlet.builder(BASE)
                .resourceIdentifiersByZone(ZONAL)
                .build();
        var bytes = new ByteArrayOutputStream();
        try (var output = new ObjectOutputStream(bytes)) {
            output.writeObject(servlet);
        }
        try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()));
                TestServer server = new TestServer()
                        .servlet(METADATA + "/*", (ProtectedResourceMetadataServlet) input.readObject())
                        .start()) {
            assertDocument(server.get(METADATA + "/a/mcp"), ZONAL.get("a"), "https://a.keycard.example");
        }
    }

    @Test
    @DisplayName("rows 1, 7 and 9: each resource publishes its configured identifier not the servlet origin")
    void exactDocuments() throws Exception {
        try (TestServer server = new TestServer()
                .servlet(METADATA, provider(ORIGIN).protectedResourceMetadata().build())
                .servlet(
                        METADATA + "/mcp",
                        provider(RESOURCE).protectedResourceMetadata().build())
                .start()) {
            assertDocument(server.get(METADATA), ORIGIN, BASE.toString());
            assertDocument(server.get(METADATA + "/mcp"), RESOURCE, BASE.toString());
        }
    }

    @Test
    @DisplayName("rows 4a, 4b, 9a and integration 2: discover and proxy only the configured zone issuers")
    void zonalDiscovery() throws Exception {
        List<URI> fetched = new CopyOnWriteArrayList<>();
        ProtectedResourceMetadataServlet metadata = ProtectedResourceMetadataServlet.builder(BASE)
                .resourceIdentifiersByZone(ZONAL)
                .build();
        try (TestServer server = new TestServer()
                .servlet(METADATA + "/*", metadata)
                .servlet(
                        AS_METADATA + "/*",
                        metadata.authorizationServerMetadata(
                                request -> {
                                    fetched.add(request.uri());
                                    return new TransportResponse(
                                            200,
                                            Map.of(),
                                            asDocument(request.uri().getScheme() + "://"
                                                    + request.uri().getAuthority()));
                                },
                                Duration.ofSeconds(1)))
                .start()) {
            for (String zone : List.of("a", "b")) {
                String issuer = "https://" + zone + ".keycard.example";
                assertDocument(server.get(METADATA + "/" + zone + "/mcp"), ZONAL.get(zone), issuer);
                HttpResponse<String> response = server.get(AS_METADATA + "/" + zone);
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(response.body()).isEqualTo(asDocument(issuer));
            }
            assertThat(server.get(AS_METADATA).statusCode()).isEqualTo(404);
            assertThat(server.get(AS_METADATA + "/unknown").statusCode()).isEqualTo(404);
            assertThat(fetched)
                    .containsExactly(
                            URI.create("https://a.keycard.example" + AS_METADATA),
                            URI.create("https://b.keycard.example" + AS_METADATA));
        }
    }

    @Test
    @DisplayName("row 9c: one shared document advertises every configured issuer")
    void sharedDocument() throws Exception {
        ProtectedResourceMetadataServlet metadata = ProtectedResourceMetadataServlet.builder(BASE)
                .resourceIdentifiersByZone(Map.of("a", RESOURCE, "b", RESOURCE))
                .multiResource(true)
                .build();
        try (TestServer server =
                new TestServer().servlet(METADATA + "/*", metadata).start()) {
            assertDocument(
                    server.get(METADATA + "/mcp"), RESOURCE, "https://a.keycard.example", "https://b.keycard.example");
        }
    }

    @Test
    @DisplayName("rows 8 and 8a: verifier-only modes leave AS metadata and JWKS available")
    void verifierOnly() {
        for (ProtectedResourceMetadataServlet metadata : List.of(
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifier("urn:example:service")
                        .build(),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .multiResource(true)
                        .build(),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .allowAnyAudience(true)
                        .build())) {
            try (TestServer server = new TestServer()
                    .servlet(METADATA + "/*", metadata)
                    .servlet(
                            AS_METADATA,
                            metadata.authorizationServerMetadata(
                                    request -> new TransportResponse(200, Map.of(), "{}"), Duration.ofSeconds(1)))
                    .servlet("/.well-known/jwks.json", JwksServlet.of(new JWKSet(TestServer.KEY.toPublicJWK())))
                    .start()) {
                assertThat(server.get(METADATA).statusCode()).isEqualTo(404);
                assertThat(server.get(AS_METADATA).statusCode()).isEqualTo(200);
                assertThat(server.get("/.well-known/jwks.json").statusCode()).isEqualTo(200);
            }
        }
    }

    @Test
    @DisplayName("rows 8b, 9b and 9d: conflicting standalone modes fail before routing")
    void invalidMetadataOptions() {
        List<ProtectedResourceMetadataServlet.Builder> invalid = List.of(
                ProtectedResourceMetadataServlet.builder(BASE)
                        .multiResource(true)
                        .allowAnyAudience(true),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifier(RESOURCE)
                        .resourceIdentifiersByZone(ZONAL),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifier(RESOURCE)
                        .multiResource(true),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifier(RESOURCE)
                        .allowAnyAudience(true),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifiersByZone(ZONAL)
                        .allowAnyAudience(true),
                ProtectedResourceMetadataServlet.builder().resourceIdentifiersByZone(ZONAL),
                ProtectedResourceMetadataServlet.builder(BASE)
                        .resourceIdentifiersByZone(ZONAL)
                        .multiResource(true));
        for (ProtectedResourceMetadataServlet.Builder builder : invalid) {
            assertThatThrownBy(builder::build).isInstanceOf(ConfigurationException.class);
        }
    }

    @Test
    @DisplayName("row 8c and bearer rows 7, 14: one legacy warning per configuration")
    void legacyWarning() throws Exception {
        List<String> warnings = new ArrayList<>();
        Logger logger = Logger.getLogger(ResourceBinding.class.getName());
        Handler capture = new Handler() {
            @Override
            public void publish(LogRecord record) {
                warnings.add(record.getMessage());
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        logger.addHandler(capture);
        try {
            var standalone = ProtectedResourceMetadataServlet.builder(BASE).build();
            var legacy = AuthProvider.builder(BASE).audiences(RESOURCE).build();
            var omitted = AuthProvider.builder(BASE).build();
            RequireBearerAuthFilter.builder(omitted).build();
            RequireBearerAuthFilter.builder(legacy).build();
            try (TestServer root = new TestServer()
                            .servlet(METADATA + "/*", standalone)
                            .start();
                    TestServer composed = new TestServer()
                            .servlet(
                                    METADATA + "/*",
                                    legacy.protectedResourceMetadata().build())
                            .start()) {
                assertDocument(root.get(METADATA + "/mcp"), root.url("/mcp").toString(), BASE.toString());
                assertDocument(
                        composed.get(METADATA + "/mcp"), composed.url("/mcp").toString(), BASE.toString());
                assertThat(warnings).hasSize(3).allMatch(warning -> warning.contains("resource_identifier"));
                provider(RESOURCE).protectedResourceMetadata().build();
                ProtectedResourceMetadataServlet.builder(BASE)
                        .multiResource(true)
                        .build();
                ProtectedResourceMetadataServlet.builder(BASE)
                        .allowAnyAudience(true)
                        .build();
                assertThat(warnings).hasSize(3);
            }
        } finally {
            logger.removeHandler(capture);
        }
    }

    @Test
    @DisplayName("rows 10 and 10a: mounted servlet requires explicit forwarding or root registration")
    void mountValidation() throws Exception {
        String path = METADATA + "/app/mcp";
        var metadata = provider(ORIGIN + "/app/mcp").protectedResourceMetadata();
        try (TestServer wrongMapping = new TestServer().eagerServlet("/wrong", metadata.build())) {
            assertThatThrownBy(wrongMapping::start).hasRootCauseInstanceOf(ConfigurationException.class);
        }
        try (TestServer invalid =
                new TestServer().contextPath("/app").eagerServlet(METADATA + "/*", metadata.build())) {
            assertThatThrownBy(invalid::start).hasRootCauseInstanceOf(ConfigurationException.class);
        }
        try (TestServer forwarded = new TestServer()
                .contextPath("/app")
                .eagerServlet(METADATA + "/*", metadata.metadataForwarded(true).build())
                .start()) {
            assertDocument(forwarded.get("/app" + path), ORIGIN + "/app/mcp", BASE.toString());
        }
    }

    private static AuthProvider provider(String identifier) {
        return AuthProvider.builder(BASE).resourceIdentifier(identifier).build();
    }

    private static void assertDocument(HttpResponse<String> response, String resource, String... issuers)
            throws Exception {
        assertThat(response.statusCode()).isEqualTo(200);
        var document = JSONObjectUtils.parse(response.body());
        assertThat(document.get("resource")).isEqualTo(resource);
        assertThat(JSONObjectUtils.getStringList(document, "authorization_servers"))
                .containsExactlyInAnyOrder(issuers);
    }

    private static String asDocument(String issuer) {
        return "{ \"issuer\" : \"" + issuer + "\", \"authorization_endpoint\": \"" + issuer
                + "/authorize?keep=true\" }";
    }
}
