package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.AuthorizationServerMetadata;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** authorization-server-discovery.md (spec-version 3), Unit Tests table and Errors table. */
class AuthorizationServerDiscoveryConformanceTest {

    private final AuthorizationServerDiscovery discovery = AuthorizationServerDiscovery.create();

    @Test
    @DisplayName("row 1: valid issuer, well-formed document returns metadata with endpoints populated")
    void row1() {
        try (StubZone zone = StubZone.start()) {
            serve(zone, document(zone));

            AuthorizationServerMetadata metadata = discovery.discover(zone.issuer());

            assertThat(metadata.issuer()).isEqualTo(zone.issuer());
            assertThat(metadata.tokenEndpoint()).isEqualTo(zone.url("/oauth/token"));
            assertThat(metadata.authorizationEndpoint()).isEqualTo(zone.url("/oauth/authorize"));
            assertThat(metadata.jwksUri()).isEqualTo(zone.url("/.well-known/jwks.json"));
            assertThat(metadata.registrationEndpoint()).isEqualTo(zone.url("/oauth/register"));
            assertThat(metadata.grantTypesSupported()).containsExactly("authorization_code", "client_credentials");
            assertThat(metadata.tokenEndpointAuthMethodsSupported())
                    .containsExactly("client_secret_basic", "private_key_jwt");
            assertThat(metadata.responseTypesSupported()).containsExactly("code");

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.DISCOVERY_PATH).get(0);
            assertThat(request.method()).isEqualTo("GET");
            assertThat(request.header("Accept")).isEqualTo("application/json");
        }
    }

    @Test
    @DisplayName("row 2: response issuer matches the request, ignoring a trailing slash")
    void row2() {
        try (StubZone zone = StubZone.start()) {
            Map<String, Object> doc = document(zone);
            doc.put("issuer", zone.issuer() + "/");
            serve(zone, doc);

            assertThat(discovery.discover(zone.issuer()).issuer()).isEqualTo(URI.create(zone.issuer() + "/"));
            assertThat(discovery.discover(zone.issuer() + "/")).isNotNull();
        }
    }

    @Test
    @DisplayName("row 3: response issuer does not match the request raises issuer_mismatch")
    void row3() {
        try (StubZone zone = StubZone.start()) {
            Map<String, Object> doc = document(zone);
            doc.put("issuer", "https://other.keycard.cloud");
            serve(zone, doc);

            assertThatThrownBy(() -> discovery.discover(zone.issuer()))
                    .isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                        assertThat(e.code()).isEqualTo(OAuthProtocolException.ISSUER_MISMATCH);
                        assertThat(e.retryable()).isFalse();
                    });
        }
    }

    @Test
    @DisplayName("row 4: non-2xx response raises an HTTP error")
    void row4() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 404, "{\"error\":\"not_found\"}");

            assertThatThrownBy(() -> discovery.discover(zone.issuer()))
                    .isInstanceOfSatisfying(HttpStatusException.class, e -> {
                        assertThat(e.status()).isEqualTo(404);
                        assertThat(e.body()).contains("not_found");
                    });
        }
    }

    @Test
    @DisplayName("row 5: malformed JSON or a missing issuer raises a typed protocol error")
    void row5() {
        try (StubZone zone = StubZone.start()) {
            for (String body : List.of("not json", "[]", "{\"token_endpoint\":\"https://x/t\"}", "{\"issuer\":7}")) {
                zone.respond("GET", StubZone.DISCOVERY_PATH, 200, body);

                assertThatThrownBy(() -> discovery.discover(zone.issuer()))
                        .as(body)
                        .isInstanceOfSatisfying(
                                OAuthProtocolException.class,
                                e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_METADATA));
            }
        }
    }

    @Test
    @DisplayName("row 5: a mistyped standard field raises a typed protocol error")
    void row5MistypedField() {
        try (StubZone zone = StubZone.start()) {
            for (Map.Entry<String, Object> field : Map.<String, Object>of(
                            "token_endpoint", 42, "jwks_uri", "relative/path", "grant_types_supported", List.of(1))
                    .entrySet()) {
                Map<String, Object> doc = document(zone);
                doc.put(field.getKey(), field.getValue());
                serve(zone, doc);

                assertThatThrownBy(() -> discovery.discover(zone.issuer()))
                        .as(field.getKey())
                        .isInstanceOfSatisfying(
                                OAuthProtocolException.class,
                                e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_METADATA));
            }
        }
    }

    @Test
    @DisplayName("row 6: unknown fields are preserved")
    void row6() {
        try (StubZone zone = StubZone.start()) {
            Map<String, Object> doc = document(zone);
            doc.put("revocation_endpoint", zone.url("/oauth/revoke").toString());
            doc.put("x_keycard_extension", Map.of("nested", true));
            serve(zone, doc);

            AuthorizationServerMetadata metadata = discovery.discover(zone.issuer());

            assertThat(metadata.get("revocation_endpoint"))
                    .isEqualTo(zone.url("/oauth/revoke").toString());
            assertThat(metadata.get("x_keycard_extension")).isEqualTo(Map.of("nested", true));
            assertThat(metadata.raw()).containsKeys("issuer", "token_endpoint", "x_keycard_extension");
        }
    }

    @Test
    @DisplayName("rows 7 and 9: userinfo, end_session and device_authorization endpoints are typed")
    void rows7And9() {
        try (StubZone zone = StubZone.start()) {
            Map<String, Object> doc = document(zone);
            doc.put("userinfo_endpoint", zone.url("/oauth/userinfo").toString());
            doc.put("end_session_endpoint", zone.url("/oauth/logout").toString());
            doc.put("device_authorization_endpoint", zone.url("/oauth/device").toString());
            serve(zone, doc);

            AuthorizationServerMetadata metadata = discovery.discover(zone.issuer());

            assertThat(metadata.userinfoEndpoint()).isEqualTo(zone.url("/oauth/userinfo"));
            assertThat(metadata.endSessionEndpoint()).isEqualTo(zone.url("/oauth/logout"));
            assertThat(metadata.deviceAuthorizationEndpoint()).isEqualTo(zone.url("/oauth/device"));
        }
    }

    @Test
    @DisplayName("rows 8 and 10: omitted optional endpoints are absent, with no error")
    void rows8And10() {
        try (StubZone zone = StubZone.start()) {
            serve(zone, Map.of("issuer", zone.issuer().toString()));

            AuthorizationServerMetadata metadata = discovery.discover(zone.issuer());

            assertThat(metadata.userinfoEndpoint()).isNull();
            assertThat(metadata.endSessionEndpoint()).isNull();
            assertThat(metadata.deviceAuthorizationEndpoint()).isNull();
            assertThat(metadata.tokenEndpoint()).isNull();
            assertThat(metadata.grantTypesSupported()).isEmpty();
        }
    }

    @Test
    @DisplayName("contract: the well-known segment goes between the host and the issuer path (RFC 8414 §3.1)")
    void pathInsertion() {
        try (StubZone zone = StubZone.start()) {
            URI issuer = zone.url("/zones/acme");
            serve(zone, StubZone.DISCOVERY_PATH + "/zones/acme", Map.of("issuer", issuer.toString()));

            assertThat(discovery.discover(issuer).issuer()).isEqualTo(issuer);
            assertThat(discovery.discover(URI.create(issuer + "/")).issuer()).isEqualTo(issuer);
        }
    }

    @Test
    @DisplayName("errors: empty or invalid issuer input is a configuration error, before any request")
    void invalidIssuer() {
        try (StubZone zone = StubZone.start()) {
            for (String issuer : List.of(
                    "",
                    "  ",
                    "not a url",
                    "acme.keycard.cloud",
                    "ftp://acme.keycard.cloud",
                    zone.issuer() + "?zone=a",
                    zone.issuer() + "#frag")) {
                assertThatThrownBy(() -> discovery.discover(issuer))
                        .as(issuer)
                        .isInstanceOfSatisfying(
                                ConfigurationException.class,
                                e -> assertThat(e.retryable()).isFalse());
            }
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("errors: a network failure raises a network error")
    void networkFailure() throws IOException {
        URI closed = closedPort();

        assertThatThrownBy(() -> discovery.discover(closed)).isInstanceOfSatisfying(NetworkException.class, e -> {
            assertThat(e.retryable()).isTrue();
            assertThat(e.getCause()).isInstanceOf(IOException.class);
        });
    }

    static Map<String, Object> document(StubZone zone) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", zone.issuer().toString());
        doc.put("token_endpoint", zone.url("/oauth/token").toString());
        doc.put("authorization_endpoint", zone.url("/oauth/authorize").toString());
        doc.put("jwks_uri", zone.url("/.well-known/jwks.json").toString());
        doc.put("registration_endpoint", zone.url("/oauth/register").toString());
        doc.put("grant_types_supported", List.of("authorization_code", "client_credentials"));
        doc.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "private_key_jwt"));
        doc.put("response_types_supported", List.of("code"));
        return doc;
    }

    static void serve(StubZone zone, Map<String, Object> doc) {
        serve(zone, StubZone.DISCOVERY_PATH, doc);
    }

    static void serve(StubZone zone, String path, Map<String, Object> doc) {
        zone.respond("GET", path, 200, JSONObjectUtils.toJSONString(doc));
    }

    static URI closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return URI.create("http://127.0.0.1:" + socket.getLocalPort());
        }
    }
}
