package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientRegistrationClient;
import ai.keycard.oauth.ClientRegistrationRequest;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.RegisteredClient;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** dynamic-client-registration.md (spec-version 1), Unit Tests table. */
class DynamicClientRegistrationConformanceTest {

    private static final String REGISTRATION_PATH = "/oauth/register";

    @Test
    @DisplayName("row 1: named fields and additional metadata go in the JSON body, named fields winning")
    void row1() throws Exception {
        try (StubZone zone = zone()) {
            zone.respond("POST", REGISTRATION_PATH, 201, "{\"client_id\":\"c-1\"}");

            client(zone)
                    .register(ClientRegistrationRequest.builder()
                            .additionalMetadata(Map.of("client_name", "loses", "vendor_flag", true))
                            .clientName("Payments CLI")
                            .redirectUris(URI.create("http://127.0.0.1:8765/callback"))
                            .grantTypes("authorization_code", "refresh_token")
                            .tokenEndpointAuthMethod("none")
                            .scope("openid", "profile")
                            .build());

            var request = zone.requests(REGISTRATION_PATH).get(0);
            assertThat(request.header("Content-Type")).startsWith("application/json");
            Map<String, Object> body = JSONObjectUtils.parse(request.body());
            assertThat(body)
                    .containsEntry("client_name", "Payments CLI")
                    .containsEntry("vendor_flag", true)
                    .containsEntry("redirect_uris", List.of("http://127.0.0.1:8765/callback"))
                    .containsEntry("grant_types", List.of("authorization_code", "refresh_token"))
                    .containsEntry("token_endpoint_auth_method", "none")
                    .containsEntry("scope", "openid profile")
                    .doesNotContainKeys("response_types", "jwks_uri", "software_id");
        }
    }

    @Test
    @DisplayName("row 2: a 2xx response is parsed into the registered client")
    void row2() {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    REGISTRATION_PATH,
                    201,
                    "{\"client_id\":\"c-2\",\"client_secret\":\"s-2\",\"client_id_issued_at\":1700000000,"
                            + "\"client_secret_expires_at\":0,\"registration_access_token\":\"mgmt-token-9f2\","
                            + "\"registration_client_uri\":\"https://zone.example/register/c-2\",\"client_name\":\"x\"}");

            RegisteredClient registered =
                    client(zone).register(ClientRegistrationRequest.builder().build());

            assertThat(registered.clientId()).isEqualTo("c-2");
            assertThat(registered.clientSecret()).isEqualTo("s-2");
            assertThat(registered.clientIdIssuedAt()).isEqualTo(Instant.ofEpochSecond(1700000000));
            assertThat(registered.clientSecretExpiresAt()).isEqualTo(Instant.EPOCH);
            assertThat(registered.registrationAccessToken()).isEqualTo("mgmt-token-9f2");
            assertThat(registered.registrationClientUri()).isEqualTo(URI.create("https://zone.example/register/c-2"));
            assertThat(registered.raw()).containsEntry("client_name", "x");
            assertThat(registered.toString()).doesNotContain("s-2").doesNotContain("mgmt-token-9f2");
            assertThat(registered.toClientSecret().clientId(zone.issuer())).isEqualTo("c-2");
        }
    }

    @Test
    @DisplayName("row 3: a response without client_id is invalid_response")
    void row3() {
        try (StubZone zone = zone()) {
            zone.respond("POST", REGISTRATION_PATH, 201, "{\"client_secret\":\"s\"}");
            assertThatThrownBy(() -> client(zone)
                            .register(ClientRegistrationRequest.builder().build()))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE));
        }
    }

    @Test
    @DisplayName("row 4: an RFC 7591 error is a typed OAuth error with code and description")
    void row4() {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    REGISTRATION_PATH,
                    400,
                    "{\"error\":\"invalid_redirect_uri\",\"error_description\":\"not https\"}");
            assertThatThrownBy(() -> client(zone)
                            .register(ClientRegistrationRequest.builder().build()))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("invalid_redirect_uri");
                        assertThat(e.errorDescription()).isEqualTo("not https");
                        assertThat(e.retryable()).isFalse();
                    });
        }
    }

    @Test
    @DisplayName("an initial access token is sent as a Bearer credential")
    void initialAccessToken() {
        try (StubZone zone = zone()) {
            zone.respond("POST", REGISTRATION_PATH, 201, "{\"client_id\":\"c\"}");
            ClientRegistrationClient.builder(zone.issuer())
                    .initialAccessToken("iat-1")
                    .build()
                    .register(ClientRegistrationRequest.builder().build());
            assertThat(zone.requests(REGISTRATION_PATH).get(0).header("Authorization"))
                    .isEqualTo("Bearer iat-1");
        }
    }

    @Test
    @DisplayName("a zone without a registration endpoint is a configuration error")
    void noEndpoint() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            assertThatThrownBy(() -> client(zone)
                            .register(ClientRegistrationRequest.builder().build()))
                    .isInstanceOf(ConfigurationException.class);
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start();
        zone.respond(
                "GET",
                StubZone.DISCOVERY_PATH,
                200,
                "{\"issuer\":\"" + zone.issuer() + "\",\"token_endpoint\":\"" + zone.url(StubZone.TOKEN_PATH)
                        + "\",\"registration_endpoint\":\"" + zone.url(REGISTRATION_PATH) + "\"}");
        return zone;
    }

    private static ClientRegistrationClient client(StubZone zone) {
        return ClientRegistrationClient.builder(zone.issuer()).build();
    }
}
