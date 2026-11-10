package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** impersonation.md, Unit Tests table. */
class ImpersonationConformanceTest {

    private static final URI RESOURCE = URI.create("https://api.example.com");

    @Test
    @DisplayName("row 1: a substitute-user token for the user, no actor token, the substitute-user type")
    void row1() throws Exception {
        try (StubZone zone = zone()) {
            TokenExchangeClient client = TokenExchangeClient.builder(zone.issuer())
                    .credential(ClientSecret.of("gw", "gw-secret"))
                    .actor(() -> "must.not.be.sent")
                    .build();

            assertThat(client.impersonate("user-\"42\"", RESOURCE, "read").accessToken())
                    .isEqualTo("it");

            Map<String, List<String>> form =
                    zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            assertThat(form)
                    .containsEntry("subject_token_type", List.of(TokenTypes.SUBSTITUTE_USER))
                    .containsEntry("grant_type", List.of(TokenTypes.TOKEN_EXCHANGE_GRANT))
                    .containsEntry("resource", List.of(RESOURCE.toString()))
                    .containsEntry("scope", List.of("read"))
                    .doesNotContainKeys("actor_token", "actor_token_type");

            String token = form.get("subject_token").get(0);
            assertThat(token).endsWith(".");
            String[] parts = token.split("\\.", -1);
            assertThat(parts).hasSize(3);
            assertThat(parts[2]).isEmpty();
            assertThat(JSONObjectUtils.parse(new Base64URL(parts[0]).decodeToString()))
                    .containsExactly(Map.entry("typ", "vnd.kc.su+jwt"), Map.entry("alg", "none"));
            assertThat(JSONObjectUtils.parse(new Base64URL(parts[1]).decodeToString()))
                    .containsExactly(Map.entry("sub", "user-\"42\""));
        }
    }

    @Test
    @DisplayName("rows 2 and 3: invalid_grant for an unknown user, unauthorized_client without permission")
    void rows2And3() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            TokenExchangeClient client = TokenExchangeClient.builder(zone.issuer())
                    .credential(ClientSecret.of("gw", "gw-secret"))
                    .build();
            for (String code : List.of("invalid_grant", "unauthorized_client")) {
                zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"" + code + "\"}");

                assertThatThrownBy(() -> client.impersonate("user-1", RESOURCE))
                        .isInstanceOfSatisfying(
                                OAuthErrorException.class,
                                e -> assertThat(e.error()).isEqualTo(code));
            }
        }
    }

    @Test
    @DisplayName("row 4: a missing resource is a client-side validation error")
    void row4() {
        try (StubZone zone = zone()) {
            TokenExchangeClient client = TokenExchangeClient.builder(zone.issuer())
                    .credential(ClientSecret.of("gw", "gw-secret"))
                    .build();

            assertThatThrownBy(() -> client.impersonate("user-1", null)).isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> client.impersonate("", RESOURCE)).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 5: with no scope, none is sent and the server's defaults apply")
    void row5() {
        try (StubZone zone = zone()) {
            TokenExchangeClient.builder(zone.issuer())
                    .credential(ClientSecret.of("gw", "gw-secret"))
                    .build()
                    .impersonate("user-1", RESOURCE);

            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams()).doesNotContainKey("scope");
        }
    }

    @Test
    @DisplayName("row 6: an assertion-based credential authenticates in the body, with no Basic header")
    void row6() {
        try (StubZone zone = zone()) {
            TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.of(() -> "svid.jwt"))
                    .build()
                    .impersonate("user-1", RESOURCE);

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("client_assertion", List.of("svid.jwt"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION))
                    .containsEntry("subject_token_type", List.of(TokenTypes.SUBSTITUTE_USER));
            assertThat(request.header("Authorization")).isNull();
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"it\",\"token_type\":\"Bearer\"}");
        return zone;
    }
}
