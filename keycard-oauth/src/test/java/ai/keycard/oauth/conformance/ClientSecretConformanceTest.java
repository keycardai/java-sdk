package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ClientCredentialsClient;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.testing.StubZone;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** client-secret.md (spec-version 2), Unit Tests table. */
class ClientSecretConformanceTest {

    private static final URI ACME = URI.create("https://acme.keycard.cloud");
    private static final URI BETA = URI.create("https://beta.keycard.cloud");
    private static final URI TOKEN = URI.create("https://acme.keycard.cloud/oauth/token");

    @Test
    @DisplayName("row 1: a single-zone credential sends Authorization: Basic base64(client_id:client_secret)")
    void row1() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"t\",\"token_type\":\"Bearer\"}");

            ClientCredentialsClient.builder(zone.issuer())
                    .credential(ClientSecret.of("my-client", "s3cret"))
                    .build()
                    .requestToken();

            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).header("Authorization"))
                    .isEqualTo("Basic " + basic("my-client", "s3cret"));
        }
    }

    @Test
    @DisplayName("row 2: an empty client_id or client_secret is a configuration error at construction")
    void row2() {
        assertThatThrownBy(() -> ClientSecret.of("", "s")).isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> ClientSecret.of("c", "")).isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 3: a multi-zone credential uses the configured zone's Basic header")
    void row3() {
        ClientSecret credential = multiZone();

        assertThat(credential.isMultiZone()).isTrue();
        assertThat(credential.authenticate(ACME, TOKEN).headers())
                .containsEntry("Authorization", "Basic " + basic("acme-client", "acme-secret"));
        assertThat(credential.authenticate(URI.create(BETA + "/"), TOKEN).headers())
                .containsEntry("Authorization", "Basic " + basic("beta-client", "beta-secret"));
        assertThat(credential.clientId(BETA)).isEqualTo("beta-client");
    }

    @Test
    @DisplayName("row 4: a multi-zone credential fails closed for an unconfigured zone, with no fallback")
    void row4() {
        ClientSecret credential = multiZone();
        URI other = URI.create("https://other.keycard.cloud");

        assertThatThrownBy(() -> credential.authenticate(other, TOKEN)).isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(
                        () -> credential.prepareTokenExchangeRequest(TokenExchangeContext.of("subject", null, other)))
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> credential.clientId(other)).isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 4: no request is sent for an unconfigured zone")
    void row4NoRequest() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            ClientCredentialsClient client = ClientCredentialsClient.builder(zone.issuer())
                    .credential(multiZone())
                    .build();

            assertThatThrownBy(client::requestToken).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 5: an empty multi-zone map is a configuration error at construction")
    void row5() {
        assertThatThrownBy(() -> ClientSecret.perZone(Map.of())).isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> ClientSecret.perZone(Map.of(ACME, multiZone())))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 6: the prepared token-exchange request has the access-token type and no client credentials")
    void row6() {
        URI resource = URI.create("https://api.example.com");
        TokenExchangeRequest request = ClientSecret.of("my-client", "s3cret")
                .prepareTokenExchangeRequest(TokenExchangeContext.of("subject-token", resource, ACME));

        assertThat(request.subjectToken()).isEqualTo("subject-token");
        assertThat(request.subjectTokenType()).isEqualTo(TokenTypes.ACCESS_TOKEN);
        assertThat(request.resource()).isEqualTo(resource);
        assertThat(request.clientAssertion()).isNull();
        assertThat(request.clientAssertionType()).isNull();
        assertThat(request.clientId()).isNull();
    }

    @Test
    @DisplayName("row 7: client authentication returns the zone's Basic header and no form fields")
    void row7() {
        ClientAuthentication single = ClientSecret.of("my-client", "s3cret").authenticate(ACME, TOKEN);
        ClientAuthentication zoned = multiZone().authenticate(ACME, TOKEN);

        assertThat(single.headers())
                .containsExactly(Map.entry("Authorization", "Basic " + basic("my-client", "s3cret")));
        assertThat(single.formFields()).isEmpty();
        assertThat(zoned.headers())
                .containsExactly(Map.entry("Authorization", "Basic " + basic("acme-client", "acme-secret")));
        assertThat(zoned.formFields()).isEmpty();
    }

    @Test
    @DisplayName("secrets never appear in toString")
    void noSecretsInToString() {
        assertThat(ClientSecret.of("my-client", "s3cret").toString())
                .contains("my-client")
                .doesNotContain("s3cret");
        assertThat(multiZone().toString()).doesNotContain("acme-secret").doesNotContain("beta-secret");
        assertThat(ClientSecret.of("my-client", "s3cret")
                        .authenticate(ACME, TOKEN)
                        .toString())
                .doesNotContain(basic("my-client", "s3cret"));
    }

    private static ClientSecret multiZone() {
        return ClientSecret.perZone(Map.of(
                ACME, ClientSecret.of("acme-client", "acme-secret"),
                BETA, ClientSecret.of("beta-client", "beta-secret")));
    }

    static String basic(String id, String secret) {
        return Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}
