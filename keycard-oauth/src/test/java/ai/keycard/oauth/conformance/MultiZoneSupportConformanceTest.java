package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** multi-zone-support.md, Unit Tests table, plus the TokenVerifier surface it relies on. */
class MultiZoneSupportConformanceTest {

    private static RSAKey keyA;
    private static RSAKey keyB;

    @BeforeAll
    static void keys() throws Exception {
        keyA = new RSAKeyGenerator(2048).keyID("zone-a-key").generate();
        keyB = new RSAKeyGenerator(2048).keyID("zone-b-key").generate();
    }

    @Test
    @DisplayName("row 1: a credential built from two zones is multi-zone, each zone with its own pair")
    void row1() {
        URI a = URI.create("https://a.keycard.cloud");
        URI b = URI.create("https://b.keycard.cloud");
        ClientSecret credential =
                ClientSecret.perZone(Map.of(a, ClientSecret.of("a-client", "a"), b, ClientSecret.of("b-client", "b")));

        assertThat(credential.isMultiZone()).isTrue();
        assertThat(credential.clientId(a)).isEqualTo("a-client");
        assertThat(credential.clientId(b)).isEqualTo("b-client");
        assertThat(ClientSecret.of("x", "y").isMultiZone()).isFalse();
    }

    @Test
    @DisplayName("row 2: an inbound token for zone A verifies against A's issuer; B's keys are never used")
    void row2() {
        try (StubZone a = zone(keyA);
                StubZone b = zone(keyB)) {
            TokenVerifier verifier = verifier(a, b);

            AccessToken token = verifier.verifyTokenForZone(token(a, keyA), a.issuer());

            assertThat(token.issuer()).isEqualTo(a.issuer().toString());
            assertThat(b.requests()).isEmpty();
            assertThatThrownBy(() -> verifier.verifyTokenForZone(token(a, keyA), b.issuer()))
                    .isInstanceOf(InvalidTokenException.class);
            assertThat(b.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 3: an outbound exchange for zone A uses A's credential and targets A")
    void row3() {
        try (StubZone a = exchangeZone();
                StubZone b = exchangeZone()) {
            ClientSecret credential = ClientSecret.perZone(Map.of(
                    a.issuer(),
                    ClientSecret.of("a-client", "a-secret"),
                    b.issuer(),
                    ClientSecret.of("b-client", "b-secret")));
            TokenExchangeClient forB = TokenExchangeClient.builder(b.issuer())
                    .credential(credential)
                    .build();

            forB.forZone(a.issuer()).exchangeToken("subject", URI.create("https://api.example.com"));

            assertThat(a.requests(StubZone.TOKEN_PATH)).hasSize(1);
            assertThat(a.requests(StubZone.TOKEN_PATH).get(0).header("Authorization"))
                    .isEqualTo("Basic " + ClientSecretConformanceTest.basic("a-client", "a-secret"));
            assertThat(b.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 4: a zone the verifier doesn't trust fails closed")
    void row4() {
        try (StubZone a = zone(keyA)) {
            TokenVerifier verifier = verifier(a);

            assertThatThrownBy(() -> verifier.verifyTokenForZone(token(a, keyA), URI.create("https://unknown.example")))
                    .isInstanceOf(InvalidTokenException.class);
        }
    }

    @Test
    @DisplayName("row 5: an exchange for a zone with no configured credential fails closed, sending nothing")
    void row5() {
        try (StubZone a = exchangeZone();
                StubZone c = exchangeZone()) {
            TokenExchangeClient client = TokenExchangeClient.builder(a.issuer())
                    .credential(ClientSecret.perZone(Map.of(a.issuer(), ClientSecret.of("a-client", "a-secret"))))
                    .build()
                    .forZone(c.issuer());

            assertThatThrownBy(() -> client.exchangeToken("subject", URI.create("https://api.example.com")))
                    .isInstanceOf(ConfigurationException.class);
            assertThat(c.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 6: interleaved requests for zones A and B are each served from their own caches")
    void row6() {
        try (StubZone a = zone(keyA);
                StubZone b = zone(keyB)) {
            TokenVerifier verifier = verifier(a, b);

            for (int i = 0; i < 3; i++) {
                assertThat(verifier.verifyToken(token(a, keyA)).issuer())
                        .isEqualTo(a.issuer().toString());
                assertThat(verifier.verifyToken(token(b, keyB)).issuer())
                        .isEqualTo(b.issuer().toString());
            }

            assertThat(a.requests(StubZone.JWKS_PATH)).hasSize(1);
            assertThat(b.requests(StubZone.JWKS_PATH)).hasSize(1);
            assertThatThrownBy(() -> verifier.verifyToken(forged(a, keyB))).isInstanceOf(InvalidTokenException.class);
        }
    }

    @Test
    @DisplayName("TokenVerifier: identity accessors, audience enforcement and clearCache")
    void tokenVerifierSurface() {
        try (StubZone a = zone(keyA)) {
            TokenVerifier verifier = TokenVerifier.builder(a.issuer())
                    .audiences("https://api.example.com")
                    .build();

            AccessToken token = verifier.verifyToken(token(a, keyA));
            assertThat(token.subject()).isEqualTo("user-1");
            assertThat(token.subjectProfile()).isEqualTo("user");
            assertThat(token.keycardAppId()).isEqualTo("app-1");
            assertThat(token.clientId()).isEqualTo("client-1");
            assertThat(token.scopes()).containsExactly("read", "write");
            assertThat(token.audiences()).containsExactly("https://api.example.com");
            assertThat(token.toString()).doesNotContain(token.token());

            TokenVerifier otherAudience = TokenVerifier.builder(a.issuer())
                    .audiences("https://other.example")
                    .build();
            assertThatThrownBy(() -> otherAudience.verifyToken(token(a, keyA)))
                    .isInstanceOf(InvalidTokenException.class);

            // The audience mismatch is rejected before any key lookup, so only the first verifier
            // has fetched; clearCache makes it fetch again.
            assertThat(a.requests(StubZone.JWKS_PATH)).hasSize(1);
            verifier.clearCache();
            verifier.verifyToken(token(a, keyA));
            assertThat(a.requests(StubZone.JWKS_PATH)).hasSize(2);
            assertThatThrownBy(() -> TokenVerifier.builder()).isInstanceOf(ConfigurationException.class);
        }
    }

    private static TokenVerifier verifier(StubZone... zones) {
        URI[] issuers = new URI[zones.length];
        for (int i = 0; i < zones.length; i++) {
            issuers[i] = zones[i].issuer();
        }
        return TokenVerifier.builder(issuers)
                .audiences("https://api.example.com")
                .build();
    }

    private static StubZone zone(RSAKey key) {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(key.toPublicJWK()).toString());
        return zone;
    }

    private static StubZone exchangeZone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"xt\"}");
        return zone;
    }

    private static String token(StubZone zone, RSAKey key) {
        return sign(zone.issuer().toString(), key, key.getKeyID());
    }

    /** Claims zone {@code zone} as issuer but is signed with another zone's key under this zone's kid. */
    private static String forged(StubZone zone, RSAKey otherKey) {
        return sign(zone.issuer().toString(), otherKey, keyA.getKeyID());
    }

    private static String sign(String issuer, RSAKey key, String kid) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", "user-1");
        claims.put("sub_profile", "user");
        claims.put("keycard_app_id", "app-1");
        claims.put("client_id", "client-1");
        claims.put("aud", List.of("https://api.example.com"));
        claims.put("scope", "read write");
        claims.put("iat", now);
        claims.put("exp", now + 300);
        try {
            return JwtSigner.of(new SigningKey(key.toRSAPrivateKey(), kid, null))
                    .sign(claims);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
