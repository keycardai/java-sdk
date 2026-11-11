package ai.keycard.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Regression tests for the pre-release adversarial review of keycard-oauth's core. */
class HardeningTest {

    private static RSAKey key;

    @BeforeAll
    static void keys() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
    }

    @Test
    @DisplayName("a JSON null body is a typed error everywhere, never a NullPointerException")
    void jsonNullBodies() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, "null");
            assertThatThrownBy(
                            () -> AuthorizationServerDiscovery.builder().build().discover(zone.issuer()))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_METADATA));
        }
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("GET", StubZone.JWKS_PATH, 200, "null");
            assertThatThrownBy(() -> JwksKeyring.create().resolve(zone.issuer(), "k1"))
                    .isInstanceOf(JwksException.Fetch.class);
            zone.respond("GET", StubZone.USERINFO_PATH, 200, "null");
            assertThatThrownBy(
                            () -> UserInfoClient.builder(zone.issuer()).build().userInfo("at"))
                    .isInstanceOf(OAuthProtocolException.class);
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "null");
            assertThatThrownBy(() -> ClientCredentialsClient.builder(zone.issuer())
                            .credential(ClientSecret.of("id", "secret"))
                            .build()
                            .requestToken())
                    .isInstanceOf(OAuthProtocolException.class);
        }
    }

    @Test
    @DisplayName("one malformed key doesn't stop the good keys in the same set from resolving")
    void malformedKeySkipped() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "GET",
                    StubZone.JWKS_PATH,
                    200,
                    "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"bad\",\"n\":\"!!\",\"e\":\"AQAB\"},"
                            + key.toPublicJWK().toJSONString() + "]}");
            assertThat(JwksKeyring.create().resolve(zone.issuer(), "k1")).isNotNull();
        }
    }

    @Test
    @DisplayName("a duplicate kid on an encryption key doesn't hide the signing key")
    void duplicateKidPrefersSigningKey() throws Exception {
        RSAKey enc =
                new RSAKeyGenerator(2048).keyID("k1").keyUse(KeyUse.ENCRYPTION).generate();
        RSAKey sig =
                new RSAKeyGenerator(2048).keyID("k1").keyUse(KeyUse.SIGNATURE).generate();
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "GET",
                    StubZone.JWKS_PATH,
                    200,
                    "{\"keys\":[" + enc.toPublicJWK().toJSONString() + ","
                            + sig.toPublicJWK().toJSONString() + "]}");
            assertThat(JwksKeyring.create().resolve(zone.issuer(), "k1")).isEqualTo(sig.toRSAPublicKey());
        }
    }

    @Test
    @DisplayName("a missing token_endpoint doesn't stop the keyring sharing the cache from finding jwks_uri")
    void missingFieldDoesNotPoisonSharedCache() {
        try (StubZone zone = StubZone.start()) {
            zone.respond(
                    "GET",
                    StubZone.DISCOVERY_PATH,
                    200,
                    "{\"issuer\":\"" + zone.issuer() + "\",\"jwks_uri\":\"" + zone.url(StubZone.JWKS_PATH) + "\"}");
            zone.respond(
                    "GET",
                    StubZone.JWKS_PATH,
                    200,
                    "{\"keys\":[" + key.toPublicJWK().toJSONString() + "]}");
            AuthorizationServerMetadataCache shared = AuthorizationServerMetadataCache.create();
            assertThatThrownBy(() -> shared.tokenEndpoint(zone.issuer())).isInstanceOf(OAuthProtocolException.class);
            assertThat(JwksKeyring.builder().metadataCache(shared).build().resolve(zone.issuer(), "k1"))
                    .isNotNull();
        }
    }

    @Test
    @DisplayName("a discovery TTL under a minute builds: the default failure TTL shrinks to fit")
    void shortDiscoveryTtl() {
        assertThatCode(() -> TokenVerifier.builder(URI.create("https://zone.example"))
                        .discoveryTtl(Duration.ofSeconds(30))
                        .build())
                .doesNotThrowAnyException();
        assertThatCode(() -> JwksKeyring.builder()
                        .discoveryTtl(Duration.ofSeconds(30))
                        .build())
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("an aud array with a non-string member is rejected")
    void nonStringAudience() {
        Map<String, Object> claims = claims();
        claims.put("aud", List.of(1, "api"));
        assertThatThrownBy(() -> verifier((issuer, kid) -> publicKey()).verify(sign(claims)))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("duplicate audiences or algorithms in the builder are accepted")
    void duplicateBuilderArguments() {
        assertThatCode(() -> JwtVerifier.builder(URI.create("https://zone.example"))
                        .audiences("api", "api")
                        .algorithms("RS256", "RS256")
                        .keyring((issuer, kid) -> publicKey())
                        .build())
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a keyring that returns null or throws something untyped yields a typed error")
    void misbehavingKeyring() {
        String token = sign(claims());
        assertThatThrownBy(() -> verifier((issuer, kid) -> null).verify(token))
                .isInstanceOf(InvalidTokenException.class);
        assertThatThrownBy(() -> verifier((issuer, kid) -> {
                            throw new IllegalStateException("boom");
                        })
                        .verify(token))
                .isInstanceOf(JwksException.class);
    }

    @Test
    @DisplayName("signer keys are checked when the signer is built: P-384 and RSA-1024 are configuration errors")
    void signerKeyValidation() throws Exception {
        ECKey p384 = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_384)
                .keyID("ec")
                .generate();
        assertThatThrownBy(() -> JwtSigner.of(new SigningKey(p384.toECPrivateKey(), "ec", null)))
                .isInstanceOf(ConfigurationException.class);
        KeyPairGenerator small = KeyPairGenerator.getInstance("RSA");
        small.initialize(1024);
        assertThatThrownBy(() ->
                        JwtSigner.of(new SigningKey(small.generateKeyPair().getPrivate(), "small", null)))
                .isInstanceOf(ConfigurationException.class);
        KeyPairGenerator p256 = KeyPairGenerator.getInstance("EC");
        p256.initialize(new ECGenParameterSpec("secp256r1"));
        assertThat(JwtSigner.of(new SigningKey(p256.generateKeyPair().getPrivate(), "p256", null))
                        .algorithm())
                .isEqualTo("ES256");
    }

    @Test
    @DisplayName("a far-future exp reads as Instant.MAX instead of overflowing")
    void farFutureExpiry() {
        Map<String, Object> claims = claims();
        claims.put("exp", Long.MAX_VALUE);
        assertThat(new AccessToken("t", claims).expiresAt()).isEqualTo(Instant.MAX);
    }

    @Test
    @DisplayName("malformed registration and device responses are invalid_response, not raw exceptions")
    void malformedResponses() {
        try (StubZone zone = StubZone.start()) {
            zone.respond(
                    "GET",
                    StubZone.DISCOVERY_PATH,
                    200,
                    "{\"issuer\":\"" + zone.issuer() + "\",\"registration_endpoint\":\"" + zone.url("/register")
                            + "\"}");
            zone.respond("POST", "/register", 201, "{\"client_id\":\"c\",\"registration_client_uri\":\"not a uri\"}");
            assertThatThrownBy(() -> ClientRegistrationClient.builder(zone.issuer())
                            .build()
                            .register(ClientRegistrationRequest.builder().build()))
                    .isInstanceOf(OAuthProtocolException.class);
        }
        assertThatThrownBy(() -> DeviceAuthorizationClient.parse(
                        "{\"device_code\":\"d\",\"user_code\":\"u\",\"verification_uri\":\"https://z/d\","
                                + "\"expires_in\":9223372036854775807}",
                        TestClock.start().instant()))
                .isInstanceOf(OAuthProtocolException.class);
    }

    @Test
    @DisplayName("an interaction timeout is not retryable")
    void interactionTimeout() {
        assertThat(new InteractionTimeoutException("waited").retryable()).isFalse();
    }

    private static JwtVerifier verifier(VerificationKeyring keyring) {
        return JwtVerifier.builder(URI.create("https://zone.example"))
                .audiences("api")
                .keyring(keyring)
                .build();
    }

    private static Map<String, Object> claims() {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "https://zone.example");
        claims.put("sub", "user");
        claims.put("aud", "api");
        claims.put("client_id", "client");
        claims.put("iat", now);
        claims.put("exp", now + 300);
        return claims;
    }

    private static String sign(Map<String, Object> claims) {
        try {
            return JwtSigner.of(new SigningKey(key.toRSAPrivateKey(), "k1", null))
                    .sign(claims);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static java.security.PublicKey publicKey() {
        try {
            return key.toRSAPublicKey();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
