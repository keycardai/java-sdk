package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.JwksException;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.JwtVerifier;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.VerificationKeyring;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** jwt-signing-and-verification.md (spec-version 1), Unit Tests table. */
class JwtSigningAndVerificationConformanceTest {

    private static final URI ISSUER = URI.create("https://acme.keycard.cloud");
    private static RSAKey rsa;
    private static RSAKey other;

    private final TestClock clock = TestClock.start();
    private final AtomicInteger lookups = new AtomicInteger();

    @BeforeAll
    static void keys() throws Exception {
        rsa = new RSAKeyGenerator(2048).keyID("k1").generate();
        other = new RSAKeyGenerator(2048).keyID("k1").generate();
    }

    @Test
    @DisplayName("row 1: claims without iss get the keyring issuer; header has kid and alg RS256")
    void row1() throws Exception {
        String token = signer().sign(Map.of("sub", "user-1"));

        Map<String, Object> header = part(token, 0);
        assertThat(header).containsEntry("alg", "RS256").containsEntry("kid", "k1");
        assertThat(part(token, 1)).containsEntry("iss", ISSUER.toString()).containsEntry("sub", "user-1");
        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("row 2: an iss in the claims is preserved; temporal claims are signed verbatim")
    void row2() throws Exception {
        String token = signer().sign(Map.of("iss", "https://other.example", "exp", 12345, "iat", 12000));

        assertThat(part(token, 1))
                .containsEntry("iss", "https://other.example")
                .containsEntry("exp", 12345L)
                .containsEntry("iat", 12000L)
                .doesNotContainKey("nbf");
    }

    @Test
    @DisplayName("rows 3 and 4: a signed token round-trips through a verifier trusting its issuer")
    void rows3And4() {
        Map<String, Object> claims = verifier().verify(signer().sign(validClaims()));

        assertThat(claims).containsEntry("sub", "user-1").containsEntry("client_id", "app-1");
        assertThat(lookups).hasValue(1);
    }

    @Test
    @DisplayName("row 5: alg none is rejected before any key lookup")
    void row5() {
        String header = Base64URL.encode("{\"alg\":\"none\",\"kid\":\"k1\"}").toString();
        String payload =
                Base64URL.encode(JSONObjectUtils.toJSONString(validClaims())).toString();

        assertThatThrownBy(() -> verifier().verify(header + "." + payload + "."))
                .isInstanceOf(InvalidTokenException.class);
        assertThat(lookups).hasValue(0);
    }

    @Test
    @DisplayName("row 6: an alg outside the allowlist is rejected")
    void row6() throws Exception {
        JwtVerifier es256Only = JwtVerifier.builder(ISSUER)
                .algorithms("ES256")
                .keyring(keyring())
                .clock(clock)
                .build();

        assertThatThrownBy(() -> es256Only.verify(signer().sign(validClaims())))
                .isInstanceOf(InvalidTokenException.class);
        assertThat(lookups).hasValue(0);
    }

    @Test
    @DisplayName("row 7: an untrusted iss is rejected with no key lookup and no network I/O")
    void row7() {
        Map<String, Object> claims = validClaims();
        claims.put("iss", "https://evil.example");

        assertThatThrownBy(() -> verifier().verify(signer().sign(claims))).isInstanceOf(InvalidTokenException.class);
        assertThat(lookups).hasValue(0);
    }

    @Test
    @DisplayName("row 8: a missing exp, or any other required claim, is rejected")
    void row8() {
        for (String claim : List.of("exp", "sub", "aud", "iat", "client_id")) {
            Map<String, Object> claims = validClaims();
            claims.remove(claim);

            assertThatThrownBy(() -> verifier().verify(signer().sign(claims)))
                    .as(claim)
                    .isInstanceOf(InvalidTokenException.class);
        }
    }

    @Test
    @DisplayName("row 9: exp in the past is rejected")
    void row9() {
        Map<String, Object> claims = validClaims();
        claims.put("exp", now() - 1);

        assertThatThrownBy(() -> verifier().verify(signer().sign(claims))).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("row 10: nbf in the future is rejected")
    void row10() {
        Map<String, Object> claims = validClaims();
        claims.put("nbf", now() + 30);

        assertThatThrownBy(() -> verifier().verify(signer().sign(claims))).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("rows 11 and 12: with audiences configured, a missing or non-intersecting aud is rejected")
    void rows11And12() {
        JwtVerifier withAudience = JwtVerifier.builder(ISSUER)
                .audiences("https://api.example.com")
                .keyring(keyring())
                .clock(clock)
                .build();
        Map<String, Object> wrong = validClaims();
        wrong.put("aud", List.of("https://other.example.com"));

        assertThatThrownBy(() -> withAudience.verify(signer().sign(wrong))).isInstanceOf(InvalidTokenException.class);

        Map<String, Object> right = validClaims();
        right.put("aud", List.of("https://other.example.com", "https://api.example.com"));
        assertThat(withAudience.verify(signer().sign(right))).containsKey("aud");
    }

    @Test
    @DisplayName("row 13: a missing kid header is rejected")
    void row13() {
        String header = Base64URL.encode("{\"alg\":\"RS256\"}").toString();
        String[] signed = signer().sign(validClaims()).split("\\.");

        assertThatThrownBy(() -> verifier().verify(header + "." + signed[1] + "." + signed[2]))
                .isInstanceOf(InvalidTokenException.class);
        assertThat(lookups).hasValue(0);
    }

    @Test
    @DisplayName("row 14: a tampered signature or payload is rejected")
    void row14() {
        String[] parts = signer().sign(validClaims()).split("\\.");
        Map<String, Object> forged = validClaims();
        forged.put("sub", "admin");
        String swapped = parts[0] + "." + Base64URL.encode(JSONObjectUtils.toJSONString(forged)) + "." + parts[2];

        assertThatThrownBy(() -> verifier().verify(swapped)).isInstanceOf(InvalidTokenException.class);
        String otherKey = JwtSigner.of(signingKey(other)).sign(validClaims());
        assertThatThrownBy(() -> verifier().verify(otherKey)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    @DisplayName("row 15: an exp just past now is accepted with a wide enough clock skew")
    void row15() {
        Map<String, Object> claims = validClaims();
        claims.put("exp", now() - 20);
        JwtVerifier lenient = JwtVerifier.builder(ISSUER)
                .clockSkew(Duration.ofSeconds(30))
                .keyring(keyring())
                .clock(clock)
                .build();

        assertThat(lenient.verify(signer().sign(claims))).containsKey("exp");
    }

    @Test
    @DisplayName("row 16: one second past exp with the default skew is rejected; the default is zero")
    void row16() {
        Map<String, Object> claims = validClaims();
        claims.put("exp", now() - 1);

        assertThatThrownBy(() -> verifier().verify(signer().sign(claims))).isInstanceOf(InvalidTokenException.class);
        claims.put("exp", now());
        assertThat(verifier().verify(signer().sign(claims))).containsKey("exp");
    }

    @Test
    @DisplayName("errors: malformed tokens are invalid; an unknown kid is invalid; a JWKS outage is not")
    void errorCategories() {
        for (String token : List.of("", "a.b", "a.b.c.d", "!!!.###.$$$")) {
            assertThatThrownBy(() -> verifier().verify(token)).as(token).isInstanceOf(InvalidTokenException.class);
        }
        JwtVerifier missingKey = JwtVerifier.builder(ISSUER)
                .keyring((issuer, kid) -> {
                    throw new JwksException.KeyNotFound("no " + kid);
                })
                .clock(clock)
                .build();
        assertThatThrownBy(() -> missingKey.verify(signer().sign(validClaims())))
                .isInstanceOf(InvalidTokenException.class)
                .hasCauseInstanceOf(JwksException.KeyNotFound.class);

        JwtVerifier outage = JwtVerifier.builder(ISSUER)
                .keyring((issuer, kid) -> {
                    throw new JwksException.Fetch("down", null, true);
                })
                .clock(clock)
                .build();
        assertThatThrownBy(() -> outage.verify(signer().sign(validClaims())))
                .isInstanceOfSatisfying(
                        JwksException.Fetch.class,
                        e -> assertThat(e.retryable()).isTrue());
    }

    @Test
    @DisplayName("construction: no trusted issuer, or an unimplemented algorithm, is a configuration error")
    void construction() {
        assertThatThrownBy(() -> JwtVerifier.builder()).isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> JwtVerifier.builder(ISSUER).algorithms("HS256"))
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> JwtVerifier.builder(ISSUER).algorithms("none"))
                .isInstanceOf(ConfigurationException.class);
    }

    private JwtSigner signer() {
        return JwtSigner.of(signingKey(rsa));
    }

    private static SigningKey signingKey(RSAKey key) {
        try {
            return new SigningKey(key.toRSAPrivateKey(), key.getKeyID(), ISSUER);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private VerificationKeyring keyring() {
        return (issuer, kid) -> {
            lookups.incrementAndGet();
            try {
                return rsa.toRSAPublicKey();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
    }

    private JwtVerifier verifier() {
        return JwtVerifier.builder(ISSUER).keyring(keyring()).clock(clock).build();
    }

    private Map<String, Object> validClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER.toString());
        claims.put("sub", "user-1");
        claims.put("aud", "https://api.example.com");
        claims.put("client_id", "app-1");
        claims.put("iat", now() - 10);
        claims.put("exp", now() + 300);
        return claims;
    }

    private long now() {
        return clock.instant().getEpochSecond();
    }

    private static Map<String, Object> part(String token, int index) throws Exception {
        return JSONObjectUtils.parse(new Base64URL(token.split("\\.")[index]).decodeToString());
    }
}
