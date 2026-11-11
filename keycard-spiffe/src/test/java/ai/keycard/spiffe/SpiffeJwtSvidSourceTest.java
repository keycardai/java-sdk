package ai.keycard.spiffe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.WorkloadIdentityConfigurationException;
import ai.keycard.oauth.WorkloadIdentityRuntimeException;
import ai.keycard.oauth.testing.StubZone;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.svid.jwtsvid.JwtSvidSource;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SpiffeJwtSvidSourceTest {

    private static final String AUDIENCE = "https://acme.keycard.cloud";
    private static final String ENGINE = "spiffe://bank.example/engine";

    @Test
    @DisplayName("fetches a JWT-SVID for the audience and returns its compact token")
    void fetchesForAudience() throws Exception {
        FakeSource fake = new FakeSource(ENGINE);
        SpiffeJwtSvidSource source =
                SpiffeJwtSvidSource.builder(AUDIENCE).jwtSvidSource(fake).build();

        String token = source.identityToken();

        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getSubject()).isEqualTo(ENGINE);
        assertThat(fake.calls).containsExactly("aud=" + AUDIENCE);
    }

    @Test
    @DisplayName("fetches for a configured SPIFFE ID when the workload holds several")
    void fetchesForSpiffeId() {
        FakeSource fake = new FakeSource(ENGINE);
        SpiffeJwtSvidSource.builder(AUDIENCE)
                .spiffeId(ENGINE)
                .jwtSvidSource(fake)
                .build()
                .identityToken();

        assertThat(fake.calls).containsExactly("id=" + ENGINE + " aud=" + AUDIENCE);
    }

    @Test
    @DisplayName("fetches fresh on every call; the credential never caches it")
    void freshEveryCall() {
        FakeSource fake = new FakeSource(ENGINE);
        SpiffeJwtSvidSource source =
                SpiffeJwtSvidSource.builder(AUDIENCE).jwtSvidSource(fake).build();

        source.identityToken();
        source.identityToken();

        assertThat(fake.calls).hasSize(2);
    }

    @Test
    @DisplayName("a Workload API failure is a retryable runtime error from the spiffe source")
    void workloadApiFailure() {
        FakeSource fake = new FakeSource(ENGINE);
        fake.failure = new JwtSvidException("no identity issued");
        SpiffeJwtSvidSource source =
                SpiffeJwtSvidSource.builder(AUDIENCE).jwtSvidSource(fake).build();

        assertThatThrownBy(source::identityToken).isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
            assertThat(e.source()).isEqualTo("spiffe");
            assertThat(e.retryable()).isTrue();
            assertThat(e.getCause()).isSameAs(fake.failure);
        });
    }

    @Test
    @DisplayName("a closed source refuses to fetch instead of opening a new Workload API connection")
    void closedSourceRefuses() {
        SpiffeJwtSvidSource unopened = SpiffeJwtSvidSource.builder(AUDIENCE)
                .socketPath("unix:///nonexistent/agent.sock")
                .build();
        unopened.close();
        assertThatThrownBy(unopened::identityToken)
                .isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
                    assertThat(e.retryable()).isFalse();
                    assertThat(e.getMessage()).contains("closed");
                });
    }

    @Test
    @DisplayName("an unchecked failure from the SVID source, such as a source closed elsewhere, is a typed error")
    void uncheckedFailureIsTyped() {
        FakeSource fake = new FakeSource(ENGINE);
        fake.crash = new IllegalStateException("JWT SVID source is closed");
        SpiffeJwtSvidSource source =
                SpiffeJwtSvidSource.builder(AUDIENCE).jwtSvidSource(fake).build();
        assertThatThrownBy(source::identityToken).isInstanceOfSatisfying(WorkloadIdentityRuntimeException.class, e -> {
            assertThat(e.retryable()).isFalse();
            assertThat(e.getCause()).isSameAs(fake.crash);
        });
    }

    @Test
    @DisplayName("a blank audience, bad SPIFFE ID or bad socket address is a configuration error")
    void configurationErrors() {
        assertThatThrownBy(() -> SpiffeJwtSvidSource.builder(" "))
                .isInstanceOfSatisfying(
                        WorkloadIdentityConfigurationException.class,
                        e -> assertThat(e.source()).isEqualTo("spiffe"));
        assertThatThrownBy(() -> SpiffeJwtSvidSource.builder(AUDIENCE).spiffeId("not a spiffe id"))
                .isInstanceOf(WorkloadIdentityConfigurationException.class);

        SpiffeJwtSvidSource badSocket = SpiffeJwtSvidSource.builder(AUDIENCE)
                .socketPath("ftp://nowhere")
                .build();
        assertThatThrownBy(badSocket::identityToken).isInstanceOf(WorkloadIdentityConfigurationException.class);
    }

    @Test
    @DisplayName("closing leaves an injected source open")
    void closeLeavesInjectedSource() {
        FakeSource fake = new FakeSource(ENGINE);
        SpiffeJwtSvidSource source =
                SpiffeJwtSvidSource.builder(AUDIENCE).jwtSvidSource(fake).build();

        source.close();
        source.identityToken();

        assertThat(fake.calls).hasSize(1);
    }

    @Test
    @DisplayName("BNY's flow: the SVID authenticates the engine and names it as actor on the exchange")
    void svidAsAssertionAndActor() {
        FakeSource fake = new FakeSource(ENGINE);
        try (StubZone zone = StubZone.start().serveDiscovery();
                SpiffeJwtSvidSource svids = SpiffeJwtSvidSource.builder(AUDIENCE)
                        .jwtSvidSource(fake)
                        .build()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"downstream\"}");

            TokenExchangeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.builder(svids)
                            .clientId("engine-credential")
                            .build())
                    .actor(svids)
                    .build()
                    .exchangeToken("user-access-token", URI.create("https://ledger.bank.example"));

            var form = zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            assertThat(form.get("client_assertion")).hasSize(1);
            assertThat(form.get("actor_token")).hasSize(1);
            assertThat(form.get("actor_token_type")).containsExactly(TokenTypes.JWT);
            assertThat(form.get("client_assertion_type")).containsExactly(TokenTypes.JWT_BEARER_ASSERTION);
            assertThat(form.get("client_id")).containsExactly("engine-credential");
            assertThat(form.get("subject_token")).containsExactly("user-access-token");
            assertThat(fake.calls).hasSize(2);
        }
    }

    /** Issues real ES256 JWT-SVIDs for one SPIFFE ID and records each fetch. */
    private static final class FakeSource implements JwtSvidSource {

        private final String spiffeId;
        private final ECKey key;
        private final List<String> calls = new ArrayList<>();
        private JwtSvidException failure;
        private RuntimeException crash;

        FakeSource(String spiffeId) {
            this.spiffeId = spiffeId;
            try {
                this.key = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public JwtSvid fetchJwtSvid(String audience, String... extraAudience) throws JwtSvidException {
            calls.add("aud=" + audience);
            return issue(audience);
        }

        @Override
        public JwtSvid fetchJwtSvid(SpiffeId subject, String audience, String... extraAudience)
                throws JwtSvidException {
            calls.add("id=" + subject + " aud=" + audience);
            return issue(audience);
        }

        @Override
        public List<JwtSvid> fetchJwtSvids(String audience, String... extraAudience) throws JwtSvidException {
            return List.of(fetchJwtSvid(audience, extraAudience));
        }

        @Override
        public List<JwtSvid> fetchJwtSvids(SpiffeId subject, String audience, String... extraAudience)
                throws JwtSvidException {
            return List.of(fetchJwtSvid(subject, audience, extraAudience));
        }

        private JwtSvid issue(String audience) throws JwtSvidException {
            if (failure != null) {
                throw failure;
            }
            if (crash != null) {
                throw crash;
            }
            try {
                SignedJWT jwt = new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256)
                                .keyID(key.getKeyID())
                                .type(JOSEObjectType.JWT)
                                .build(),
                        new JWTClaimsSet.Builder()
                                .subject(spiffeId)
                                .audience(audience)
                                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                                .build());
                jwt.sign(new ECDSASigner(key));
                return JwtSvid.parseInsecure(jwt.serialize(), Set.of(audience));
            } catch (JwtSvidException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
