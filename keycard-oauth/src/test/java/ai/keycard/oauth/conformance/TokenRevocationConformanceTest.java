package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.AuthorizationServerMetadata;
import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ClientAuthenticator;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenRevocationClient;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WebIdentity;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** token-revocation.md (spec-version 1), Unit Tests table. */
class TokenRevocationConformanceTest {

    // A nonstandard path makes derivation from the issuer fail.
    private static final String REVOKE_PATH = "/custom/revoke";
    private static final String CLIENT_ID = "test-client";

    @TempDir
    Path keyDirectory;

    @Test
    @DisplayName("row 1: a public client sends its id, token and default hint to the discovered endpoint")
    void row1() {
        try (StubZone zone = zone()) {
            String token = "opaque token+%&=";
            publicClient(zone).revokeToken(token);

            RecordedRequest request = onlyRevocationRequest(zone);
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.header("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
            assertThat(request.header("Authorization")).isNull();
            assertThat(request.formParams())
                    .containsExactlyInAnyOrderEntriesOf(Map.of(
                            "token", List.of(token),
                            "token_type_hint", List.of("refresh_token"),
                            "client_id", List.of(CLIENT_ID)));
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, REVOKE_PATH);
        }
    }

    @Test
    @DisplayName("row 2: a client id and secret use HTTP Basic")
    void row2() {
        try (StubZone zone = zone()) {
            TokenRevocationClient.builder(zone.issuer())
                    .clientId("client:id")
                    .clientSecret("test+secret")
                    .build()
                    .revokeToken("token");

            RecordedRequest request = onlyRevocationRequest(zone);
            assertThat(request.header("Authorization")).isEqualTo("Basic Y2xpZW50JTNBaWQ6dGVzdCUyQnNlY3JldA==");
            assertThat(request.formParams()).containsOnlyKeys("token", "token_type_hint");
        }
    }

    @Test
    @DisplayName("row 3: a private-key JWT credential sends the zone issuer as the sole audience")
    void row3() throws Exception {
        try (StubZone zone = zone()) {
            WebIdentity identity = WebIdentity.builder()
                    .clientId(CLIENT_ID)
                    .storageDir(keyDirectory)
                    .build();
            TokenRevocationClient.builder(URI.create(zone.issuer() + "/"))
                    .credential(new HeaderSigningCredential(identity, zone.issuer()))
                    .build()
                    .revokeToken("token");

            RecordedRequest request = onlyRevocationRequest(zone);
            assertThat(request.header("X-Test-Auth")).isEqualTo("present");
            Map<String, List<String>> form = request.formParams();
            assertThat(form).containsOnlyKeys("token", "token_type_hint", "client_assertion", "client_assertion_type");
            assertThat(form.get("client_assertion_type")).containsExactly(TokenTypes.JWT_BEARER_ASSERTION);
            assertThat(form.get("client_assertion")).hasSize(1);
            SignedJWT assertion = SignedJWT.parse(form.get("client_assertion").get(0));
            RSAKey key = (RSAKey) identity.publicJwks().getKeys().get(0);
            assertThat(assertion.verify(new RSASSAVerifier(key))).isTrue();
            assertThat(assertion.getJWTClaimsSet().getAudience())
                    .containsExactly(zone.issuer().toString());
        }
    }

    @Test
    @DisplayName("row 4: an explicit hint is sent unchanged")
    void row4() {
        try (StubZone zone = zone()) {
            publicClient(zone).revokeToken("token", "custom+token hint");

            assertThat(onlyRevocationRequest(zone).formParams().get("token_type_hint"))
                    .containsExactly("custom+token hint");
        }
    }

    @ParameterizedTest
    @CsvSource({"known,''", "unknown,''", "expired,''", "invalid,''", "already-revoked,''", "known,not JSON"})
    @DisplayName("row 5: HTTP 200 succeeds without parsing a response body")
    void row5(String token, String body) {
        try (StubZone zone = zone()) {
            zone.respond("POST", REVOKE_PATH, new StubResponse(200, Map.of(), body));

            publicClient(zone).revokeToken(token);

            assertThat(onlyRevocationRequest(zone).formParams().get("token")).containsExactly(token);
        }
    }

    @Test
    @DisplayName("row 6: missing revocation endpoint fails without a fallback request")
    void row6() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            assertThatThrownBy(() -> publicClient(zone).revokeToken("token"))
                    .isInstanceOfSatisfying(ConfigurationException.class, e -> {
                        assertThat(e).hasMessageContaining("revocation_endpoint");
                        assertThat(e.retryable()).isFalse();
                    });
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "401,invalid_client,false",
        "400,invalid_grant,true",
        "400,unsupported_token_type,true",
        "429,invalid_client,true",
        "503,invalid_client,true"
    })
    @DisplayName("row 7: OAuth errors preserve status, code and description and follow base retryability")
    void row7(int status, String code, boolean retryable) {
        try (StubZone zone = zone()) {
            zone.respond("POST", REVOKE_PATH, status, errorBody(code, "server explanation"));

            assertOAuthError(publicClient(zone), "token", status, code, "server explanation", retryable);
            onlyRevocationRequest(zone);
        }
    }

    @Test
    @DisplayName("row 8: a transport failure or 5xx is retryable without an automatic retry")
    void row8() {
        try (StubZone zone = zone()) {
            zone.respond("POST", REVOKE_PATH, new StubResponse(503, Map.of(), "unavailable"));
            TokenRevocationClient client = publicClient(zone);

            assertThatThrownBy(() -> client.revokeToken("token"))
                    .isInstanceOfSatisfying(HttpStatusException.class, e -> {
                        assertThat(e.status()).isEqualTo(503);
                        assertThat(e.retryable()).isTrue();
                    });
            onlyRevocationRequest(zone);

            AuthorizationServerMetadata metadata =
                    AuthorizationServerDiscovery.create().discover(zone.issuer());
            AtomicInteger attempts = new AtomicInteger();
            Duration timeout = Duration.ofSeconds(3);
            TokenRevocationClient offline = TokenRevocationClient.builder(metadata)
                    .clientId(CLIENT_ID)
                    .fetchTimeout(timeout)
                    .transport(request -> {
                        attempts.incrementAndGet();
                        assertThat(request.uri()).isEqualTo(zone.url(REVOKE_PATH));
                        assertThat(request.timeout()).isEqualTo(timeout);
                        throw new NetworkException("connection failed", new IOException("connection failed"));
                    })
                    .build();

            assertThatThrownBy(() -> offline.revokeToken("token"))
                    .isInstanceOfSatisfying(
                            NetworkException.class,
                            e -> assertThat(e.retryable()).isTrue());
            assertThat(attempts).hasValue(1);
        }
    }

    @Test
    @DisplayName("row 9: conflicting or unsupported authentication fails before any request")
    void row9() {
        try (StubZone zone = zone()) {
            Credential credential = ClientSecret.of(CLIENT_ID, "test-secret");
            assertThatThrownBy(() -> TokenRevocationClient.builder(zone.issuer())
                            .credential(credential)
                            .clientId(CLIENT_ID)
                            .build())
                    .isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> TokenRevocationClient.builder(zone.issuer())
                            .credential(credential)
                            .clientSecret("test-secret")
                            .build())
                    .isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> TokenRevocationClient.builder(zone.issuer())
                            .credential(context -> TokenExchangeRequest.builder(context.subjectToken())
                                    .build())
                            .build())
                    .isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> TokenRevocationClient.builder(zone.issuer())
                            .clientSecret("test-secret")
                            .build())
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 10: pre-discovered metadata bypasses discovery")
    void row10() {
        try (StubZone zone = zone()) {
            AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(
                    zone.issuer(),
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    zone.url(REVOKE_PATH),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    Map.of());

            TokenRevocationClient.builder(metadata).clientId(CLIENT_ID).build().revokeToken("token");

            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(REVOKE_PATH);
        }
    }

    @Test
    @DisplayName("row 11: a missing or empty token fails before any request")
    void row11() {
        try (StubZone zone = zone()) {
            TokenRevocationClient client = publicClient(zone);

            assertThatThrownBy(() -> client.revokeToken(""))
                    .isInstanceOfSatisfying(
                            ConfigurationException.class,
                            e -> assertThat(e.retryable()).isFalse());
            assertThatThrownBy(() -> client.revokeToken(null)).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"invalid_grant", "unsupported_token_type"})
    @DisplayName("row 12: invalid_grant and unsupported_token_type are retryable per base")
    void row12(String code) {
        try (StubZone zone = zone()) {
            zone.respond("POST", REVOKE_PATH, 400, errorBody(code, "denied"));

            assertOAuthError(publicClient(zone), "token", 400, code, "denied", true);
        }
    }

    @Test
    @DisplayName("row 13: HTTP 400 for an exchanged access token preserves unsupported_token_type")
    void row13() throws JOSEException {
        try (StubZone zone = zone()) {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(zone.issuer().toString())
                    .claim("sid", "session")
                    .claim("act", Map.of("sub", "actor"))
                    .build();
            assertUnsupportedToken(zone, jwt("at+jwt", claims), "exchanged access token");
        }
    }

    @Test
    @DisplayName("row 14: HTTP 400 for an access token without a session preserves unsupported_token_type")
    void row14() throws JOSEException {
        try (StubZone zone = zone()) {
            JWTClaimsSet claims =
                    new JWTClaimsSet.Builder().issuer(zone.issuer().toString()).build();
            assertUnsupportedToken(zone, jwt("at+jwt", claims), "access token has no sid");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"at+jwt", "vnd.kc.rt+jwt"})
    @DisplayName("row 15: HTTP 400 for a recognized token from another issuer preserves unsupported_token_type")
    void row15(String type) throws JOSEException {
        try (StubZone zone = zone()) {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer("https://other.example")
                    .claim("sid", "session")
                    .build();
            assertUnsupportedToken(zone, jwt(type, claims), "issuer does not match");
        }
    }

    @Test
    @DisplayName("workload identity sends its original assertion")
    void forwardsWorkloadAssertion() throws JOSEException {
        try (StubZone zone = zone()) {
            String assertion = jwt(
                    "JWT",
                    new JWTClaimsSet.Builder().audience("workload-audience").build());
            TokenRevocationClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.builder(() -> assertion)
                            .clientId(CLIENT_ID)
                            .build())
                    .build()
                    .revokeToken("token");

            Map<String, List<String>> form = onlyRevocationRequest(zone).formParams();
            assertThat(form.get("client_assertion")).containsExactly(assertion);
            assertThat(form.get("client_id")).containsExactly(CLIENT_ID);
        }
    }

    @Test
    @DisplayName("cached discovery honors Retry-After and reuses metadata once it succeeds")
    void pacesAndCachesDiscovery() {
        try (StubZone zone = zone()) {
            TestClock clock = TestClock.start();
            zone.respond("GET", StubZone.DISCOVERY_PATH, new StubResponse(503, Map.of("Retry-After", "5"), ""));
            TokenRevocationClient client = TokenRevocationClient.builder(zone.issuer())
                    .clock(clock)
                    .clientId(CLIENT_ID)
                    .build();

            assertThatThrownBy(() -> client.revokeToken("first")).isInstanceOf(HttpStatusException.class);
            serveRevocationMetadata(zone);
            clock.advance(Duration.ofMillis(4999));
            assertThatThrownBy(() -> client.revokeToken("second")).isInstanceOf(HttpStatusException.class);
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);

            clock.advance(Duration.ofMillis(1));
            client.revokeToken("third");
            client.revokeToken("fourth");
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, StubZone.DISCOVERY_PATH, REVOKE_PATH, REVOKE_PATH);
        }
    }

    @Test
    @DisplayName("discovery can pick up a newly advertised revocation endpoint after the negative TTL")
    void missingEndpointExpires() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            TestClock clock = TestClock.start();
            TokenRevocationClient client = TokenRevocationClient.builder(zone.issuer())
                    .clock(clock)
                    .negativeTtl(Duration.ofSeconds(5))
                    .clientId(CLIENT_ID)
                    .build();

            assertThatThrownBy(() -> client.revokeToken("token")).isInstanceOf(ConfigurationException.class);
            serveRevocationMetadata(zone);
            zone.respond("POST", REVOKE_PATH, new StubResponse(200, Map.of(), ""));
            clock.advance(Duration.ofMillis(4999));
            assertThatThrownBy(() -> client.revokeToken("token")).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);

            clock.advance(Duration.ofMillis(1));
            client.revokeToken("token");
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, StubZone.DISCOVERY_PATH, REVOKE_PATH);
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start();
        serveRevocationMetadata(zone);
        return zone.respond("POST", REVOKE_PATH, new StubResponse(200, Map.of(), ""));
    }

    private static void serveRevocationMetadata(StubZone zone) {
        AuthorizationServerDiscoveryConformanceTest.serve(
                zone,
                Map.of(
                        "issuer",
                        zone.issuer().toString(),
                        "revocation_endpoint",
                        zone.url(REVOKE_PATH).toString()));
    }

    private static TokenRevocationClient publicClient(StubZone zone) {
        return TokenRevocationClient.builder(zone.issuer()).clientId(CLIENT_ID).build();
    }

    private static RecordedRequest onlyRevocationRequest(StubZone zone) {
        List<RecordedRequest> requests = zone.requests(REVOKE_PATH);
        assertThat(requests).hasSize(1);
        return requests.get(0);
    }

    private static String errorBody(String code, String description) {
        return JSONObjectUtils.toJSONString(Map.of("error", code, "error_description", description));
    }

    private static void assertOAuthError(
            TokenRevocationClient client,
            String token,
            int status,
            String code,
            String description,
            boolean retryable) {
        assertThatThrownBy(() -> client.revokeToken(token)).isInstanceOfSatisfying(OAuthErrorException.class, e -> {
            assertThat(e.status()).isEqualTo(status);
            assertThat(e.error()).isEqualTo(code);
            assertThat(e.errorDescription()).isEqualTo(description);
            assertThat(e.retryable()).isEqualTo(retryable);
        });
    }

    private static void assertUnsupportedToken(StubZone zone, String token, String description) {
        zone.respond("POST", REVOKE_PATH, 400, errorBody("unsupported_token_type", description));
        assertOAuthError(publicClient(zone), token, 400, "unsupported_token_type", description, true);
        assertThat(onlyRevocationRequest(zone).formParams().get("token")).containsExactly(token);
    }

    private static String jwt(String type, JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(new JOSEObjectType(type))
                        .build(),
                claims);
        jwt.sign(new MACSigner(new byte[32]));
        return jwt.serialize();
    }

    private record HeaderSigningCredential(WebIdentity identity, URI expectedIssuer)
            implements Credential, ClientAuthenticator {

        @Override
        public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
            return identity.prepareTokenExchangeRequest(context);
        }

        @Override
        public ClientAuthentication authenticate(URI issuer, URI endpoint) {
            assertThat(issuer).isEqualTo(expectedIssuer);
            assertThat(endpoint).isEqualTo(expectedIssuer);
            return new ClientAuthentication(
                    Map.of("X-Test-Auth", "present"),
                    identity.authenticate(issuer, endpoint).formFields());
        }
    }
}
