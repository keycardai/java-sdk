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
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenIntrospection;
import ai.keycard.oauth.TokenIntrospectionClient;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.TransportRequest;
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
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** token-introspection.md (spec-version 1), Unit Tests table. */
class TokenIntrospectionConformanceTest {

    // A nonstandard path makes derivation from the issuer fail.
    private static final String INTROSPECT_PATH = "/custom/introspect";
    private static final URI ISSUER = URI.create("https://zone.example");
    private static final URI INTROSPECTION_ENDPOINT = ISSUER.resolve(INTROSPECT_PATH);
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";

    @TempDir
    Path keyDirectory;

    @Test
    @DisplayName("row 1: client-secret credential sends form POST with token and HTTP Basic auth")
    void row1() {
        try (StubZone zone = zone()) {
            String token = "opaque token+%&=";
            TokenIntrospectionClient client = builder(zone)
                    .credential(ClientSecret.of("client:id", "test+secret"))
                    .build();

            TokenIntrospection result = client.introspectToken(token);

            assertThat(result.active()).isTrue();
            RecordedRequest request = onlyIntrospectionRequest(zone);
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.header("Content-Type")).isEqualTo("application/x-www-form-urlencoded");
            assertThat(request.header("Accept")).isEqualTo("application/json");
            assertThat(request.header("Authorization")).isEqualTo("Basic Y2xpZW50JTNBaWQ6dGVzdCUyQnNlY3JldA==");
            assertThat(request.formParams()).containsExactlyInAnyOrderEntriesOf(Map.of("token", List.of(token)));
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, INTROSPECT_PATH);
        }
    }

    @Test
    @DisplayName("row 2: private-key JWT credential sends headers and fields with zone issuer as sole audience")
    void row2() throws Exception {
        try (StubZone zone = zone()) {
            WebIdentity identity = WebIdentity.builder()
                    .clientId(CLIENT_ID)
                    .storageDir(keyDirectory)
                    .build();
            TokenIntrospectionClient.builder(URI.create(ISSUER + "/"))
                    .transport(transport(zone))
                    .credential(new HeaderSigningCredential(identity))
                    .build()
                    .introspectToken("token");

            RecordedRequest request = onlyIntrospectionRequest(zone);
            assertThat(request.header("X-Test-Auth")).isEqualTo("present");
            Map<String, List<String>> form = request.formParams();
            assertThat(form).containsOnlyKeys("token", "client_assertion", "client_assertion_type");
            assertThat(form.get("client_assertion_type")).containsExactly(TokenTypes.JWT_BEARER_ASSERTION);
            assertThat(form.get("client_assertion")).hasSize(1);
            SignedJWT assertion = SignedJWT.parse(form.get("client_assertion").get(0));
            RSAKey key = (RSAKey) identity.publicJwks().getKeys().get(0);
            assertThat(assertion.verify(new RSASSAVerifier(key))).isTrue();
            assertThat(assertion.getJWTClaimsSet().getAudience()).containsExactly(ISSUER.toString());
        }
    }

    @Test
    @DisplayName("row 3: active access-token response with all fields populates typed fields and scope list")
    void row3() {
        try (StubZone zone = zone()) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("active", true);
            body.put("token_type", "Bearer");
            body.put("iss", ISSUER.toString());
            body.put("sub", "user-123");
            body.put("client_id", CLIENT_ID);
            body.put("aud", List.of("https://api.example.com", "https://secondary.example.com"));
            body.put("scope", "read write  admin");
            body.put("sid", "session-1");
            body.put("jti", "token-id-1");
            body.put("iat", 1700000000L);
            body.put("exp", 1700003600L);
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(body));

            TokenIntrospection result = client(zone).introspectToken("access-token");

            assertThat(result.active()).isTrue();
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.iss()).isEqualTo(ISSUER.toString());
            assertThat(result.sub()).isEqualTo("user-123");
            assertThat(result.clientId()).isEqualTo(CLIENT_ID);
            assertThat(result.aud()).containsExactly("https://api.example.com", "https://secondary.example.com");
            assertThat(result.scope()).containsExactly("read", "write", "admin");
            assertThat(result.sid()).isEqualTo("session-1");
            assertThat(result.jti()).isEqualTo("token-id-1");
            assertThat(result.iat()).isEqualTo(Instant.ofEpochSecond(1700000000L));
            assertThat(result.exp()).isEqualTo(Instant.ofEpochSecond(1700003600L));
        }
    }

    @Test
    @DisplayName("row 4: response with only active false returns inactive result with no error")
    void row4() {
        try (StubZone zone = zone()) {
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(Map.of("active", false)));

            TokenIntrospection result = client(zone).introspectToken("inactive-token");

            assertThat(result.active()).isFalse();
            assertThat(result.tokenType()).isNull();
            assertThat(result.iss()).isNull();
            assertThat(result.sub()).isNull();
            assertThat(result.clientId()).isNull();
            assertThat(result.aud()).isEmpty();
            assertThat(result.scope()).isEmpty();
            assertThat(result.sid()).isNull();
            assertThat(result.jti()).isNull();
            assertThat(result.iat()).isNull();
            assertThat(result.exp()).isNull();
            assertThat(result.raw()).containsExactlyEntriesOf(Map.of("active", false));
        }
    }

    @Test
    @DisplayName("inactive response ignores extra and mistyped fields and returns only active false")
    void inactiveResponseDropsExtraAndMistypedFields() {
        try (StubZone zone = zone()) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("active", false);
            body.put("exp", "x");
            body.put("sub", "user-123");
            body.put("scope", 123);
            body.put("aud", 456);
            body.put("custom_claim", "value");
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(body));

            TokenIntrospection result = client(zone).introspectToken("inactive-token");

            assertThat(result.active()).isFalse();
            assertThat(result.tokenType()).isNull();
            assertThat(result.iss()).isNull();
            assertThat(result.sub()).isNull();
            assertThat(result.clientId()).isNull();
            assertThat(result.aud()).isEmpty();
            assertThat(result.scope()).isEmpty();
            assertThat(result.sid()).isNull();
            assertThat(result.jti()).isNull();
            assertThat(result.iat()).isNull();
            assertThat(result.exp()).isNull();
            assertThat(result.get("custom_claim")).isNull();
            assertThat(result.raw()).containsExactlyEntriesOf(Map.of("active", false));
        }
    }

    @Test
    @DisplayName("row 5: metadata without introspection endpoint fails without a fallback request")
    void row5() {
        try (StubZone zone = StubZone.start()) {
            serveMetadataWithoutIntrospection(zone);

            assertThatThrownBy(() -> client(zone).introspectToken("token"))
                    .isInstanceOfSatisfying(ConfigurationException.class, e -> {
                        assertThat(e).hasMessageContaining("introspection_endpoint");
                        assertThat(e.retryable()).isFalse();
                    });
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "401,invalid_client,false",
        "400,invalid_request,true",
        "429,invalid_client,true",
        "503,invalid_client,true"
    })
    @DisplayName("row 6: OAuth errors preserve status, code and description and follow base retryability")
    void row6(int status, String code, boolean retryable) {
        try (StubZone zone = zone()) {
            zone.respond("POST", INTROSPECT_PATH, status, errorBody(code, "server explanation"));

            assertThatThrownBy(() -> client(zone).introspectToken("token"))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.status()).isEqualTo(status);
                        assertThat(e.error()).isEqualTo(code);
                        assertThat(e.errorDescription()).isEqualTo("server explanation");
                        assertThat(e.retryable()).isEqualTo(retryable);
                    });
            onlyIntrospectionRequest(zone);
        }
    }

    @Test
    @DisplayName("row 7: transport failure or 5xx including server_error is retryable with no hidden retry")
    void row7() {
        try (StubZone zone = zone()) {
            zone.respond("POST", INTROSPECT_PATH, 500, errorBody("server_error", "vault unavailable"));
            assertThatThrownBy(() -> client(zone).introspectToken("token"))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.status()).isEqualTo(500);
                        assertThat(e.error()).isEqualTo("server_error");
                        assertThat(e.retryable()).isTrue();
                    });
            onlyIntrospectionRequest(zone);

            zone.respond("POST", INTROSPECT_PATH, new StubResponse(503, Map.of(), "unavailable"));
            assertThatThrownBy(() -> client(zone).introspectToken("token"))
                    .isInstanceOfSatisfying(HttpStatusException.class, e -> {
                        assertThat(e.status()).isEqualTo(503);
                        assertThat(e.retryable()).isTrue();
                    });
            assertThat(zone.requests(INTROSPECT_PATH)).hasSize(2);

            AuthorizationServerMetadata metadata = AuthorizationServerDiscovery.builder()
                    .transport(transport(zone))
                    .build()
                    .discover(ISSUER);
            AtomicInteger attempts = new AtomicInteger();
            Duration timeout = Duration.ofSeconds(3);
            TokenIntrospectionClient offline = TokenIntrospectionClient.builder(metadata)
                    .credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                    .fetchTimeout(timeout)
                    .transport(request -> {
                        attempts.incrementAndGet();
                        assertThat(request.uri()).isEqualTo(INTROSPECTION_ENDPOINT);
                        assertThat(request.timeout()).isEqualTo(timeout);
                        throw new NetworkException("connection failed", new IOException("connection failed"));
                    })
                    .build();

            assertThatThrownBy(() -> offline.introspectToken("token"))
                    .isInstanceOfSatisfying(
                            NetworkException.class,
                            e -> assertThat(e.retryable()).isTrue());
            assertThat(attempts).hasValue(1);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "not json", "[]", "{}", "{\"active\":\"true\"}", "{\"active\":1}", "{\"active\":null}"})
    @DisplayName("row 8: empty body, malformed JSON, or missing or non-boolean active raises invalid_response")
    void row8(String body) {
        try (StubZone zone = zone()) {
            zone.respond("POST", INTROSPECT_PATH, new StubResponse(200, Map.of(), body));

            assertThatThrownBy(() -> client(zone).introspectToken("token"))
                    .as(body)
                    .isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                        assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE);
                        assertThat(e.retryable()).isTrue();
                    });
        }
    }

    @Test
    @DisplayName("row 9: two calls with the same token send two introspection requests with no caching")
    void row9() {
        try (StubZone zone = zone()) {
            TokenIntrospectionClient client = client(zone);

            assertThat(client.introspectToken("same-token").active()).isTrue();
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(Map.of("active", false)));
            assertThat(client.introspectToken("same-token").active()).isFalse();

            assertThat(zone.requests(INTROSPECT_PATH)).hasSize(2);
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, INTROSPECT_PATH, INTROSPECT_PATH);
        }
    }

    @Test
    @DisplayName("row 10: pre-discovered metadata skips discovery")
    void row10() {
        try (StubZone zone = zone()) {
            TokenIntrospection result = TokenIntrospectionClient.builder(metadata(INTROSPECTION_ENDPOINT))
                    .credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                    .transport(transport(zone))
                    .build()
                    .introspectToken("token");

            assertThat(result.active()).isTrue();
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(INTROSPECT_PATH);
        }
    }

    @Test
    @DisplayName("row 11: credential without client authentication fails before any request")
    void row11() {
        try (StubZone zone = zone()) {
            Credential withoutAuth = context ->
                    TokenExchangeRequest.builder(context.subjectToken()).build();
            assertThatThrownBy(() -> builder(zone).credential(withoutAuth).build())
                    .isInstanceOfSatisfying(
                            ConfigurationException.class,
                            e -> assertThat(e.retryable()).isFalse());
            assertThatThrownBy(() -> builder(zone).build()).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 12: empty or null token fails before any request")
    void row12() {
        try (StubZone zone = zone()) {
            TokenIntrospectionClient client = client(zone);

            assertThatThrownBy(() -> client.introspectToken(""))
                    .isInstanceOfSatisfying(
                            ConfigurationException.class,
                            e -> assertThat(e.retryable()).isFalse());
            assertThatThrownBy(() -> client.introspectToken(null)).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).isEmpty();
        }
    }

    @Test
    @DisplayName("row 13: active response with iss and unknown claims preserves typed iss and unknown claims")
    void row13() {
        try (StubZone zone = zone()) {
            Map<String, Object> act = Map.of("sub", "agent-1");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("active", true);
            body.put("iss", ISSUER.toString());
            body.put("sub", "user-123");
            body.put("sub_profile", "user");
            body.put("act", act);
            body.put("auth_time", 1700000100L);
            body.put("keycard_app_id", "app-456");
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(body));

            TokenIntrospection result = client(zone).introspectToken("token");

            assertThat(result.active()).isTrue();
            assertThat(result.iss()).isEqualTo(ISSUER.toString());
            assertThat(result.get("sub_profile")).isEqualTo("user");
            assertThat(result.get("act")).isEqualTo(act);
            assertThat(result.get("auth_time")).isEqualTo(1700000100L);
            assertThat(result.get("keycard_app_id")).isEqualTo("app-456");
            assertThat(result.raw()).containsKeys("active", "iss", "sub_profile", "act", "auth_time", "keycard_app_id");
        }
    }

    @Test
    @DisplayName("row 14: active refresh-token response without token_type succeeds with null tokenType")
    void row14() {
        try (StubZone zone = zone()) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("active", true);
            body.put("iss", ISSUER.toString());
            body.put("sub", "user-123");
            body.put("client_id", CLIENT_ID);
            body.put("aud", ISSUER.toString());
            body.put("sid", "session-1");
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(body));

            TokenIntrospection result = client(zone).introspectToken("refresh-token");

            assertThat(result.active()).isTrue();
            assertThat(result.tokenType()).isNull();
            assertThat(result.iss()).isEqualTo(ISSUER.toString());
            assertThat(result.sub()).isEqualTo("user-123");
            assertThat(result.aud()).containsExactly(ISSUER.toString());
            assertThat(result.sid()).isEqualTo("session-1");
        }
    }

    @Test
    @DisplayName("row 15: token_type_hint is sent unchanged when set and omitted otherwise")
    void row15() {
        try (StubZone zone = zone()) {
            TokenIntrospectionClient client = client(zone);

            client.introspectToken("token-1");
            client.introspectToken("token-2", "custom+token hint");

            List<RecordedRequest> requests = zone.requests(INTROSPECT_PATH);
            assertThat(requests).hasSize(2);
            assertThat(requests.get(0).formParams()).containsOnlyKeys("token");
            assertThat(requests.get(1).formParams())
                    .containsExactlyInAnyOrderEntriesOf(
                            Map.of("token", List.of("token-2"), "token_type_hint", List.of("custom+token hint")));
        }
    }

    @Test
    @DisplayName("workload identity sends its original assertion")
    void forwardsWorkloadAssertion() throws JOSEException {
        try (StubZone zone = zone()) {
            String assertion = jwt(
                    "JWT",
                    new JWTClaimsSet.Builder().audience("workload-audience").build());
            builder(zone)
                    .credential(WorkloadIdentity.builder(() -> assertion)
                            .clientId(CLIENT_ID)
                            .build())
                    .build()
                    .introspectToken("token");

            Map<String, List<String>> form = onlyIntrospectionRequest(zone).formParams();
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
            TokenIntrospectionClient client = builder(zone)
                    .clock(clock)
                    .credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                    .build();

            assertThatThrownBy(() -> client.introspectToken("first")).isInstanceOf(HttpStatusException.class);
            serveIntrospectionMetadata(zone);
            clock.advance(Duration.ofMillis(4999));
            assertThatThrownBy(() -> client.introspectToken("second")).isInstanceOf(HttpStatusException.class);
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);

            clock.advance(Duration.ofMillis(1));
            assertThat(client.introspectToken("third").active()).isTrue();
            assertThat(client.introspectToken("fourth").active()).isTrue();
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(
                            StubZone.DISCOVERY_PATH, StubZone.DISCOVERY_PATH, INTROSPECT_PATH, INTROSPECT_PATH);
        }
    }

    @Test
    @DisplayName("discovery can pick up a newly advertised introspection endpoint after the negative TTL")
    void missingEndpointExpires() {
        try (StubZone zone = StubZone.start()) {
            serveMetadataWithoutIntrospection(zone);
            TestClock clock = TestClock.start();
            TokenIntrospectionClient client = builder(zone)
                    .clock(clock)
                    .negativeTtl(Duration.ofSeconds(5))
                    .credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                    .build();

            assertThatThrownBy(() -> client.introspectToken("token")).isInstanceOf(ConfigurationException.class);
            serveIntrospectionMetadata(zone);
            zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(Map.of("active", true)));
            clock.advance(Duration.ofMillis(4999));
            assertThatThrownBy(() -> client.introspectToken("token")).isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);

            clock.advance(Duration.ofMillis(1));
            assertThat(client.introspectToken("token").active()).isTrue();
            assertThat(zone.requests())
                    .extracting(RecordedRequest::path)
                    .containsExactly(StubZone.DISCOVERY_PATH, StubZone.DISCOVERY_PATH, INTROSPECT_PATH);
        }
    }

    @Test
    @DisplayName("introspection rejects cleartext endpoints in discovered and supplied metadata")
    void rejectsCleartextIntrospectionEndpoint() {
        try (StubZone zone = StubZone.start()) {
            URI insecureEndpoint = zone.url(INTROSPECT_PATH);
            AuthorizationServerDiscoveryConformanceTest.serve(
                    zone, Map.of("issuer", ISSUER.toString(), "introspection_endpoint", insecureEndpoint.toString()));
            for (TokenIntrospectionClient.Builder builder : List.of(
                    builder(zone),
                    TokenIntrospectionClient.builder(metadata(insecureEndpoint)).transport(transport(zone)))) {
                TokenIntrospectionClient client = builder.credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                        .build();
                assertThatThrownBy(() -> client.introspectToken("token"))
                        .isInstanceOf(ConfigurationException.class)
                        .hasMessageContaining("introspection_endpoint must be an HTTPS URL");
            }
            assertThat(zone.requests()).extracting(RecordedRequest::path).containsExactly(StubZone.DISCOVERY_PATH);
        }
    }

    @Test
    @DisplayName("introspection discovery requires an HTTPS issuer")
    void rejectsCleartextDiscoveryIssuer() {
        assertThatThrownBy(() -> TokenIntrospectionClient.builder(URI.create("http://zone.example")))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("issuer must be an HTTPS URL");
    }

    @Test
    @DisplayName("the introspection client rejects a JDK transport configured to follow redirects")
    void rejectsRedirectFollowingHttpClient() {
        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        assertThatThrownBy(() -> TokenIntrospectionClient.builder(ISSUER).httpClient(http))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("redirects to be disabled");
        assertThatThrownBy(() -> TokenIntrospectionClient.builder(ISSUER).transport(KeycardHttpTransport.of(http)))
                .isInstanceOf(ConfigurationException.class)
                .hasMessageContaining("redirects to be disabled");
    }

    @Test
    @DisplayName("mistyped optional fields in an active response raise invalid_response")
    void mistypedOptionalFields() {
        try (StubZone zone = zone()) {
            for (Map.Entry<String, Object> field : Map.<String, Object>of(
                            "token_type",
                            42,
                            "scope",
                            List.of("read"),
                            "aud",
                            123,
                            "iat",
                            "not-a-number",
                            "exp",
                            1700000000.5)
                    .entrySet()) {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("active", true);
                body.put(field.getKey(), field.getValue());
                zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(body));

                assertThatThrownBy(() -> client(zone).introspectToken("token"))
                        .as(field.getKey())
                        .isInstanceOfSatisfying(
                                OAuthProtocolException.class,
                                e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE));
            }
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start();
        serveIntrospectionMetadata(zone);
        return zone.respond("POST", INTROSPECT_PATH, 200, JSONObjectUtils.toJSONString(Map.of("active", true)));
    }

    private static void serveIntrospectionMetadata(StubZone zone) {
        AuthorizationServerDiscoveryConformanceTest.serve(
                zone, Map.of("issuer", ISSUER.toString(), "introspection_endpoint", INTROSPECTION_ENDPOINT.toString()));
    }

    private static void serveMetadataWithoutIntrospection(StubZone zone) {
        AuthorizationServerDiscoveryConformanceTest.serve(zone, Map.of("issuer", ISSUER.toString()));
    }

    private static TokenIntrospectionClient client(StubZone zone) {
        return builder(zone)
                .credential(ClientSecret.of(CLIENT_ID, CLIENT_SECRET))
                .build();
    }

    private static TokenIntrospectionClient.Builder builder(StubZone zone) {
        return TokenIntrospectionClient.builder(ISSUER).transport(transport(zone));
    }

    private static AuthorizationServerMetadata metadata(URI endpoint) {
        return new AuthorizationServerMetadata(
                ISSUER, null, null, null, null, null, null, null, null, endpoint, List.of(), List.of(), List.of(),
                List.of(), List.of(), Map.of());
    }

    private static KeycardHttpTransport transport(StubZone zone) {
        KeycardHttpTransport http = KeycardHttpTransport.create();
        // Keep HTTPS URLs at the SDK boundary and deliver those requests to the loopback stub.
        return request -> {
            URI path = ISSUER.relativize(request.uri());
            assertThat(path.isAbsolute()).isFalse();
            return http.send(new TransportRequest(
                    request.method(),
                    zone.issuer().resolve(path),
                    request.headers(),
                    request.body(),
                    request.timeout()));
        };
    }

    private static RecordedRequest onlyIntrospectionRequest(StubZone zone) {
        List<RecordedRequest> requests = zone.requests(INTROSPECT_PATH);
        assertThat(requests).hasSize(1);
        return requests.get(0);
    }

    private static String errorBody(String code, String description) {
        return JSONObjectUtils.toJSONString(Map.of("error", code, "error_description", description));
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

    private record HeaderSigningCredential(WebIdentity identity) implements Credential, ClientAuthenticator {

        @Override
        public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
            return identity.prepareTokenExchangeRequest(context);
        }

        @Override
        public ClientAuthentication authenticate(URI issuer, URI endpoint) {
            assertThat(issuer).isEqualTo(ISSUER);
            assertThat(endpoint).isEqualTo(ISSUER);
            return new ClientAuthentication(
                    Map.of("X-Test-Auth", "present"),
                    identity.authenticate(issuer, endpoint).formFields());
        }
    }
}
