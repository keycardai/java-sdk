package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationCodeClient;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.InteractionTimeoutException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.Pkce;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WebAppFlow;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.oauth.testing.StubZone;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * authorization-code-pkce.md (spec-version 4, client authentication from base spec-version 5),
 * Unit Tests table. Row 13 (the removed single-resource argument) has no Java counterpart: Java
 * never shipped that argument.
 */
class AuthorizationCodePkceConformanceTest {

    private static final URI REDIRECT = URI.create("http://127.0.0.1:8765/callback");
    private static final String TOKENS = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
            + "\"refresh_token\":\"rt-2\",\"id_token\":\"idt\",\"scope\":\"openid\"}";

    @Test
    @DisplayName("row 1: a generated verifier is 43 to 128 unreserved characters")
    void row1() {
        for (int i = 0; i < 20; i++) {
            String verifier = Pkce.generate().codeVerifier();
            assertThat(verifier).hasSizeBetween(43, 128).matches("[A-Za-z0-9._~-]+");
        }
        assertThat(Pkce.generate().codeVerifier()).isNotEqualTo(Pkce.generate().codeVerifier());
        assertThatThrownBy(() -> Pkce.s256("too-short")).isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 2: the S256 challenge is BASE64URL(SHA-256(verifier))")
    void row2() throws Exception {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        Pkce pkce = Pkce.s256(verifier);

        assertThat(pkce.codeChallenge()).isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assertThat(pkce.codeChallenge())
                .isEqualTo(Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(MessageDigest.getInstance("SHA-256")
                                .digest(verifier.getBytes(StandardCharsets.US_ASCII))));
        assertThat(pkce.codeChallengeMethod()).isEqualTo("S256");
        assertThat(pkce.toString()).doesNotContain(verifier);
    }

    @Test
    @DisplayName("row 3: the authorize URL carries response_type, client_id, redirect_uri, the challenge and scope")
    void row3() {
        Pkce pkce = Pkce.generate();
        URI url = AuthorizationCodeClient.buildAuthorizeUrl(
                URI.create("https://acme.keycard.cloud/oauth/authorize"),
                "my-cli",
                REDIRECT,
                pkce,
                "st",
                List.of("openid", "email"),
                List.of());

        Map<String, List<String>> query = query(url);
        assertThat(url.getPath()).isEqualTo("/oauth/authorize");
        assertThat(query)
                .containsEntry("response_type", List.of("code"))
                .containsEntry("client_id", List.of("my-cli"))
                .containsEntry("redirect_uri", List.of(REDIRECT.toString()))
                .containsEntry("code_challenge", List.of(pkce.codeChallenge()))
                .containsEntry("code_challenge_method", List.of("S256"))
                .containsEntry("scope", List.of("openid email"))
                .containsEntry("state", List.of("st"))
                .doesNotContainKey("resource");
    }

    @Test
    @DisplayName("rows 4 and 5: a public client exchanges the code with client_id in the body and no Basic")
    void rows4And5() {
        try (StubZone zone = zone()) {
            TokenResponse token = AuthorizationCodeClient.builder(zone.issuer())
                    .clientId("my-cli")
                    .build()
                    .exchangeCode("the-code", "the-verifier-the-verifier-the-verifier-1234", REDIRECT);

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("grant_type", List.of("authorization_code"))
                    .containsEntry("code", List.of("the-code"))
                    .containsEntry("code_verifier", List.of("the-verifier-the-verifier-the-verifier-1234"))
                    .containsEntry("redirect_uri", List.of(REDIRECT.toString()))
                    .containsEntry("client_id", List.of("my-cli"));
            assertThat(request.header("Authorization")).isNull();
            assertThat(token.refreshToken()).isEqualTo("rt-2");
            assertThat(token.idToken()).isEqualTo("idt");
        }
    }

    @Test
    @DisplayName("row 6: a confidential client sends Basic and doesn't repeat client_id in the body")
    void row6() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient.builder(zone.issuer())
                    .clientId("web-app")
                    .clientSecret("s3cret")
                    .build()
                    .exchangeCode("c", "v".repeat(43), REDIRECT);

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.header("Authorization"))
                    .isEqualTo("Basic " + ClientSecretConformanceTest.basic("web-app", "s3cret"));
            assertThat(request.formParams()).doesNotContainKey("client_id");
        }
    }

    @Test
    @DisplayName("row 7: an OAuth error response is a typed error carrying error and error_description")
    void row7() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "POST",
                    StubZone.TOKEN_PATH,
                    400,
                    "{\"error\":\"invalid_grant\",\"error_description\":\"code used\"}");

            assertThatThrownBy(() -> AuthorizationCodeClient.builder(zone.issuer())
                            .clientId("my-cli")
                            .build()
                            .exchangeCode("c", "v".repeat(43), REDIRECT))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("invalid_grant");
                        assertThat(e.errorDescription()).isEqualTo("code used");
                    });
        }
    }

    @Test
    @DisplayName("rows 8 and 12: begin returns url, state, verifier and resources; one resource parameter each")
    void rows8And12() {
        try (StubZone zone = zone()) {
            URI ledger = URI.create("https://ledger.example");
            URI crm = URI.create("https://crm.example");
            WebAppFlow flow = client(zone).begin(REDIRECT, List.of("openid"), List.of(ledger, crm));

            Map<String, List<String>> query = query(flow.url());
            assertThat(flow.url().toString())
                    .startsWith(zone.url(StubZone.AUTHORIZE_PATH).toString());
            assertThat(query).containsEntry("state", List.of(flow.state()));
            assertThat(query)
                    .containsEntry(
                            "code_challenge",
                            List.of(Pkce.s256(flow.codeVerifier()).codeChallenge()));
            assertThat(query.get("resource")).containsExactly(ledger.toString(), crm.toString());
            assertThat(flow.resources()).containsExactly(ledger, crm);
            assertThat(flow.state()).hasSizeGreaterThanOrEqualTo(22);
            assertThat(flow.toString()).doesNotContain(flow.codeVerifier());
        }
    }

    @Test
    @DisplayName("rows 9 and 14: complete with a matching state exchanges the code and never sends resource")
    void rows9And14() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient client = client(zone);
            WebAppFlow flow = client.begin(REDIRECT, List.of(), List.of(URI.create("https://ledger.example")));

            TokenResponse token = client.complete(
                    Map.of("code", "the-code", "state", flow.state()), flow.state(), flow.codeVerifier(), REDIRECT);

            assertThat(token.accessToken()).isEqualTo("at");
            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams())
                    .containsEntry("code", List.of("the-code"))
                    .containsEntry("code_verifier", List.of(flow.codeVerifier()))
                    .containsEntry("redirect_uri", List.of(REDIRECT.toString()))
                    .doesNotContainKey("resource");
        }
    }

    @Test
    @DisplayName("row 10: a wrong or missing state is rejected before any token request")
    void row10() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient client = client(zone);
            WebAppFlow flow = client.begin(REDIRECT, List.of(), List.of());

            assertThatThrownBy(() -> client.complete(
                            Map.of("code", "c", "state", "forged"), flow.state(), flow.codeVerifier(), REDIRECT))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo("state_mismatch"));
            assertThatThrownBy(() -> client.complete(Map.of("code", "c"), flow.state(), flow.codeVerifier(), REDIRECT))
                    .isInstanceOf(OAuthProtocolException.class);
            assertThatThrownBy(() ->
                            client.complete(Map.of("state", flow.state()), flow.state(), flow.codeVerifier(), REDIRECT))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo("invalid_callback"));
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 11: error=access_denied in the callback is a typed error with no token request")
    void row11() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient client = client(zone);

            assertThatThrownBy(() -> client.complete(
                            Map.of("error", "access_denied", "error_description", "user said no", "state", "s"),
                            "s",
                            "v".repeat(43),
                            REDIRECT))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("access_denied");
                        assertThat(e.errorDescription()).isEqualTo("user said no");
                        assertThat(e.retryable()).isFalse();
                    });
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName(
            "row 15: a public refresh sends grant_type, refresh_token, client_id and each resource; invalid_grant is permanent, 5xx retryable")
    void row15() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient client = client(zone);
            URI ledger = URI.create("https://ledger.example");

            TokenResponse renewed = client.refresh("rt-1", List.of(ledger), List.of());

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("grant_type", List.of("refresh_token"))
                    .containsEntry("refresh_token", List.of("rt-1"))
                    .containsEntry("client_id", List.of("my-cli"))
                    .containsEntry("resource", List.of(ledger.toString()))
                    .doesNotContainKeys("subject_token_type", "scope");
            assertThat(request.header("Authorization")).isNull();
            assertThat(renewed.refreshToken()).isEqualTo("rt-2");

            zone.respond("POST", StubZone.TOKEN_PATH, 400, "{\"error\":\"invalid_grant\"}");
            assertThatThrownBy(() -> client.refresh("rt-1", List.of(), List.of()))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("invalid_grant");
                        assertThat(e.retryable()).isFalse();
                    });

            zone.respond("POST", StubZone.TOKEN_PATH, 503, "{}");
            assertThatThrownBy(() -> client.refresh("rt-1", List.of(), List.of()))
                    .isInstanceOfSatisfying(
                            ai.keycard.oauth.HttpStatusException.class,
                            e -> assertThat(e.retryable()).isTrue());
        }
    }

    @Test
    @DisplayName("row 16: a credential refresh sends its form fields and headers, never subject_token_type")
    void row16() {
        try (StubZone zone = zone()) {
            AuthorizationCodeClient.builder(zone.issuer())
                    .credential(WorkloadIdentity.builder(() -> "svid")
                            .clientId("engine")
                            .build())
                    .build()
                    .refresh("rt-1", List.of(URI.create("https://ledger.example")), List.of());

            StubZone.RecordedRequest request =
                    zone.requests(StubZone.TOKEN_PATH).get(0);
            assertThat(request.formParams())
                    .containsEntry("client_assertion", List.of("svid"))
                    .containsEntry("client_assertion_type", List.of(TokenTypes.JWT_BEARER_ASSERTION))
                    .containsEntry("client_id", List.of("engine"))
                    .containsEntry("resource", List.of("https://ledger.example"))
                    .doesNotContainKey("subject_token_type");

            AuthorizationCodeClient.builder(zone.issuer())
                    .credential(ClientSecret.of("web-app", "s3cret"))
                    .build()
                    .refresh("rt-1", List.of(), List.of());
            assertThat(zone.requests(StubZone.TOKEN_PATH).get(1).header("Authorization"))
                    .isEqualTo("Basic " + ClientSecretConformanceTest.basic("web-app", "s3cret"));

            assertThatThrownBy(() -> AuthorizationCodeClient.builder(zone.issuer())
                            .credential(ClientSecret.of("a", "b"))
                            .clientId("a")
                            .build())
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("high-level flow: the loopback server receives the redirect and the code is exchanged")
    void loopbackFlow() {
        try (StubZone zone = zone()) {
            List<URI> opened = new ArrayList<>();
            TokenResponse token = client(zone)
                    .authenticate(AuthorizationCodeClient.Loopback.builder()
                            .scopes("openid")
                            .resources(URI.create("https://ledger.example"))
                            .browser(url -> {
                                opened.add(url);
                                Map<String, List<String>> query = query(url);
                                // The zone's redirect, as a browser would follow it.
                                get(URI.create(query.get("redirect_uri").get(0) + "?code=browser-code&state="
                                        + query.get("state").get(0)));
                            })
                            .build());

            assertThat(token.accessToken()).isEqualTo("at");
            assertThat(opened).hasSize(1);
            Map<String, List<String>> form =
                    zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            assertThat(form).containsEntry("code", List.of("browser-code"));
            assertThat(form.get("redirect_uri").get(0))
                    .startsWith("http://127.0.0.1:")
                    .endsWith("/callback");
        }
    }

    @Test
    @DisplayName("high-level flow: no redirect within the timeout is an interaction timeout")
    void loopbackTimeout() {
        try (StubZone zone = zone()) {
            assertThatThrownBy(() -> client(zone)
                            .authenticate(AuthorizationCodeClient.Loopback.builder()
                                    .timeout(Duration.ofMillis(200))
                                    .browser(url -> {})
                                    .build()))
                    .isInstanceOf(InteractionTimeoutException.class);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKENS);
        return zone;
    }

    private static AuthorizationCodeClient client(StubZone zone) {
        return AuthorizationCodeClient.builder(zone.issuer()).clientId("my-cli").build();
    }

    static Map<String, List<String>> query(URI url) {
        Map<String, List<String>> params = new LinkedHashMap<>();
        for (String pair : url.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            params.computeIfAbsent(
                            URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8), k -> new ArrayList<>())
                    .add(URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return params;
    }

    private static void get(URI url) {
        try {
            HttpClient.newHttpClient()
                    .send(HttpRequest.newBuilder(url).GET().build(), HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
