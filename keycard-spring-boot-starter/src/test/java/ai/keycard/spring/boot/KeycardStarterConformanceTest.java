package ai.keycard.spring.boot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * The starter against FRAMEWORK-INTEGRATIONS.md's checklist: the bearer HTTP contract (P8),
 * standards-named metadata (P7), and the grant-decorator Unit Tests table through {@link
 * KeycardGrant}.
 */
class KeycardStarterConformanceTest {

    private static final RSAKey KEY = key();
    private static final String AUDIENCE = "https://api.example.com";
    private static final String CALENDAR = "https://calendar.example";
    private static final String MAIL = "https://mail.example";

    @Test
    @DisplayName("P8: a verified token reaches the handler; Spring sees Keycard's claims")
    void verified() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = perform(mvc, "/me", token(zone, "read", AUDIENCE));
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result)).startsWith("user-1 ").contains("SCOPE_read");
        });
    }

    @Test
    @DisplayName("P8: no token is 401 with an RFC 6750 challenge naming resource_metadata")
    void missing() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = perform(mvc, "/me", null);
            assertThat(result.getResponse().getStatus()).isEqualTo(401);
            assertThat(result.getResponse().getHeader("WWW-Authenticate"))
                    .startsWith("Bearer")
                    .contains("resource_metadata=");
        });
    }

    @Test
    @DisplayName("P8: an unauthenticated POST is 401, not a CSRF 403; a cookie POST keeps CSRF")
    void postWithoutToken() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult bare = mvc.perform(post("/echo")).andReturn();
            assertThat(bare.getResponse().getStatus()).isEqualTo(401);
            assertThat(bare.getResponse().getHeader("WWW-Authenticate")).contains("resource_metadata=");
            MvcResult authorized = mvc.perform(
                            post("/echo").header("Authorization", "Bearer " + token(zone, "read", AUDIENCE)))
                    .andReturn();
            assertThat(authorized.getResponse().getStatus()).isEqualTo(200);
            MvcResult cookie = mvc.perform(post("/echo").cookie(new jakarta.servlet.http.Cookie("SESSION", "x")))
                    .andReturn();
            assertThat(cookie.getResponse().getStatus()).isEqualTo(403);
        });
    }

    @Test
    @DisplayName("P8: a token for another audience, or a forged one, is 401 invalid_token")
    void invalid() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            for (String token : List.of(token(zone, "read", "https://other.example"), "not.a.jwt")) {
                MvcResult result = perform(mvc, "/me", token);
                assertThat(result.getResponse().getStatus()).isEqualTo(401);
                assertThat(result.getResponse().getHeader("WWW-Authenticate")).contains("error=\"invalid_token\"");
            }
        });
    }

    @Test
    @DisplayName("P8: a malformed Authorization header is 400 invalid_request")
    void malformed() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = mvc.perform(get("/me").header("Authorization", "Bearer a b c"))
                    .andReturn();
            assertThat(result.getResponse().getStatus()).isEqualTo(400);
            assertThat(result.getResponse().getHeader("WWW-Authenticate")).contains("invalid_request");
        });
    }

    @Test
    @DisplayName("P8: a missing scope on a Spring rule is 403 insufficient_scope")
    void insufficientScope() throws Exception {
        withApp(ScopedChain.class, (zone, mvc) -> {
            MvcResult denied = perform(mvc, "/me", token(zone, "read", AUDIENCE));
            assertThat(denied.getResponse().getStatus()).isEqualTo(403);
            assertThat(denied.getResponse().getHeader("WWW-Authenticate")).contains("insufficient_scope");
            assertThat(perform(mvc, "/me", token(zone, "read admin", AUDIENCE))
                            .getResponse()
                            .getStatus())
                    .isEqualTo(200);
        });
    }

    @Test
    @DisplayName("P8: unreachable zone keys are 503 temporarily_unavailable with no challenge")
    void zoneUnavailable() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            zone.respond("GET", StubZone.JWKS_PATH, 503, "{}");
            MvcResult result = perform(mvc, "/me", token(zone, "read", AUDIENCE));
            assertThat(result.getResponse().getStatus()).isEqualTo(503);
            assertThat(result.getResponse().getHeader("WWW-Authenticate")).isNull();
            assertThat(body(result)).contains("temporarily_unavailable");
        });
    }

    @Test
    @DisplayName("P7: RFC 9728 metadata with path insertion names the zone, without a token")
    void protectedResourceMetadata() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = perform(mvc, "/.well-known/oauth-protected-resource/mcp", null);
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result))
                    .contains("\"resource\":\"http://localhost/mcp\"")
                    .contains(zone.issuer().toString())
                    .contains("\"resource_name\":\"Test API\"")
                    .contains("\"mcp:tools\"");
        });
    }

    @Test
    @DisplayName("P7: the zone's RFC 8414 metadata is proxied unmodified, without a token")
    void authorizationServerMetadata() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = perform(mvc, "/.well-known/oauth-authorization-server", null);
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result)).contains(zone.url(StubZone.TOKEN_PATH).toString());
        });
    }

    @Test
    @DisplayName("grant row 1: two resources exchange; the handler gets an AccessContext with both")
    void grantRow1() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            String caller = token(zone, "read", AUDIENCE);
            MvcResult result = perform(mvc, "/both", caller);
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result)).isEqualTo("SUCCESS at_" + CALENDAR + " at_" + MAIL);
            assertThat(zone.requests(StubZone.TOKEN_PATH))
                    .allSatisfy(
                            r -> assertThat(r.formParams().get("subject_token")).containsExactly(caller));
            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams().get("scope"))
                    .containsExactly("calendar.read");
        });
    }

    @Test
    @DisplayName("grant row 2: a failed exchange is recorded and the handler still runs")
    void grantRow2() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            zone.respondWith(
                    "POST",
                    StubZone.TOKEN_PATH,
                    r -> r.formParams().get("resource").contains(MAIL)
                            ? StubResponse.json(400, "{\"error\":\"invalid_target\"}")
                            : exchanged(r.formParams().get("resource").get(0)));
            MvcResult result = perform(mvc, "/both", token(zone, "read", AUDIENCE));
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result)).startsWith("PARTIAL_ERROR at_" + CALENDAR);
        });
    }

    @Test
    @DisplayName("grant rows 3 and 5: a class grant and a method grant union into one context")
    void grantStacked() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult result = perform(mvc, "/stacked/mail", token(zone, "read", AUDIENCE));
            assertThat(body(result)).isEqualTo("[" + CALENDAR + ", " + MAIL + "]");
        });
    }

    @Test
    @DisplayName("an application JwtDecoder or SecurityFilterChain replaces the starter's")
    void backsOff() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withUserConfiguration(DefaultChain.class, CustomDecoder.class)
                    .run(context ->
                            assertThat(context.getBean(JwtDecoder.class)).isNotInstanceOf(KeycardJwtDecoder.class));
            runner(zone)
                    .withUserConfiguration(ScopedChain.class)
                    .run(context -> assertThat(context.getBeansOfType(SecurityFilterChain.class))
                            .containsOnlyKeys("scoped"));
        }
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(KeycardAutoConfiguration.class))
                .withUserConfiguration(DefaultChain.class)
                .run(context -> assertThat(context).doesNotHaveBean(KeycardResourceServer.class));
    }

    // --- the application under test ----------------------------------------------------------

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class DefaultChain {

        @Bean
        Api api() {
            return new Api();
        }

        @Bean
        StackedApi stackedApi() {
            return new StackedApi();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class ScopedChain extends DefaultChain {

        @Bean
        SecurityFilterChain scoped(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_admin"))
                    .with(keycard, Customizer.withDefaults())
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomDecoder {

        @Bean
        JwtDecoder customDecoder() {
            return token -> {
                throw new UnsupportedOperationException();
            };
        }
    }

    @RestController
    static class Api {

        @GetMapping("/me")
        String me(@AuthenticationPrincipal Jwt jwt, org.springframework.security.core.Authentication auth) {
            return jwt.getSubject() + " " + auth.getAuthorities();
        }

        @org.springframework.web.bind.annotation.PostMapping("/echo")
        String echo(@AuthenticationPrincipal Jwt jwt) {
            return jwt.getSubject();
        }

        @GetMapping("/both")
        @KeycardGrant(
                resources = {CALENDAR, MAIL},
                scopes = "calendar.read")
        String both(AccessContext access) {
            StringBuilder out = new StringBuilder(access.status().name());
            for (String resource : access.successfulResources()) {
                out.append(' ').append(access.access(resource).accessToken());
            }
            return out.toString();
        }
    }

    @RestController
    @KeycardGrant(resources = CALENDAR)
    static class StackedApi {

        @GetMapping("/stacked/mail")
        @KeycardGrant(resources = MAIL)
        String mail(AccessContext access) {
            return access.successfulResources().toString();
        }
    }

    // --- helpers -----------------------------------------------------------------------------

    @FunctionalInterface
    interface MvcCheck {
        void check(StubZone zone, MockMvc mvc) throws Exception;
    }

    private static void withApp(Class<?> app, MvcCheck check) {
        try (StubZone zone = zone()) {
            runner(zone).withUserConfiguration(app).run(context -> {
                assertThat(context).hasNotFailed();
                MockMvc mvc = MockMvcBuilders.webAppContextSetup(context)
                        .apply(SecurityMockMvcConfigurers.springSecurity())
                        .build();
                check.check(zone, mvc);
            });
        }
    }

    private static WebApplicationContextRunner runner(StubZone zone) {
        return new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(KeycardAutoConfiguration.class))
                .withPropertyValues(
                        "keycard.zone-url=" + zone.issuer(),
                        "keycard.audiences=" + AUDIENCE,
                        "keycard.client-id=cid",
                        "keycard.client-secret=csecret",
                        "keycard.resource-name=Test API",
                        "keycard.scopes-supported=mcp:tools");
    }

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(KEY.toPublicJWK()).toString());
        zone.respondWith(
                "POST",
                StubZone.TOKEN_PATH,
                r -> exchanged(r.formParams().get("resource").get(0)));
        return zone;
    }

    private static StubResponse exchanged(String resource) {
        return StubResponse.json(200, "{\"access_token\":\"at_" + resource + "\",\"token_type\":\"Bearer\"}");
    }

    private static MvcResult perform(MockMvc mvc, String path, String token) throws Exception {
        var request = get(path);
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return mvc.perform(request).andReturn();
    }

    private static String body(MvcResult result) throws Exception {
        return result.getResponse().getContentAsString();
    }

    private static String token(StubZone zone, String scope, String audience) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", zone.issuer().toString());
        claims.put("sub", "user-1");
        claims.put("client_id", "client-1");
        claims.put("aud", List.of(audience));
        claims.put("scope", scope);
        claims.put("iat", now);
        claims.put("exp", now + 300);
        try {
            return JwtSigner.of(new SigningKey(KEY.toRSAPrivateKey(), KEY.getKeyID(), null))
                    .sign(claims);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey key() {
        try {
            return new RSAKeyGenerator(2048).keyID("starter-key").generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
