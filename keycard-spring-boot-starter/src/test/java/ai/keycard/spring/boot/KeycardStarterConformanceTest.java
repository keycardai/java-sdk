package ai.keycard.spring.boot;

import static ai.keycard.oauth.testing.IntrospectionStub.PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.mcp.RequireBearerAuthFilter.ZoneResolver;
import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.TransportResponse;
import ai.keycard.oauth.testing.IntrospectionStub;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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
    @DisplayName("row 18 (Spring): the configured owner credential checks the original token before the handler")
    void introspectionActive() {
        withIntrospectionApp(DefaultChain.class, "true", (zone, mvc) -> {
            String token = token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me");
            MvcResult result = perform(mvc, "/me", token);
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(result)).startsWith("user-1 ").contains("SCOPE_read");
            assertThat(zone.requests(PATH)).singleElement().satisfies(call -> {
                assertThat(call.header("Authorization")).isEqualTo("Basic b3duZXI6c2VjcmV0");
                assertThat(call.formParams().get("token")).containsExactly(token);
            });
        });
    }

    @Test
    @DisplayName("rows 19 and 22 (Spring): the same token is checked again and can become inactive")
    void introspectionInactive() {
        withIntrospectionApp(DefaultChain.class, "true", (zone, mvc) -> {
            String token = token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me");
            assertThat(perform(mvc, "/me", token).getResponse().getStatus()).isEqualTo(200);
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            var response = perform(mvc, "/me", token).getResponse();
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(response.getHeader("WWW-Authenticate"))
                    .contains(
                            "error=\"invalid_token\"",
                            "resource_metadata=\"https://api.example.com/.well-known/oauth-protected-resource/me\"");
            assertThat(response.getContentAsString()).isEmpty();
            assertThat(zone.requests(PATH)).hasSize(2);
        });
    }

    @Test
    @DisplayName("row 20 (Spring): an introspection failure returns 503 without a challenge")
    void introspectionUnavailable() {
        withIntrospectionApp(DefaultChain.class, "true", (zone, mvc) -> {
            zone.respond("POST", PATH, 401, "{\"error\":\"invalid_client\"}");
            var response = perform(mvc, "/me", token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me"))
                    .getResponse();
            assertThat(response.getStatus()).isEqualTo(503);
            assertThat(response.getHeader("WWW-Authenticate")).isNull();
            assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"temporarily_unavailable\"}");
            assertThat(zone.requests(PATH)).hasSize(1);
        });
    }

    @Test
    @DisplayName("introspection preserves the chain's custom JWT authority converter")
    void introspectionWithCustomJwtConverter() {
        withIntrospectionApp(CustomJwtChain.class, "true", (zone, mvc) -> {
            String jwt = token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me");
            zone.respond("POST", PATH, StubResponse.json(200, "{\"active\":true}"));
            assertThat(perform(mvc, "/me", jwt).getResponse().getStatus()).isEqualTo(200);
            Map<Integer, StubResponse> rejections = Map.of(
                    401, StubResponse.json(200, "{\"active\":false}"),
                    503, StubResponse.json(500, "{\"error\":\"server_error\"}"));
            for (var rejection : rejections.entrySet()) {
                zone.respond("POST", PATH, rejection.getValue());
                var session = new MockHttpSession();
                var result = mvc.perform(get("/me").session(session).header("Authorization", "Bearer " + jwt))
                        .andReturn();
                assertThat(result.getResponse().getStatus()).isEqualTo(rejection.getKey());
                assertThat(mvc.perform(get("/me").session(session))
                                .andReturn()
                                .getResponse()
                                .getStatus())
                        .isEqualTo(401);
            }
            assertThat(zone.requests(PATH)).hasSize(3);
        });
    }

    @Test
    @DisplayName("introspection accepts a JWT converter that retains only an application principal")
    void introspectionWithCustomPrincipal() {
        withIntrospectionApp(CustomPrincipalChain.class, "true", (zone, mvc) -> {
            String jwt = token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me");
            var active = perform(mvc, "/me", jwt);
            assertThat(active.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(active)).isEqualTo("user-1");
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            assertThat(perform(mvc, "/me", jwt).getResponse().getStatus()).isEqualTo(401);
            assertThat(zone.requests(PATH))
                    .hasSize(2)
                    .allSatisfy(
                            call -> assertThat(call.formParams().get("token")).containsExactly(jwt));
        });
    }

    @Test
    @DisplayName("row 21 (Spring): invalid local tokens and default or disabled introspection make no call")
    void introspectionSkipped() {
        withIntrospectionApp(DefaultChain.class, "true", (zone, mvc) -> {
            assertThat(perform(mvc, "/me", token(IntrospectionStub.issuer(zone), "read", AUDIENCE))
                            .getResponse()
                            .getStatus())
                    .isEqualTo(401);
            assertThat(zone.requests(PATH)).isEmpty();
        });
        MvcCheck valid = (zone, mvc) -> {
            assertThat(perform(mvc, "/me", token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me"))
                            .getResponse()
                            .getStatus())
                    .isEqualTo(200);
            assertThat(zone.requests(PATH)).isEmpty();
        };
        withIntrospectionApp(DefaultChain.class, null, valid);
        withIntrospectionApp(DefaultChain.class, "false", valid);
    }

    @Test
    @DisplayName("Spring honors a provider's introspection opt-in without a property opt-in")
    void introspectionInheritsProviderOptIn() {
        MvcCheck verify = (zone, mvc) -> {
            String jwt = token(IntrospectionStub.issuer(zone), "read", AUDIENCE + "/me");
            zone.respond("POST", PATH, 200, "{\"active\":false}");
            assertThat(perform(mvc, "/me", jwt).getResponse().getStatus()).isEqualTo(401);
            assertThat(zone.requests(PATH))
                    .singleElement()
                    .satisfies(
                            call -> assertThat(call.formParams().get("token")).containsExactly(jwt));
        };
        withIntrospectionApp(DefaultChain.class, null, true, verify);
        withIntrospectionApp(DefaultChain.class, "false", true, verify);
    }

    @Test
    @DisplayName("row 23 (Spring): a credential without client authentication fails at startup")
    void introspectionCredentialsRequired() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues("keycard.introspect=true")
                    .withBean(
                            Credential.class,
                            () -> context -> ClientSecret.of("owner", "secret").prepareTokenExchangeRequest(context))
                    .withUserConfiguration(DefaultChain.class)
                    .run(context -> assertThat(context)
                            .hasFailed()
                            .getFailure()
                            .hasRootCauseInstanceOf(ConfigurationException.class)
                            .hasStackTraceContaining("introspection requires a credential with client authentication"));
        }
    }

    @Test
    @DisplayName("row 25 (Spring): Spring authorization checks required scope before introspection")
    void introspectionAfterScopes() {
        withIntrospectionApp(ScopedChain.class, "true", (zone, mvc) -> {
            URI issuer = IntrospectionStub.issuer(zone);
            var denied =
                    perform(mvc, "/me", token(issuer, "read", AUDIENCE + "/me")).getResponse();
            assertThat(denied.getStatus()).isEqualTo(403);
            assertThat(denied.getHeader("WWW-Authenticate")).contains("error=\"insufficient_scope\"");
            assertThat(zone.requests(PATH)).isEmpty();
            assertThat(perform(mvc, "/me", token(issuer, "admin", AUDIENCE + "/me"))
                            .getResponse()
                            .getStatus())
                    .isEqualTo(200);
            assertThat(zone.requests(PATH)).hasSize(1);
        });
    }

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
    @DisplayName("P8: the default chain answers an unauthenticated POST, cookie or not, with the 401 challenge")
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
            assertThat(cookie.getResponse().getStatus()).isEqualTo(401);
            assertThat(cookie.getResponse().getHeader("Set-Cookie")).isNull();
        });
    }

    @Test
    @DisplayName("P8: another scheme on a protected path is 401 invalid_token, as the servlet filter answers")
    void otherSchemeIsInvalidToken() throws Exception {
        withApp(DefaultChain.class, (zone, mvc) -> {
            MvcResult basic = mvc.perform(get("/me").header("Authorization", "Basic dTpw"))
                    .andReturn();
            assertThat(basic.getResponse().getStatus()).isEqualTo(401);
            assertThat(basic.getResponse().getHeader("WWW-Authenticate"))
                    .contains("error=\"invalid_token\"")
                    .contains("resource_metadata=");
            MvcResult none = mvc.perform(get("/me")).andReturn();
            assertThat(none.getResponse().getHeader("WWW-Authenticate")).doesNotContain("error=");
        });
    }

    @Test
    @DisplayName("another scheme still reaches a permitAll path; the challenge only speaks for protected ones")
    void otherSchemeOnPublicPath() throws Exception {
        withApp(PublicChain.class, (zone, mvc) -> {
            MvcResult open = mvc.perform(get("/public/ping").header("Authorization", "Digest x"))
                    .andReturn();
            assertThat(open.getResponse().getStatus()).isEqualTo(200);
        });
    }

    @Test
    @DisplayName("Basic sign-in in the same chain as Keycard still works, and so do bearer tokens")
    void basicBesideKeycard() throws Exception {
        withApp(MixedChain.class, (zone, mvc) -> {
            MvcResult admin = mvc.perform(get("/admin/ping")
                            .header(
                                    "Authorization",
                                    "Basic "
                                            + java.util.Base64.getEncoder()
                                                    .encodeToString("admin:pw"
                                                            .getBytes(java.nio.charset.StandardCharsets.UTF_8))))
                    .andReturn();
            assertThat(admin.getResponse().getStatus()).isEqualTo(200);
            MvcResult bearer = perform(mvc, "/me", token(zone, "read", AUDIENCE));
            assertThat(bearer.getResponse().getStatus()).isEqualTo(200);
        });
    }

    @Test
    @DisplayName("the configurer leaves an application chain's CSRF on: a POST without a CSRF token is 403")
    void applicationChainKeepsCsrf() throws Exception {
        withApp(ScopedChain.class, (zone, mvc) -> {
            MvcResult basic = mvc.perform(post("/echo").header("Authorization", "Basic dTpw"))
                    .andReturn();
            assertThat(basic.getResponse().getStatus()).isEqualTo(403);
            assertThat(basic.getResponse().getHeader("WWW-Authenticate")).doesNotContain("invalid_token");
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
    @DisplayName("row 7 (bearer middleware): an empty legacy audience property behaves like omission")
    void emptyLegacyAudience() {
        withApp(
                DefaultChain.class,
                (zone, mvc) -> {
                    assertThat(perform(mvc, "/me", token(zone, "read", "urn:example:other"))
                                    .getResponse()
                                    .getStatus())
                            .isEqualTo(200);
                    assertThat(perform(mvc, "/me", null).getResponse().getHeader("WWW-Authenticate"))
                            .contains("resource_metadata=");
                },
                "keycard.audiences=");
    }

    @Test
    @DisplayName("row 8e (bearer middleware): an empty audience property cannot enable multi-resource mode")
    void emptyMultiResourceAudience() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues("keycard.audiences=", "keycard.multi-resource=true")
                    .withUserConfiguration(DefaultChain.class)
                    .run(context -> assertThat(context)
                            .hasFailed()
                            .getFailure()
                            .hasRootCauseMessage("multiResource requires a nonempty audience list"));
        }
    }

    @Test
    @DisplayName("rows 1, 8, 12 and metadata row 7 (bearer middleware): configured resource binds Spring end to end")
    void explicitResource() {
        String identifier = AUDIENCE + "/me";
        String metadata = "/.well-known/oauth-protected-resource/me";
        withApp(
                DefaultChain.class,
                (zone, mvc) -> {
                    var anonymous = mvc.perform(get("/me").header("X-Forwarded-Host", "other.example"))
                            .andReturn()
                            .getResponse();
                    assertThat(anonymous.getStatus()).isEqualTo(401);
                    assertThat(anonymous.getHeader("WWW-Authenticate"))
                            .isEqualTo("Bearer resource_metadata=\"" + AUDIENCE + metadata + "\"");
                    assertThat(perform(mvc, "/me?other=1", null).getResponse().getHeader("WWW-Authenticate"))
                            .isEqualTo("Bearer");
                    assertThat(perform(mvc, "/me", token(zone, "read", identifier))
                                    .getResponse()
                                    .getStatus())
                            .isEqualTo(200);
                    var rejected =
                            perform(mvc, "/me", token(zone, "read", AUDIENCE)).getResponse();
                    assertThat(rejected.getStatus()).isEqualTo(401);
                    assertThat(rejected.getHeader("WWW-Authenticate"))
                            .contains("error=\"invalid_token\"", AUDIENCE + metadata);
                    var document = perform(mvc, metadata, null);
                    assertThat(document.getResponse().getStatus()).isEqualTo(200);
                    assertThat(body(document)).contains("\"resource\":\"" + identifier + "\"");
                    assertThat(perform(mvc, "/.well-known/oauth-protected-resource/other", null)
                                    .getResponse()
                                    .getStatus())
                            .isEqualTo(404);
                },
                "keycard.resource-identifier=" + identifier);
    }

    @Test
    @DisplayName("per-zone verification applies the application's JWT authority converter")
    void perZoneAuthorityConverter() {
        URI base = URI.create("https://keycard.example");
        URI issuer = URI.create("https://a.keycard.example");
        String resource = AUDIENCE + "/me";
        AuthProvider provider = AuthProvider.builder(base)
                .resourceIdentifiersByZone(Map.of("a", resource))
                .transport(request -> {
                    String body = request.uri().getPath().equals(StubZone.JWKS_PATH)
                            ? new JWKSet(KEY.toPublicJWK()).toString()
                            : JSONObjectUtils.toJSONString(
                                    Map.of("issuer", issuer.toString(), "jwks_uri", issuer + StubZone.JWKS_PATH));
                    return new TransportResponse(200, Map.of(), body);
                })
                .build();
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> List.of(new SimpleGrantedAuthority("SCOPE_admin")));
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(KeycardAutoConfiguration.class))
                .withPropertyValues("keycard.zone-url=" + base)
                .withBean(AuthProvider.class, () -> provider)
                .withBean(ZoneResolver.class, () -> request -> issuer)
                .withBean(JwtAuthenticationConverter.class, () -> converter)
                .withUserConfiguration(ScopedChain.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    MockMvc mvc = MockMvcBuilders.webAppContextSetup(context)
                            .apply(SecurityMockMvcConfigurers.springSecurity())
                            .build();
                    MvcResult result = perform(mvc, "/me", token(issuer, "read", resource));
                    assertThat(result.getResponse().getStatus()).isEqualTo(200);
                    assertThat(body(result)).contains("SCOPE_admin").doesNotContain("SCOPE_read");
                });
    }

    @Test
    @DisplayName("row 8g (bearer middleware): Spring unrestricted mode never advertises protected-resource discovery")
    void explicitUnrestricted() {
        withApp(
                DefaultChain.class,
                (zone, mvc) -> {
                    assertThat(perform(mvc, "/me", token(zone, "read", "urn:example:other"))
                                    .getResponse()
                                    .getStatus())
                            .isEqualTo(200);
                    assertThat(perform(mvc, "/me", null).getResponse().getHeader("WWW-Authenticate"))
                            .isEqualTo("Bearer");
                    assertThat(perform(mvc, "/.well-known/oauth-protected-resource/me", null)
                                    .getResponse()
                                    .getStatus())
                            .isEqualTo(404);
                },
                "keycard.allow-any-audience=true");
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
    @DisplayName("an inspectable JWT decoder must enforce the configured binding")
    void decoderMustMatchExplicitBinding() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues("keycard.resource-identifier=" + AUDIENCE + "/me")
                    .withBean(
                            JwtDecoder.class,
                            () -> new KeycardJwtDecoder(TokenVerifier.builder(zone.issuer())
                                    .allowAnyAudience()
                                    .build()))
                    .withUserConfiguration(DefaultChain.class)
                    .run(context -> assertThat(context)
                            .hasFailed()
                            .getFailure()
                            .hasRootCauseMessage(
                                    "the token verifier does not enforce the configured resource binding"));
        }
    }

    @Test
    @DisplayName("an unused Keycard binding does not validate an independent security chain's decoder")
    void unusedBindingDoesNotValidateDecoder() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues("keycard.resource-identifier=" + AUDIENCE + "/me")
                    .withBean(
                            JwtDecoder.class,
                            () -> new KeycardJwtDecoder(TokenVerifier.builder(zone.issuer())
                                    .audiences(AUDIENCE)
                                    .build()))
                    .withUserConfiguration(IndependentChain.class)
                    .run(context -> {
                        assertThat(context).hasNotFailed().hasSingleBean(KeycardResourceServer.class);
                        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context)
                                .apply(SecurityMockMvcConfigurers.springSecurity())
                                .build();
                        assertThat(perform(mvc, "/me", token(zone, "read", AUDIENCE))
                                        .getResponse()
                                        .getStatus())
                                .isEqualTo(200);
                    });
        }
    }

    @Test
    @DisplayName("a provider's introspection opt-in validates only chains that apply Keycard")
    void unusedIntrospectionDoesNotValidateIndependentDecoder() {
        try (StubZone zone = zone()) {
            KeycardJwtDecoder independentDecoder = new KeycardJwtDecoder(
                    TokenVerifier.builder(zone.issuer()).audiences(AUDIENCE).build());
            var configured = runner(zone)
                    .withBean(JwtDecoder.class, () -> independentDecoder::decode)
                    .withBean(
                            AuthProvider.class,
                            () -> AuthProvider.builder(IntrospectionStub.issuer(zone))
                                    .resourceIdentifier(AUDIENCE + "/me")
                                    .credential(ClientSecret.of("owner", "secret"))
                                    .introspect(true)
                                    .transport(IntrospectionStub.transport(zone))
                                    .build());
            configured.withUserConfiguration(IndependentChain.class).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(KeycardResourceServer.class);
                MockMvc mvc = MockMvcBuilders.webAppContextSetup(context)
                        .apply(SecurityMockMvcConfigurers.springSecurity())
                        .build();
                assertThat(perform(mvc, "/me", token(zone, "read", AUDIENCE))
                                .getResponse()
                                .getStatus())
                        .isEqualTo(200);
                assertThat(zone.requests(PATH)).isEmpty();
            });
            configured.withUserConfiguration(DefaultChain.class).run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure())
                        .hasRootCauseMessage("introspection requires the provider's KeycardJwtDecoder");
            });
        }
    }

    @Test
    @DisplayName("an opaque JWT decoder remains supported in single-resource mode")
    void explicitBindingAllowsOpaqueDecoder() {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues("keycard.resource-identifier=" + AUDIENCE + "/me")
                    .withUserConfiguration(DefaultChain.class, CustomDecoder.class)
                    .run(context -> assertThat(context).hasNotFailed());
        }
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
    @EnableWebMvc
    @EnableWebSecurity
    static class CustomJwtChain extends DefaultChain {

        @Bean
        SecurityFilterChain customJwt(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("custom"))
                    .securityContext(context -> context.requireExplicitSave(false)
                            .securityContextRepository(new HttpSessionSecurityContextRepository()))
                    .oauth2ResourceServer(server -> server.jwt(jwt ->
                            jwt.jwtAuthenticationConverter(decoded -> UsernamePasswordAuthenticationToken.authenticated(
                                    decoded, null, List.of(new SimpleGrantedAuthority("custom"))))))
                    .with(keycard, Customizer.withDefaults())
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class CustomPrincipalChain {

        @Bean
        SecurityFilterChain customPrincipal(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("custom"))
                    .oauth2ResourceServer(server -> server.jwt(jwt ->
                            jwt.jwtAuthenticationConverter(decoded -> UsernamePasswordAuthenticationToken.authenticated(
                                    decoded.getSubject(), null, List.of(new SimpleGrantedAuthority("custom"))))))
                    .with(keycard, Customizer.withDefaults())
                    .build();
        }

        @Bean
        PrincipalApi principalApi() {
            return new PrincipalApi();
        }
    }

    @RestController
    static class PrincipalApi {

        @GetMapping("/me")
        String me(@AuthenticationPrincipal String principal) {
            return principal;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class IndependentChain extends DefaultChain {

        @Bean
        SecurityFilterChain independent(HttpSecurity http, JwtDecoder decoder) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                    .oauth2ResourceServer(server -> server.jwt(jwt -> jwt.decoder(decoder)))
                    .build();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class PublicChain extends DefaultChain {

        @Bean
        SecurityFilterChain open(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.requestMatchers("/public/**")
                            .permitAll()
                            .anyRequest()
                            .authenticated())
                    .with(keycard, Customizer.withDefaults())
                    .build();
        }

        @Bean
        Pings pings() {
            return new Pings();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    static class MixedChain extends DefaultChain {

        @Bean
        SecurityFilterChain mixed(HttpSecurity http, KeycardResourceServer keycard) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.requestMatchers("/public/**")
                            .permitAll()
                            .requestMatchers("/admin/**")
                            .hasRole("ADMIN")
                            .anyRequest()
                            .authenticated())
                    .httpBasic(Customizer.withDefaults())
                    .csrf(csrf -> csrf.disable())
                    .with(keycard, Customizer.withDefaults())
                    .build();
        }

        @Bean
        org.springframework.security.core.userdetails.UserDetailsService users() {
            return new org.springframework.security.provisioning.InMemoryUserDetailsManager(
                    org.springframework.security.core.userdetails.User.withUsername("admin")
                            .password("{noop}pw")
                            .roles("ADMIN")
                            .build());
        }

        @Bean
        Pings pings() {
            return new Pings();
        }
    }

    @RestController
    static class Pings {

        @GetMapping({"/public/ping", "/admin/ping"})
        String ping() {
            return "pong";
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
        withApp(app, check, "keycard.audiences=" + AUDIENCE);
    }

    private static void withApp(Class<?> app, MvcCheck check, String... properties) {
        try (StubZone zone = zone()) {
            runner(zone)
                    .withPropertyValues(properties)
                    .withUserConfiguration(app)
                    .run(context -> {
                        assertThat(context).hasNotFailed();
                        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context)
                                .apply(SecurityMockMvcConfigurers.springSecurity())
                                .build();
                        check.check(zone, mvc);
                    });
        }
    }

    private static void withIntrospectionApp(Class<?> app, String introspect, MvcCheck check) {
        withIntrospectionApp(app, introspect, false, check);
    }

    private static void withIntrospectionApp(
            Class<?> app, String introspect, boolean providerIntrospects, MvcCheck check) {
        try (StubZone zone = zone()) {
            IntrospectionStub.discovery(zone, true);
            zone.respond("POST", PATH, 200, "{\"active\":true}");
            var runner = runner(zone)
                    .withPropertyValues("keycard.zone-url=" + IntrospectionStub.issuer(zone))
                    .withBean(
                            AuthProvider.class,
                            () -> AuthProvider.builder(IntrospectionStub.issuer(zone))
                                    .resourceIdentifier(AUDIENCE + "/me")
                                    .credential(ClientSecret.of("owner", "secret"))
                                    .introspect(providerIntrospects)
                                    .transport(IntrospectionStub.transport(zone))
                                    .build())
                    .withUserConfiguration(app);
            if (introspect != null) {
                runner = runner.withPropertyValues("keycard.introspect=" + introspect);
            }
            runner.run(context -> {
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
        return token(zone.issuer(), scope, audience);
    }

    private static String token(URI issuer, String scope, String audience) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer.toString());
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
