package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.UserInfo;
import ai.keycard.oauth.UserInfoClient;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** userinfo.md, Unit Tests table. */
class UserInfoConformanceTest {

    @Test
    @DisplayName("rows 1 and 6: claims are returned with sub, unknown claims preserved, sent as a Bearer GET")
    void rows1And6() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "GET",
                    StubZone.USERINFO_PATH,
                    200,
                    "{\"sub\":\"user-1\",\"email\":\"a@example.com\",\"groups\":[\"eng\"],\"x_custom\":{\"k\":1}}");

            UserInfo user = UserInfoClient.builder(zone.issuer()).build().userInfo("access-token");

            assertThat(user.sub()).isEqualTo("user-1");
            assertThat(user.get("email")).isEqualTo("a@example.com");
            assertThat(user.claims()).containsKeys("sub", "groups", "x_custom");
            StubZone.RecordedRequest request =
                    zone.requests(StubZone.USERINFO_PATH).get(0);
            assertThat(request.method()).isEqualTo("GET");
            assertThat(request.header("Authorization")).isEqualTo("Bearer access-token");
            assertThat(request.header("Accept")).isEqualTo("application/json");
        }
    }

    @Test
    @DisplayName("row 2: a response without sub is a protocol error")
    void row2() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            for (String body : List.of("{\"email\":\"a@example.com\"}", "not json")) {
                zone.respond("GET", StubZone.USERINFO_PATH, 200, body);

                assertThatThrownBy(() ->
                                UserInfoClient.builder(zone.issuer()).build().userInfo("t"))
                        .as(body)
                        .isInstanceOf(OAuthProtocolException.class);
            }
        }
    }

    @Test
    @DisplayName("row 3: a 401 with an invalid_token challenge is a typed invalid_token error")
    void row3() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "GET",
                    StubZone.USERINFO_PATH,
                    new StubResponse(
                            401,
                            Map.of("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"expired\""),
                            ""));

            assertThatThrownBy(
                            () -> UserInfoClient.builder(zone.issuer()).build().userInfo("t"))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("invalid_token");
                        assertThat(e.errorDescription()).isEqualTo("expired");
                        assertThat(e.status()).isEqualTo(401);
                    });
        }
    }

    @Test
    @DisplayName("row 4: metadata without userinfo_endpoint is a configuration error with no request")
    void row4() {
        try (StubZone zone = StubZone.start()) {
            zone.respond("GET", StubZone.DISCOVERY_PATH, 200, "{\"issuer\":\"" + zone.issuer() + "\"}");

            assertThatThrownBy(
                            () -> UserInfoClient.builder(zone.issuer()).build().userInfo("t"))
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests(StubZone.USERINFO_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 5: an application/jwt response is a protocol error naming the content type")
    void row5() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "GET",
                    StubZone.USERINFO_PATH,
                    new StubResponse(200, Map.of("Content-Type", "application/jwt"), "eyJ.signed.claims"));

            assertThatThrownBy(
                            () -> UserInfoClient.builder(zone.issuer()).build().userInfo("t"))
                    .isInstanceOfSatisfying(OAuthProtocolException.class, e -> {
                        assertThat(e.code()).isEqualTo("unsupported_content_type");
                        assertThat(e.getMessage()).contains("application/jwt");
                    });
        }
    }
}
