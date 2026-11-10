package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.AuthorizationServerMetadata;
import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ClientAuthenticator;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.DeviceAuthorization;
import ai.keycard.oauth.DeviceAuthorizationClient;
import ai.keycard.oauth.DevicePollException;
import ai.keycard.oauth.HttpStatusException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.NetworkException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.OAuthProtocolException;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import ai.keycard.oauth.testing.TestClock;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * device-authorization.md (spec-version 2), Unit Tests table. Row 22 runs with a test credential
 * that signs a fresh assertion per endpoint, standing in for {@code WebIdentity} until SDK-51 lands
 * it. Row 28's caller deadline has no Java counterpart (cancellation is thread interruption), so
 * the row checks that the fetch timeout bounds a poll.
 */
class DeviceAuthorizationConformanceTest {

    private static final URI API = URI.create("https://api.example");
    private static final URI DOCS = URI.create("https://docs.example");
    private static final String AUTHORIZATION = "{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\","
            + "\"verification_uri\":\"https://zone.example/device\","
            + "\"verification_uri_complete\":\"https://zone.example/device?user_code=WDJB-MJHT\","
            + "\"expires_in\":600,\"interval\":5}";
    private static final String TOKEN = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600,"
            + "\"refresh_token\":\"rt\",\"id_token\":\"idt\",\"scope\":\"openid\"}";

    @Test
    @DisplayName("row 1: a credential, scopes and two resources go on the device authorization request")
    void row1() {
        try (StubZone zone = zone()) {
            RecordingAuthenticator credential = new RecordingAuthenticator();
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .credential(credential)
                    .build();

            client.requestDeviceAuthorization(List.of("openid", "read"), List.of(API, DOCS));

            RecordedRequest request =
                    zone.requests(StubZone.DEVICE_AUTHORIZATION_PATH).get(0);
            assertThat(request.method()).isEqualTo("POST");
            assertThat(request.header("X-Test-Auth")).isEqualTo("yes");
            Map<String, List<String>> form = request.formParams();
            assertThat(form.get("client_assertion")).hasSize(1);
            assertThat(form.get("scope")).containsExactly("openid read");
            assertThat(form.get("resource")).containsExactly(API.toString(), DOCS.toString());
            assertThat(form).doesNotContainKey("subject_token_type");
        }
    }

    @Test
    @DisplayName("row 2: a public client sends client_id in the body and no Authorization header")
    void row2() {
        try (StubZone zone = zone()) {
            publicClient(zone).requestDeviceAuthorization(List.of(), List.of());

            RecordedRequest request =
                    zone.requests(StubZone.DEVICE_AUTHORIZATION_PATH).get(0);
            assertThat(request.formParams().get("client_id")).containsExactly("device-cli");
            assertThat(request.header("Authorization")).isNull();
        }
    }

    @Test
    @DisplayName("row 3: both a credential and a client id, or neither, is a configuration error")
    void row3() {
        assertThatThrownBy(() -> DeviceAuthorizationClient.builder(URI.create("https://zone.example"))
                        .credential(new RecordingAuthenticator())
                        .clientId("device-cli")
                        .build())
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> DeviceAuthorizationClient.builder(URI.create("https://zone.example"))
                        .build())
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 4: metadata without device_authorization_endpoint is a configuration error with no request")
    void row4() {
        try (StubZone zone = StubZone.start()) {
            zone.respond(
                    "GET",
                    StubZone.DISCOVERY_PATH,
                    200,
                    "{\"issuer\":\"" + zone.issuer() + "\",\"token_endpoint\":\"" + zone.url(StubZone.TOKEN_PATH)
                            + "\"}");
            DeviceAuthorizationClient client = DeviceAuthorizationClient.builder(zone.issuer())
                    .clientId("device-cli")
                    .build();

            assertThatThrownBy(() -> client.requestDeviceAuthorization(List.of(), List.of()))
                    .isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("device_authorization_endpoint");
            assertThat(zone.requests(StubZone.DEVICE_AUTHORIZATION_PATH)).isEmpty();

            AuthorizationServerMetadata metadata = metadata(zone, false);
            int before = zone.requests().size();
            assertThatThrownBy(() -> DeviceAuthorizationClient.builder(metadata)
                            .clientId("device-cli")
                            .build()
                            .requestDeviceAuthorization(List.of(), List.of()))
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests()).hasSize(before);
        }
    }

    @Test
    @DisplayName("row 5: a missing interval is 5 seconds, and expires_at is the clock's time plus expires_in")
    void row5() {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    StubZone.DEVICE_AUTHORIZATION_PATH,
                    200,
                    "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://zone.example/device\","
                            + "\"expires_in\":900}");
            TestClock[] clock = new TestClock[1];
            DeviceAuthorization authorization = client(zone, clock, new ArrayList<>())
                    .clientId("device-cli")
                    .build()
                    .requestDeviceAuthorization(List.of(), List.of());

            assertThat(authorization.interval()).isEqualTo(Duration.ofSeconds(5));
            assertThat(authorization.expiresAt()).isEqualTo(clock[0].instant().plusSeconds(900));
            assertThat(authorization.verificationUriComplete()).isNull();
        }
    }

    @Test
    @DisplayName("row 6: a response missing user_code is invalid_response")
    void row6() {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    StubZone.DEVICE_AUTHORIZATION_PATH,
                    200,
                    "{\"device_code\":\"dc\",\"verification_uri\":\"https://zone.example/device\",\"expires_in\":900}");

            assertThatThrownBy(() -> publicClient(zone).requestDeviceAuthorization(List.of(), List.of()))
                    .isInstanceOfSatisfying(
                            OAuthProtocolException.class,
                            e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE));
        }
    }

    @Test
    @DisplayName(
            "row 7: poll once sends the device_code grant with the same client authentication and no resource or scope")
    void row7() {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN);
            RecordingAuthenticator credential = new RecordingAuthenticator();
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .credential(credential)
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of("openid"), List.of(API));

            client.pollOnce(authorization);

            RecordedRequest poll = zone.requests(StubZone.TOKEN_PATH).get(0);
            Map<String, List<String>> form = poll.formParams();
            assertThat(form.get("grant_type")).containsExactly("urn:ietf:params:oauth:grant-type:device_code");
            assertThat(form.get("device_code")).containsExactly("dc-1");
            assertThat(form).doesNotContainKeys("resource", "scope", "subject_token_type");
            assertThat(poll.header("X-Test-Auth")).isEqualTo("yes");
            assertThat(form.get("client_assertion")).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 8: authorization_pending twice, then a token: three polls, each after the interval")
    void row8() throws Exception {
        try (StubZone zone = zone()) {
            script(zone, pending(), pending(), StubResponse.json(200, TOKEN));
            List<Duration> waits = new ArrayList<>();
            DeviceAuthorizationClient client =
                    client(zone, new TestClock[1], waits).clientId("device-cli").build();

            TokenResponse token = client.pollUntilDone(client.requestDeviceAuthorization(List.of(), List.of()));

            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(3);
            assertThat(waits).containsExactly(seconds(5), seconds(5), seconds(5));
            assertThat(token.refreshToken()).isEqualTo("rt");
            assertThat(token.idToken()).isEqualTo("idt");
        }
    }

    @Test
    @DisplayName("row 9: slow_down adds 5 seconds to this and every later wait")
    void row9() throws Exception {
        try (StubZone zone = zone()) {
            script(zone, error(400, "slow_down"), pending(), StubResponse.json(200, TOKEN));
            List<Duration> waits = new ArrayList<>();
            DeviceAuthorizationClient client =
                    client(zone, new TestClock[1], waits).clientId("device-cli").build();

            client.pollUntilDone(client.requestDeviceAuthorization(List.of(), List.of()));

            assertThat(waits).containsExactly(seconds(5), seconds(10), seconds(10));
        }
    }

    @Test
    @DisplayName("row 10: access_denied stops the loop and is not retryable")
    void row10() {
        try (StubZone zone = zone()) {
            script(zone, error(400, "access_denied"));
            DeviceAuthorizationClient client = publicClient(zone);
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("access_denied");
                        assertThat(e.retryable()).isFalse();
                    });
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 11: when the clock passes expires_at while pending, the loop stops with expired_token")
    void row11() {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    StubZone.DEVICE_AUTHORIZATION_PATH,
                    200,
                    "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://zone.example/device\","
                            + "\"expires_in\":12,\"interval\":5}");
            zone.respondWith("POST", StubZone.TOKEN_PATH, r -> pending());
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .clientId("device-cli")
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                        assertThat(e.error()).isEqualTo("expired_token");
                        assertThat(e.retryable()).isFalse();
                    });
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(2);
        }
    }

    @Test
    @DisplayName("row 12: expired_token or invalid_grant from the server stops the loop, not retryable")
    void row12() {
        for (String code : List.of("expired_token", "invalid_grant")) {
            try (StubZone zone = zone()) {
                script(zone, error(400, code));
                DeviceAuthorizationClient client = publicClient(zone);
                DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

                assertThatThrownBy(() -> client.pollUntilDone(authorization))
                        .isInstanceOfSatisfying(OAuthErrorException.class, e -> {
                            assertThat(e.error()).isEqualTo(code);
                            assertThat(e.retryable()).isFalse();
                        });
            }
        }
    }

    @Test
    @DisplayName("row 13: a network error exposes twice the interval, a 5xx the interval, and neither polls again")
    void row13() {
        try (StubZone zone = zone()) {
            DeviceAuthorizationClient failing = client(zone, new TestClock[1], new ArrayList<>())
                    .clientId("device-cli")
                    .transport(failTokenEndpoint(KeycardHttpTransport.create()))
                    .build();
            DeviceAuthorization authorization = failing.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> failing.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(DevicePollException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.interval()).isEqualTo(seconds(10));
                        assertThat(e.getCause()).isInstanceOf(NetworkException.class);
                    });

            zone.respond("POST", StubZone.TOKEN_PATH, 500, "oops");
            assertThatThrownBy(() -> publicClient(zone).pollUntilDone(authorization))
                    .isInstanceOfSatisfying(DevicePollException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.interval()).isEqualTo(seconds(5));
                        assertThat(e.getCause()).isInstanceOf(HttpStatusException.class);
                    });
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 14: interrupted during a wait, the loop throws InterruptedException and sends nothing more")
    void row14() {
        try (StubZone zone = zone()) {
            zone.respondWith("POST", StubZone.TOKEN_PATH, r -> pending());
            int[] sleeps = {0};
            DeviceAuthorizationClient client = DeviceAuthorizationClient.builder(zone.issuer())
                    .clientId("device-cli")
                    .sleeper(duration -> {
                        if (++sleeps[0] == 2) {
                            throw new InterruptedException("cancelled");
                        }
                    })
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization)).isInstanceOf(InterruptedException.class);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 15: an authorization rebuilt from persisted fields polls with its device code")
    void row15() throws Exception {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN);
            TestClock[] clock = new TestClock[1];
            DeviceAuthorizationClient client = client(zone, clock, new ArrayList<>())
                    .clientId("device-cli")
                    .build();
            DeviceAuthorization persisted = new DeviceAuthorization(
                    "persisted-code",
                    "U",
                    URI.create("https://zone.example/device"),
                    null,
                    seconds(600),
                    seconds(5),
                    clock[0].instant().plusSeconds(600));

            client.pollUntilDone(persisted);

            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams().get("device_code"))
                    .containsExactly("persisted-code");
            assertThat(persisted.toString()).doesNotContain("persisted-code");
        }
    }

    @Test
    @DisplayName("row 16: slow_down, then a network error, exposes 2 x (interval + 5) with the network error as cause")
    void row16() {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, error(400, "slow_down"));
            KeycardHttpTransport real = KeycardHttpTransport.create();
            int[] polls = {0};
            KeycardHttpTransport transport = request -> {
                if (request.uri().getPath().equals(StubZone.TOKEN_PATH) && ++polls[0] == 2) {
                    throw new NetworkException("connection reset", new IOException("reset"));
                }
                return real.send(request);
            };
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .clientId("device-cli")
                    .transport(transport)
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(DevicePollException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.interval()).isEqualTo(seconds(20));
                        assertThat(e.getCause()).isInstanceOf(NetworkException.class);
                    });
        }
    }

    @Test
    @DisplayName("row 17: a 429 stops the loop, exposes the interval undoubled, with the HTTP error as cause")
    void row17() {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, new StubResponse(429, Map.of(), ""));
            DeviceAuthorizationClient client = publicClient(zone);
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(DevicePollException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.interval()).isEqualTo(seconds(5));
                        assertThat(e.getCause())
                                .isInstanceOfSatisfying(
                                        HttpStatusException.class,
                                        cause -> assertThat(cause.status()).isEqualTo(429));
                    });
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 18: resuming with the interval from row 16's error waits that long first")
    void row18() throws Exception {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKEN);
            List<Duration> waits = new ArrayList<>();
            DeviceAuthorizationClient client =
                    client(zone, new TestClock[1], waits).clientId("device-cli").build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            client.pollUntilDone(authorization, seconds(20));

            assertThat(waits).containsExactly(seconds(20));
        }
    }

    @Test
    @DisplayName("row 19: an interval below the authorization's is a configuration error with no request")
    void row19() {
        try (StubZone zone = zone()) {
            DeviceAuthorizationClient client = publicClient(zone);
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization, seconds(4)))
                    .isInstanceOf(ConfigurationException.class);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName(
            "row 20: interrupted while a poll is in flight, the loop throws InterruptedException and sends nothing more")
    void row20() throws Exception {
        try (StubZone zone = zone()) {
            CountDownLatch arrived = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            zone.respondWith("POST", StubZone.TOKEN_PATH, r -> {
                arrived.countDown();
                await(release);
                return pending();
            });
            DeviceAuthorizationClient client = DeviceAuthorizationClient.builder(zone.issuer())
                    .clientId("device-cli")
                    .sleeper(duration -> {})
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            AtomicReference<Throwable> outcome = new AtomicReference<>();
            Thread poller = new Thread(() -> {
                try {
                    client.pollUntilDone(authorization);
                } catch (Throwable t) {
                    outcome.set(t);
                }
            });
            poller.start();
            assertThat(arrived.await(5, TimeUnit.SECONDS)).isTrue();
            poller.interrupt();
            poller.join(5_000);
            release.countDown();

            assertThat(poller.isAlive()).isFalse();
            assertThat(outcome.get()).isInstanceOf(InterruptedException.class);
            Thread.sleep(200);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
        }
    }

    @Test
    @DisplayName("row 21: an interval longer than the time left ends with expired_token, without waiting or polling")
    void row21() {
        try (StubZone zone = zone()) {
            List<Duration> waits = new ArrayList<>();
            DeviceAuthorizationClient client =
                    client(zone, new TestClock[1], waits).clientId("device-cli").build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization, seconds(601)))
                    .isInstanceOfSatisfying(
                            OAuthErrorException.class,
                            e -> assertThat(e.error()).isEqualTo("expired_token"));
            assertThat(waits).isEmpty();
            assertThat(zone.requests(StubZone.TOKEN_PATH)).isEmpty();
        }
    }

    @Test
    @DisplayName("row 22: each request gets its own assertion, audienced to the endpoint it goes to")
    void row22() throws Exception {
        try (StubZone zone = zone()) {
            script(zone, pending(), StubResponse.json(200, TOKEN));
            RecordingAuthenticator credential = new RecordingAuthenticator();
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .credential(credential)
                    .build();

            client.pollUntilDone(client.requestDeviceAuthorization(List.of(), List.of()));

            List<String> device = zone.requests(StubZone.DEVICE_AUTHORIZATION_PATH)
                    .get(0)
                    .formParams()
                    .get("client_assertion");
            List<String> polls = zone.requests(StubZone.TOKEN_PATH).stream()
                    .map(r -> r.formParams().get("client_assertion").get(0))
                    .toList();
            assertThat(device.get(0)).startsWith("aud=" + zone.url(StubZone.DEVICE_AUTHORIZATION_PATH) + ";");
            assertThat(polls)
                    .hasSize(2)
                    .allSatisfy(a -> assertThat(a).startsWith("aud=" + zone.url(StubZone.TOKEN_PATH) + ";"));
            assertThat(List.of(device.get(0), polls.get(0), polls.get(1))).doesNotHaveDuplicates();
        }
    }

    @Test
    @DisplayName("row 23: a credential without client authentication is a configuration error")
    void row23() {
        Credential exchangeOnly = new Credential() {
            @Override
            public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
                return TokenExchangeRequest.builder(context.subjectToken()).build();
            }
        };
        assertThatThrownBy(() -> DeviceAuthorizationClient.builder(URI.create("https://zone.example"))
                        .credential(exchangeOnly))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("row 24: with two resources, the token is returned without being tied to either")
    void row24() throws Exception {
        try (StubZone zone = zone()) {
            zone.respond(
                    "POST",
                    StubZone.TOKEN_PATH,
                    200,
                    "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"resource\":\"" + API + "\"}");
            DeviceAuthorizationClient client = publicClient(zone);

            TokenResponse token =
                    client.pollUntilDone(client.requestDeviceAuthorization(List.of(), List.of(API, DOCS)));

            assertThat(token.accessToken()).isEqualTo("at");
            assertThat(token.raw()).containsEntry("resource", API.toString());
        }
    }

    @Test
    @DisplayName("row 25: an interval of 0, -1 or \"5\" is invalid_response")
    void row25() {
        for (String interval : List.of("0", "-1", "\"5\"")) {
            try (StubZone zone = zone()) {
                zone.respond(
                        "POST",
                        StubZone.DEVICE_AUTHORIZATION_PATH,
                        200,
                        "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://zone.example/device\","
                                + "\"expires_in\":900,\"interval\":" + interval + "}");

                assertThatThrownBy(() -> publicClient(zone).requestDeviceAuthorization(List.of(), List.of()))
                        .as("interval %s", interval)
                        .isInstanceOfSatisfying(
                                OAuthProtocolException.class,
                                e -> assertThat(e.code()).isEqualTo(OAuthProtocolException.INVALID_RESPONSE));
            }
        }
    }

    @Test
    @DisplayName("row 26: a 503 with temporarily_unavailable exposes the interval with the OAuth error as cause")
    void row26() {
        try (StubZone zone = zone()) {
            zone.respond("POST", StubZone.TOKEN_PATH, error(503, "temporarily_unavailable"));
            DeviceAuthorizationClient client = publicClient(zone);
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization))
                    .isInstanceOfSatisfying(DevicePollException.class, e -> {
                        assertThat(e.retryable()).isTrue();
                        assertThat(e.interval()).isEqualTo(seconds(5));
                        assertThat(e.getCause())
                                .isInstanceOfSatisfying(
                                        OAuthErrorException.class,
                                        cause -> assertThat(cause.error()).isEqualTo("temporarily_unavailable"));
                    });
        }
    }

    @Test
    @DisplayName("row 27: a credential failing on a poll is returned as is, without an interval")
    void row27() {
        try (StubZone zone = zone()) {
            KeycardException broken = new KeycardException("the token source is unavailable");
            URI tokenEndpoint = zone.url(StubZone.TOKEN_PATH);
            RecordingAuthenticator credential = new RecordingAuthenticator() {
                @Override
                public ClientAuthentication authenticate(URI issuer, URI endpoint) {
                    if (endpoint.equals(tokenEndpoint)) {
                        throw broken;
                    }
                    return super.authenticate(issuer, endpoint);
                }
            };
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .credential(credential)
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            assertThatThrownBy(() -> client.pollUntilDone(authorization)).isSameAs(broken);
        }
    }

    @Test
    @DisplayName("row 28: the fetch timeout bounds a poll that never answers; it's a network error at 2 x interval")
    void row28() {
        try (StubZone zone = zone()) {
            CountDownLatch release = new CountDownLatch(1);
            zone.respondWith("POST", StubZone.TOKEN_PATH, r -> {
                await(release);
                return pending();
            });
            DeviceAuthorizationClient client = client(zone, new TestClock[1], new ArrayList<>())
                    .clientId("device-cli")
                    .fetchTimeout(Duration.ofMillis(300))
                    .build();
            DeviceAuthorization authorization = client.requestDeviceAuthorization(List.of(), List.of());

            CompletableFuture<Throwable> outcome = CompletableFuture.supplyAsync(() -> {
                try {
                    client.pollUntilDone(authorization);
                    return null;
                } catch (Throwable t) {
                    return t;
                }
            });
            Throwable thrown = outcome.orTimeout(5, TimeUnit.SECONDS).join();
            release.countDown();

            assertThat(thrown).isInstanceOfSatisfying(DevicePollException.class, e -> {
                assertThat(e.interval()).isEqualTo(seconds(10));
                assertThat(e.getCause()).isInstanceOf(NetworkException.class);
            });
        }
    }

    // --- helpers ---------------------------------------------------------------------------

    private static StubZone zone() {
        StubZone zone = StubZone.start().serveDiscovery();
        zone.respond("POST", StubZone.DEVICE_AUTHORIZATION_PATH, 200, AUTHORIZATION);
        return zone;
    }

    /** A builder whose clock is a test clock and whose sleeper records each wait and advances it. */
    private static DeviceAuthorizationClient.Builder client(StubZone zone, TestClock[] clock, List<Duration> waits) {
        clock[0] = TestClock.start();
        TestClock testClock = clock[0];
        return DeviceAuthorizationClient.builder(zone.issuer()).clock(testClock).sleeper(duration -> {
            waits.add(duration);
            testClock.advance(duration);
        });
    }

    private static DeviceAuthorizationClient publicClient(StubZone zone) {
        return client(zone, new TestClock[1], new ArrayList<>())
                .clientId("device-cli")
                .build();
    }

    private static AuthorizationServerMetadata metadata(StubZone zone, boolean withDevice) {
        AuthorizationServerMetadata discovered =
                AuthorizationServerDiscovery.builder().build().discover(zone.issuer());
        return new AuthorizationServerMetadata(
                discovered.issuer(),
                discovered.tokenEndpoint(),
                null,
                null,
                null,
                null,
                null,
                withDevice ? zone.url(StubZone.DEVICE_AUTHORIZATION_PATH) : null,
                List.of(),
                List.of(),
                List.of(),
                Map.of());
    }

    /** Answers the token endpoint with each response in turn, repeating the last. */
    private static void script(StubZone zone, StubResponse... responses) {
        Deque<StubResponse> queue = new ArrayDeque<>(List.of(responses));
        zone.respondWith("POST", StubZone.TOKEN_PATH, r -> queue.size() > 1 ? queue.poll() : queue.peek());
    }

    private static StubResponse pending() {
        return error(400, "authorization_pending");
    }

    private static StubResponse error(int status, String code) {
        return StubResponse.json(status, "{\"error\":\"" + code + "\"}");
    }

    private static Duration seconds(long seconds) {
        return Duration.ofSeconds(seconds);
    }

    private static KeycardHttpTransport failTokenEndpoint(KeycardHttpTransport real) {
        return request -> {
            if (request.uri().getPath().equals(StubZone.TOKEN_PATH)) {
                throw new NetworkException("connection reset", new IOException("reset"));
            }
            return real.send(request);
        };
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Signs a fresh, endpoint-audienced stand-in assertion per call and adds a marker header. */
    static class RecordingAuthenticator implements Credential, ClientAuthenticator {

        @Override
        public ClientAuthentication authenticate(URI issuer, URI endpoint) {
            return new ClientAuthentication(
                    Map.of("X-Test-Auth", "yes"),
                    Map.of(
                            "client_assertion_type",
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            "client_assertion",
                            "aud=" + endpoint + ";jti=" + UUID.randomUUID()));
        }

        @Override
        public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
            return TokenExchangeRequest.builder(context.subjectToken()).build();
        }
    }
}
