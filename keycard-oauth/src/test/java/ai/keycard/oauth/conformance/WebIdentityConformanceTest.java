package ai.keycard.oauth.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.DeviceAuthorizationClient;
import ai.keycard.oauth.FileKeyStorage;
import ai.keycard.oauth.KeyStorage;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.WebIdentity;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.TestClock;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * web-identity.md (spec-version 2), Unit Tests table. {@code audience_config} isn't offered in
 * Java (row 9 holds trivially: the assertion's {@code aud} is always the endpoint URL).
 */
class WebIdentityConformanceTest {

    private static final URI ZONE = URI.create("https://zone.example");
    private static final URI TOKEN_ENDPOINT = URI.create("https://zone.example/oauth/token");
    private static final URI DEVICE_ENDPOINT = URI.create("https://zone.example/oauth/device_authorization");

    @TempDir
    Path dir;

    @Test
    @DisplayName("row 1: first use generates and stores a key; a later use loads the same key")
    void row1() throws Exception {
        WebIdentity first = identity("payments", null);
        RSAKey published = (RSAKey) first.publicJwks().getKeys().get(0);
        Path file = dir.resolve("payments.pem");
        assertThat(file).exists();
        assertThat(Files.readString(file)).startsWith("-----BEGIN PRIVATE KEY-----");
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertThat(Files.getPosixFilePermissions(file))
                    .isEqualTo(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        }

        WebIdentity second = identity("payments", null);
        assertThat(second.publicJwks().getKeys().get(0).getKeyID()).isEqualTo("payments");
        assertThat(((RSAKey) second.publicJwks().getKeys().get(0)).getModulus()).isEqualTo(published.getModulus());
    }

    @Test
    @DisplayName("row 2: an explicit key id wins, else a sanitized server name, else a generated id")
    void row2() {
        assertThat(WebIdentity.builder()
                        .keyId("explicit")
                        .serverName("Ignored Name")
                        .storageDir(dir)
                        .build()
                        .keyId())
                .isEqualTo("explicit");
        assertThat(WebIdentity.builder()
                        .serverName("  Payments API!! v2 ")
                        .storageDir(dir)
                        .build()
                        .keyId())
                .isEqualTo("payments-api-v2");
        String generated = WebIdentity.builder().storageDir(dir).build().keyId();
        assertThat(generated).matches("[0-9a-f-]{36}");
        assertThat(WebIdentity.builder().storageDir(dir).build().keyId()).isNotEqualTo(generated);
    }

    @Test
    @DisplayName("rows 3 and 4: an exchange carries a jwt-bearer assertion with the specified claims and no Basic")
    void rows3and4() throws Exception {
        TestClock clock = TestClock.start();
        WebIdentity identity = WebIdentity.builder()
                .keyId("kid-1")
                .clientId("my-client")
                .storageDir(dir)
                .clock(clock)
                .build();

        TokenExchangeRequest request = identity.prepareTokenExchangeRequest(
                TokenExchangeContext.of("subject", URI.create("https://api.example"), ZONE)
                        .withTokenEndpoint(TOKEN_ENDPOINT));

        assertThat(request.clientAssertionType()).isEqualTo(WebIdentity.ASSERTION_TYPE);
        assertThat(request.subjectTokenType()).isEqualTo(TokenTypes.ACCESS_TOKEN);
        assertThat(request.clientId()).isNull();
        Map<String, Object> claims = verify(identity, request.clientAssertion());
        long now = clock.instant().getEpochSecond();
        assertThat(claims)
                .containsEntry("iss", "my-client")
                .containsEntry("sub", "my-client")
                .containsEntry("aud", TOKEN_ENDPOINT.toString())
                .containsEntry("iat", now)
                .containsEntry("exp", now + 300)
                .containsKey("jti");
    }

    @Test
    @DisplayName("row 5: client authentication contributes no Basic header")
    void row5() {
        ClientAuthentication auth = identity("kid", "my-client").authenticate(ZONE, TOKEN_ENDPOINT);
        assertThat(auth.headers()).isEmpty();
    }

    @Test
    @DisplayName("row 6: the public key set holds the signing key, without private material")
    void row6() {
        WebIdentity identity = identity("kid-6", "my-client");
        RSAKey key = (RSAKey) identity.publicJwks().getKeys().get(0);
        assertThat(key.getKeyID()).isEqualTo("kid-6");
        assertThat(key.isPrivate()).isFalse();
        assertThat(identity.publicJwks().toString()).doesNotContain("\"d\"");
        assertThat(WebIdentity.clientJwksUrl(URI.create("https://api.example/")))
                .isEqualTo(URI.create("https://api.example/.well-known/jwks.json"));
    }

    @Test
    @DisplayName("row 7: client authentication for the device endpoint signs aud = that endpoint, form fields only")
    void row7() throws Exception {
        WebIdentity identity = identity("kid-7", "my-client");
        ClientAuthentication auth = identity.authenticate(ZONE, DEVICE_ENDPOINT);

        assertThat(auth.headers()).isEmpty();
        assertThat(auth.formFields()).containsOnlyKeys("client_assertion", "client_assertion_type");
        Map<String, Object> claims = verify(identity, auth.formFields().get("client_assertion"));
        assertThat(claims)
                .containsEntry("aud", DEVICE_ENDPOINT.toString())
                .containsEntry("iss", "my-client")
                .containsEntry("sub", "my-client");
    }

    @Test
    @DisplayName("row 8: client authentication without a client id is a configuration error and signs nothing")
    void row8() {
        CountingStorage storage = new CountingStorage();
        WebIdentity identity =
                WebIdentity.builder().keyId("kid-8").storage(storage).build();
        assertThatThrownBy(() -> identity.authenticate(ZONE, TOKEN_ENDPOINT))
                .isInstanceOf(ConfigurationException.class);
        assertThat(storage.loads).isZero();
    }

    @Test
    @DisplayName("row 9: the assertion's aud is the endpoint URL, whatever the zone")
    void row9() throws Exception {
        WebIdentity identity = identity("kid-9", "my-client");
        URI other = URI.create("https://zone.example/somewhere/else");
        Map<String, Object> claims =
                verify(identity, identity.authenticate(ZONE, other).formFields().get("client_assertion"));
        assertThat(claims).containsEntry("aud", other.toString());
    }

    @Test
    @DisplayName("row 10: an exchange with a resource client id signs it as iss and sub")
    void row10() throws Exception {
        WebIdentity identity = identity("kid-10", "my-client");
        TokenExchangeRequest request = identity.prepareTokenExchangeRequest(
                new TokenExchangeContext("subject", null, ZONE, "resource-client", TOKEN_ENDPOINT));
        Map<String, Object> claims = verify(identity, request.clientAssertion());
        assertThat(claims).containsEntry("iss", "resource-client").containsEntry("sub", "resource-client");

        WebIdentity anonymous =
                WebIdentity.builder().keyId("kid-10b").storageDir(dir).build();
        assertThatThrownBy(() -> anonymous.prepareTokenExchangeRequest(
                        TokenExchangeContext.of("subject", null, ZONE).withTokenEndpoint(TOKEN_ENDPOINT)))
                .isInstanceOf(ConfigurationException.class);
    }

    @Test
    @DisplayName("every call signs a new jti")
    void freshJti() throws Exception {
        WebIdentity identity = identity("kid-jti", "my-client");
        Object first = verify(
                        identity,
                        identity.authenticate(ZONE, TOKEN_ENDPOINT).formFields().get("client_assertion"))
                .get("jti");
        Object second = verify(
                        identity,
                        identity.authenticate(ZONE, TOKEN_ENDPOINT).formFields().get("client_assertion"))
                .get("jti");
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    @DisplayName("a PKCS#1 key written by the Ruby SDK loads, and so does one in the legacy mcp_keys layout")
    void pkcs1Key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();
        byte[] pkcs1 = pkcs1(key.getEncoded());
        String pem = "-----BEGIN RSA PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pkcs1)
                + "\n-----END RSA PRIVATE KEY-----\n";
        Files.writeString(dir.resolve("ruby-key.pem"), pem);

        RSAKey loaded = (RSAKey)
                identity("ruby-key", "my-client").publicJwks().getKeys().get(0);
        assertThat(loaded.getModulus().decodeToBigInteger()).isEqualTo(key.getModulus());
    }

    @Test
    @DisplayName("device row 22: one flow signs a fresh assertion per request, audienced to each endpoint")
    void deviceFlow() throws Exception {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond(
                    "POST",
                    StubZone.DEVICE_AUTHORIZATION_PATH,
                    200,
                    "{\"device_code\":\"dc\",\"user_code\":\"U\",\"verification_uri\":\"https://z/device\","
                            + "\"expires_in\":600,\"interval\":5}");
            List<String> responses = new ArrayList<>(List.of(
                    "{\"error\":\"authorization_pending\"}", "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}"));
            zone.respondWith(
                    "POST",
                    StubZone.TOKEN_PATH,
                    r -> responses.size() > 1
                            ? StubZone.StubResponse.json(400, responses.remove(0))
                            : StubZone.StubResponse.json(200, responses.get(0)));
            WebIdentity identity = identity("kid-device", "my-client");
            TestClock clock = TestClock.start();
            DeviceAuthorizationClient device = DeviceAuthorizationClient.builder(zone.issuer())
                    .credential(identity)
                    .clock(clock)
                    .sleeper(clock::advance)
                    .build();

            device.pollUntilDone(device.requestDeviceAuthorization(List.of(), List.of()));

            Map<String, Object> deviceClaims = verify(
                    identity,
                    zone.requests(StubZone.DEVICE_AUTHORIZATION_PATH)
                            .get(0)
                            .formParams()
                            .get("client_assertion")
                            .get(0));
            List<Map<String, Object>> pollClaims = new ArrayList<>();
            for (var poll : zone.requests(StubZone.TOKEN_PATH)) {
                pollClaims.add(verify(
                        identity, poll.formParams().get("client_assertion").get(0)));
            }
            assertThat(deviceClaims)
                    .containsEntry(
                            "aud", zone.url(StubZone.DEVICE_AUTHORIZATION_PATH).toString());
            assertThat(pollClaims)
                    .hasSize(2)
                    .allSatisfy(c -> assertThat(c)
                            .containsEntry("aud", zone.url(StubZone.TOKEN_PATH).toString()));
            assertThat(List.of(
                            deviceClaims.get("jti"),
                            pollClaims.get(0).get("jti"),
                            pollClaims.get(1).get("jti")))
                    .doesNotHaveDuplicates();
        }
    }

    @Test
    @DisplayName("a token exchange signs aud = the discovered token endpoint")
    void exchangeThroughClient() throws Exception {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\"}");
            WebIdentity identity = identity("kid-x", "my-client");
            TokenExchangeClient.builder(zone.issuer())
                    .credential(identity)
                    .build()
                    .exchangeToken("subject", URI.create("https://api.example"));

            Map<String, Object> claims = verify(
                    identity,
                    zone.requests(StubZone.TOKEN_PATH)
                            .get(0)
                            .formParams()
                            .get("client_assertion")
                            .get(0));
            assertThat(claims)
                    .containsEntry("aud", zone.url(StubZone.TOKEN_PATH).toString());
            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).header("Authorization"))
                    .isNull();
        }
    }

    private WebIdentity identity(String keyId, @Nullable String clientId) {
        WebIdentity.Builder builder = WebIdentity.builder().keyId(keyId).storage(FileKeyStorage.of(dir));
        if (clientId != null) {
            builder.clientId(clientId);
        }
        return builder.build();
    }

    private static Map<String, Object> verify(WebIdentity identity, String assertion) throws Exception {
        JWSObject jws = JWSObject.parse(assertion);
        RSAKey key = (RSAKey) identity.publicJwks().getKeys().get(0);
        assertThat(jws.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jws.getHeader().getKeyID()).isEqualTo(identity.keyId());
        assertThat(jws.verify(new RSASSAVerifier(key))).isTrue();
        return new HashMap<>(jws.getPayload().toJSONObject());
    }

    /** Pulls the PKCS#1 RSAPrivateKey out of a PKCS#8 encoding: the last OCTET STRING. */
    private static byte[] pkcs1(byte[] pkcs8) {
        int i = pkcs8.length;
        for (int p = 0; p < pkcs8.length - 4; p++) {
            if (pkcs8[p] == 0x04 && (pkcs8[p + 1] & 0xff) == 0x82) {
                i = p;
            }
        }
        int length = ((pkcs8[i + 2] & 0xff) << 8) | (pkcs8[i + 3] & 0xff);
        byte[] out = new byte[length];
        System.arraycopy(pkcs8, i + 4, out, 0, length);
        return out;
    }

    /** Counts loads, to show nothing was signed. */
    static final class CountingStorage implements KeyStorage {

        int loads;

        @Override
        public @Nullable String load(String keyId) {
            loads++;
            return null;
        }

        @Override
        public void store(String keyId, String pem) {}
    }
}
