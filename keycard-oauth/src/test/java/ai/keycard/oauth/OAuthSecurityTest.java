package ai.keycard.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ai.keycard.oauth.testing.StubZone;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Regression tests for the pre-release adversarial review of keycard-oauth's security paths. */
class OAuthSecurityTest {

    private static final String TOKENS = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":300}";

    @TempDir
    Path dir;

    @Test
    @DisplayName("transport requests and responses describe themselves without header values or bodies")
    void transportToStringRedacts() {
        TransportRequest request = TransportRequest.post(
                        URI.create("https://zone.example/oauth/token"),
                        "application/x-www-form-urlencoded",
                        "subject_token=secret-subject&client_secret=secret-client",
                        Duration.ofSeconds(5))
                .withHeader("Authorization", "Basic c2VjcmV0LWJhc2lj");
        TransportResponse response = new TransportResponse(
                200, Map.of("Set-Cookie", List.of("session=secret-cookie")), "{\"access_token\":\"secret-at\"}");

        assertThat(request.toString())
                .contains("POST", "https://zone.example/oauth/token", "Authorization")
                .doesNotContain("secret", "c2VjcmV0");
        assertThat(response.toString())
                .containsIgnoringCase("set-cookie")
                .contains("200")
                .doesNotContain("secret");
    }

    @Test
    @DisplayName("a header value the JDK refuses is a configuration error that doesn't quote the value")
    void invalidHeaderNotQuoted() {
        TransportRequest request = TransportRequest.get(URI.create("http://127.0.0.1:9/x"), Duration.ofSeconds(1))
                .withHeader("Authorization", "Bearer secret-token\r\nX-Injected: 1");
        assertThatThrownBy(() -> new JdkHttpTransport(HttpClient.newHttpClient()).send(request))
                .isInstanceOf(ConfigurationException.class)
                .satisfies(e -> {
                    assertThat(e.getMessage()).doesNotContain("secret-token");
                    assertThat(e.getCause()).isNull();
                });
    }

    @Test
    @DisplayName("complete() checks state before error: a forged error redirect is a state mismatch")
    void stateCheckedBeforeError() {
        AuthorizationCodeClient client = AuthorizationCodeClient.builder(URI.create("https://zone.example"))
                .clientId("cli")
                .build();
        assertThatThrownBy(() -> client.complete(
                        Map.of("error", "access_denied"), "expected", "verifier", URI.create("http://127.0.0.1/cb")))
                .isInstanceOfSatisfying(
                        OAuthProtocolException.class, e -> assertThat(e.code()).isEqualTo("state_mismatch"));
        assertThatThrownBy(() -> client.complete(
                        Map.of("error", "access_denied", "state", "expected"),
                        "expected",
                        "verifier",
                        URI.create("http://127.0.0.1/cb")))
                .isInstanceOf(OAuthErrorException.class);
    }

    @Test
    @DisplayName("the loopback server ignores wrong-state, wrong-path and non-GET callbacks and waits for the real one")
    void loopbackIgnoresForgedCallbacks() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("POST", StubZone.TOKEN_PATH, 200, TOKENS);
            List<Integer> forged = new ArrayList<>();
            TokenResponse token = AuthorizationCodeClient.builder(zone.issuer())
                    .clientId("cli")
                    .build()
                    .authenticate(AuthorizationCodeClient.Loopback.builder()
                            .browser(url -> {
                                Map<String, String> query = query(url);
                                String redirect = query.get("redirect_uri");
                                String state = query.get("state");
                                forged.add(send("GET", URI.create(redirect + "?error=access_denied&state=wrong")));
                                forged.add(send("GET", URI.create(redirect + "?error=access_denied")));
                                forged.add(send("GET", URI.create(redirect + "/extra?code=evil&state=" + state)));
                                forged.add(send("POST", URI.create(redirect + "?code=evil&state=" + state)));
                                send("GET", URI.create(redirect + "?code=real&state=" + state));
                            })
                            .build());

            assertThat(token.accessToken()).isEqualTo("at");
            assertThat(forged).containsOnly(404);
            assertThat(zone.requests(StubZone.TOKEN_PATH)).hasSize(1);
            assertThat(zone.requests(StubZone.TOKEN_PATH).get(0).formParams()).containsEntry("code", List.of("real"));
        }
    }

    @Test
    @DisplayName("a key file is owner-only and a second store under the same id keeps the first key")
    void keyFileOwnerOnlyAndFirstWins() throws Exception {
        FileKeyStorage storage = FileKeyStorage.of(dir);
        storage.store("k1", "first");
        storage.store("k1", "second");
        assertThat(storage.load("k1")).isEqualTo("first");
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("k1.pem"))))
                    .isEqualTo("rw-------");
        }
        try (var files = Files.list(dir)) {
            assertThat(files.map(p -> p.getFileName().toString())).containsExactly("k1.pem");
        }
    }

    @Test
    @DisplayName("two WebIdentity instances racing on one key id end up signing with the same key")
    void webIdentitiesShareTheStoredKey() {
        WebIdentity a = WebIdentity.builder().keyId("shared").storageDir(dir).build();
        WebIdentity b = WebIdentity.builder().keyId("shared").storageDir(dir).build();
        assertThat(a.publicJwks().getKeys().get(0))
                .isEqualTo(b.publicJwks().getKeys().get(0));
    }

    @Test
    @DisplayName("key ids that aren't plain file names are refused before touching the file system")
    void keyIdTraversalRefused() {
        FileKeyStorage storage = FileKeyStorage.of(dir.resolve("keys"));
        for (String id : List.of("../escape", "a/b", ".hidden", "", "a\\b", "x".repeat(129))) {
            assertThatThrownBy(() -> storage.store(id, "pem")).isInstanceOf(ConfigurationException.class);
            assertThatThrownBy(() -> storage.load(id)).isInstanceOf(ConfigurationException.class);
        }
        assertThat(Files.exists(dir.resolve("escape.pem"))).isFalse();
    }

    @Test
    @DisplayName("a custom key directory never falls back to the legacy ./mcp_keys directory")
    void customDirectoryHasNoLegacyFallback() {
        FileKeyStorage storage = FileKeyStorage.of(dir);
        assertThat(storage.load("anything")).isNull();
        // The default directory still searches the legacy one.
        assertThat(FileKeyStorage.defaultStorage().toString()).contains("server_keys");
    }

    @Test
    @DisplayName("an authorize URL can take its client id from a WebIdentity")
    void webIdentityClientId() {
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            URI url = AuthorizationCodeClient.builder(zone.issuer())
                    .credential(WebIdentity.builder()
                            .keyId("web")
                            .clientId("https://app.example/.well-known/oauth-client")
                            .storageDir(dir)
                            .build())
                    .build()
                    .begin(URI.create("http://127.0.0.1:1/cb"), List.of(), List.of())
                    .url();
            assertThat(query(url)).containsEntry("client_id", "https://app.example/.well-known/oauth-client");
        }
    }

    @Test
    @DisplayName("Basic credentials are percent-encoded per RFC 6749 2.3.1: a colon in the id, %, + and space survive")
    void basicPercentEncoding() {
        String header = ClientAuthentication.basic("urn:app:billing", "p%ss+w rd/é")
                .headers()
                .get("Authorization");
        String decoded = new String(
                java.util.Base64.getDecoder().decode(header.substring("Basic ".length())), StandardCharsets.UTF_8);
        assertThat(decoded).isEqualTo("urn%3Aapp%3Abilling:p%25ss%2Bw%20rd%2F%C3%A9");
        // The server splits at the first colon and decodes each half.
        int colon = decoded.indexOf(':');
        assertThat(URLDecoder.decode(decoded.substring(0, colon).replace("+", "%2B"), StandardCharsets.UTF_8))
                .isEqualTo("urn:app:billing");
        assertThat(URLDecoder.decode(decoded.substring(colon + 1).replace("+", "%2B"), StandardCharsets.UTF_8))
                .isEqualTo("p%ss+w rd/é");
        assertThat(ClientAuthentication.basic("my-client", "s3cret_A.b~")
                        .headers()
                        .get("Authorization"))
                .isEqualTo("Basic "
                        + java.util.Base64.getEncoder()
                                .encodeToString("my-client:s3cret_A.b~".getBytes(StandardCharsets.UTF_8)));
    }

    private static Map<String, String> query(URI url) {
        Map<String, String> params = new LinkedHashMap<>();
        for (String pair : url.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            params.putIfAbsent(
                    URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return params;
    }

    private static int send(String method, URI url) {
        try {
            return HttpClient.newHttpClient()
                    .send(
                            HttpRequest.newBuilder(url)
                                    .method(method, HttpRequest.BodyPublishers.noBody())
                                    .build(),
                            HttpResponse.BodyHandlers.discarding())
                    .statusCode();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
