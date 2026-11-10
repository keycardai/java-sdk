package example;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hermetic end-to-end proof: a stub zone (real RSA key, discovery, JWKS and a token endpoint),
 * this example's server against it, and the MCP SDK's own client calling both tools through the
 * bearer filter and the grant. No network, no live zone.
 */
public final class SelfTest {

    private static final String DOWNSTREAM = "https://ledger.selftest";
    private static final String DENIED = "https://denied.selftest";
    private static final String SCOPE = "mcp:tools";

    private SelfTest() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-selftest").generate();
        int code;
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(key.toPublicJWK()).toString());
            zone.respondWith("POST", StubZone.TOKEN_PATH, request -> request.formParams()
                            .get("resource")
                            .contains(DENIED)
                    ? StubResponse.json(400, "{\"error\":\"invalid_target\"}")
                    : StubResponse.json(
                            200,
                            "{\"access_token\":\"" + unsigned(Map.of("sub", "usr_selftest", "aud", DOWNSTREAM))
                                    + "\",\"token_type\":\"Bearer\",\"expires_in\":300}"));

            String resourceId = "http://127.0.0.1/mcp";
            Server.Config config = new Server.Config(
                    zone.issuer(),
                    "127.0.0.1",
                    0,
                    resourceId,
                    ClientSecret.of("cid", "csecret"),
                    List.of(DOWNSTREAM, DENIED),
                    List.of(SCOPE));
            try (Server server = Server.start(config)) {
                code = run(new Driver(server.url("/")), zone, key, resourceId);
            }
        }
        System.exit(code);
    }

    private static int run(Driver driver, StubZone zone, RSAKey key, String resourceId) throws Exception {
        String caller = sign(key, zone, resourceId, SCOPE);
        String wrongScope = sign(key, zone, resourceId, "other");

        System.out.println("contract checks:");
        driver.check("healthz", () -> driver.get("/healthz").statusCode() == 200);
        driver.check("protected-resource metadata names the zone", () -> {
            HttpResponse<String> doc = driver.get("/.well-known/oauth-protected-resource/mcp");
            return doc.statusCode() == 200
                    && doc.body().contains("authorization_servers")
                    && doc.body().contains(zone.issuer().toString());
        });
        driver.check("AS metadata proxied unmodified", () -> {
            HttpResponse<String> doc = driver.get("/.well-known/oauth-authorization-server");
            return doc.statusCode() == 200 && doc.body().contains(zone.url(StubZone.TOKEN_PATH).toString());
        });
        String list = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        HttpResponse<String> bare = driver.postMcp(list, null);
        driver.check("bare POST /mcp is 401", () -> bare.statusCode() == 401);
        driver.check(
                "challenge advertises resource_metadata",
                () -> bare.headers().firstValue("WWW-Authenticate").orElse("").contains("resource_metadata="));
        HttpResponse<String> scoped = driver.postMcp(list, wrongScope);
        driver.check(
                "missing scope is 403 insufficient_scope",
                () -> scoped.statusCode() == 403
                        && scoped.headers().firstValue("WWW-Authenticate").orElse("").contains("insufficient_scope"));
        driver.check("no exchange for rejected calls", () -> zone.requests(StubZone.TOKEN_PATH).isEmpty());

        System.out.println("MCP client checks:");
        McpSyncClient client = driver.client(caller);
        try {
            driver.check("tools/list names both tools", () -> Driver.toolNames(client).containsAll(List.of("whoami", "downstream")));
            driver.check(
                    "whoami sees the verified caller",
                    () -> Driver.text(Driver.call(client, "whoami")).equals("sub=usr_selftest client_id=client_selftest"));
            CallToolResult downstream = Driver.call(client, "downstream");
            String report = Driver.text(downstream);
            driver.check(
                    "downstream reads the grant's token from the transport context",
                    () -> report.contains(DOWNSTREAM + ": sub=usr_selftest aud=" + DOWNSTREAM + " act=null"));
            driver.check(
                    "a denied resource records its error while the other succeeds",
                    () -> report.contains(DENIED + ": failed (invalid_target)") && !Boolean.TRUE.equals(downstream.isError()));
            driver.check("the grant exchanged the caller's token for the downstream resource", () -> {
                Map<String, List<String>> form = zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
                return form.get("subject_token").equals(List.of(caller))
                        && form.get("resource").equals(List.of(DOWNSTREAM));
            });
        } finally {
            client.closeGracefully();
        }
        return driver.finish("selftest");
    }

    private static String sign(RSAKey key, StubZone zone, String audience, String scope) throws Exception {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", zone.issuer().toString());
        claims.put("sub", "usr_selftest");
        claims.put("aud", audience);
        claims.put("client_id", "client_selftest");
        claims.put("scope", scope);
        claims.put("iat", now);
        claims.put("exp", now + 300);
        return JwtSigner.of(new SigningKey(key.toRSAPrivateKey(), key.getKeyID(), null)).sign(claims);
    }

    /** A JWT-shaped downstream token; the tool only decodes its claims. */
    private static String unsigned(Map<String, Object> claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String payload = com.nimbusds.jose.util.JSONObjectUtils.toJSONString(claims);
        return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".";
    }
}
