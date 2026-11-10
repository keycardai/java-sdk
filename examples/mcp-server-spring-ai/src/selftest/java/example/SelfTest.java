package example;

import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * Hermetic end-to-end proof: a stub zone (real RSA key, discovery, JWKS and a token endpoint),
 * this Spring AI app against it, and the MCP SDK's own client calling both tools through Spring
 * Security and the starter. No network, no live zone.
 */
public final class SelfTest {

    static final String DOWNSTREAM = "https://ledger.selftest";
    static final String DENIED = "https://denied.selftest";

    private static final List<String> FAILURES = new ArrayList<>();

    private SelfTest() {}

    public static void main(String[] args) throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-selftest").generate();
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(key.toPublicJWK()).toString());
            zone.respondWith("POST", StubZone.TOKEN_PATH, request -> request.formParams()
                            .get("resource")
                            .contains(DENIED)
                    ? StubResponse.json(400, "{\"error\":\"invalid_target\"}")
                    : StubResponse.json(
                            200,
                            "{\"access_token\":\"" + unsigned(Map.of("sub", "usr_selftest", "aud", DOWNSTREAM))
                                    + "\",\"token_type\":\"Bearer\"}"));
            String resourceId = "http://127.0.0.1/mcp";
            try (ConfigurableApplicationContext app = SpringApplication.run(
                    Application.class,
                    "--server.port=0",
                    "--keycard.zone-url=" + zone.issuer(),
                    "--keycard.audiences=" + resourceId,
                    "--keycard.client-id=cid",
                    "--keycard.client-secret=csecret",
                    "--keycard.scopes-supported=mcp:tools",
                    "--downstream.resources=" + DOWNSTREAM + "," + DENIED)) {
                URI base = URI.create("http://127.0.0.1:" + app.getEnvironment().getProperty("local.server.port"));
                run(base, zone, sign(key, zone, resourceId));
            }
        }
        System.out.println(FAILURES.isEmpty() ? "selftest passed" : "selftest FAILED: " + FAILURES);
        System.exit(FAILURES.isEmpty() ? 0 : 1);
    }

    private static void run(URI base, StubZone zone, String caller) throws Exception {
        HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        System.out.println("contract checks (Spring Security + keycard-spring-boot-starter):");
        HttpResponse<String> prm = http.send(
                HttpRequest.newBuilder(base.resolve("/.well-known/oauth-protected-resource/mcp")).build(),
                HttpResponse.BodyHandlers.ofString());
        check("protected-resource metadata names the zone", () -> prm.statusCode() == 200
                && prm.body().contains(zone.issuer().toString())
                && prm.body().contains(base + "/mcp"));
        HttpResponse<String> as = http.send(
                HttpRequest.newBuilder(base.resolve("/.well-known/oauth-authorization-server")).build(),
                HttpResponse.BodyHandlers.ofString());
        check("AS metadata proxied unmodified", () -> as.statusCode() == 200
                && as.body().contains(zone.url(StubZone.TOKEN_PATH).toString()));
        HttpResponse<String> bare = http.send(
                HttpRequest.newBuilder(base.resolve("/mcp"))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json, text/event-stream")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        check("bare POST /mcp is 401 with resource_metadata", () -> bare.statusCode() == 401
                && bare.headers().firstValue("WWW-Authenticate").orElse("").contains("resource_metadata="));

        System.out.println("MCP client checks (Spring AI 2.0 server):");
        McpSyncClient client = McpClient.sync(HttpClientStreamableHttpTransport.builder(base.toString())
                        .endpoint("/mcp")
                        .requestBuilder(HttpRequest.newBuilder().header("Authorization", "Bearer " + caller))
                        .build())
                .requestTimeout(Duration.ofSeconds(20))
                .build();
        try {
            client.initialize();
            check("tools/list names both tools", () -> client.listTools().tools().stream()
                    .map(Tool::name)
                    .toList()
                    .containsAll(List.of("whoami", "downstream")));
            check("whoami sees the verified caller through the transport context",
                    () -> text(call(client, "whoami")).equals("sub=usr_selftest client_id=client_selftest"));
            CallToolResult downstream = call(client, "downstream");
            String report = text(downstream);
            System.out.println("       downstream: " + report.replace("\n", " | "));
            check("the exchange yields the downstream token's claims",
                    () -> report.contains(DOWNSTREAM + ": sub=usr_selftest aud=" + DOWNSTREAM));
            check("a refused resource is reported while the other succeeds",
                    () -> report.contains(DENIED + ": failed (invalid_target)")
                            && !Boolean.TRUE.equals(downstream.isError()));
            check("the exchange sent the caller's token as the subject",
                    () -> zone.requests(StubZone.TOKEN_PATH).stream()
                            .allMatch(r -> r.formParams().get("subject_token").equals(List.of(caller))));
        } finally {
            client.closeGracefully();
        }
    }

    static CallToolResult call(McpSyncClient client, String tool) {
        return client.callTool(CallToolRequest.builder(tool).arguments(Map.of()).build());
    }

    static String text(CallToolResult result) {
        return result.content().stream()
                .filter(TextContent.class::isInstance)
                .map(c -> ((TextContent) c).text())
                .findFirst()
                .orElse("");
    }

    private static String sign(RSAKey key, StubZone zone, String audience) throws Exception {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", zone.issuer().toString());
        claims.put("sub", "usr_selftest");
        claims.put("aud", audience);
        claims.put("client_id", "client_selftest");
        claims.put("scope", "mcp:tools");
        claims.put("iat", now);
        claims.put("exp", now + 300);
        return JwtSigner.of(new SigningKey(key.toRSAPrivateKey(), key.getKeyID(), null)).sign(claims);
    }

    private static String unsigned(Map<String, Object> claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(JSONObjectUtils.toJSONString(claims).getBytes(StandardCharsets.UTF_8)) + ".";
    }

    private static void check(String name, BooleanSupplier condition) {
        boolean ok;
        try {
            ok = condition.getAsBoolean();
        } catch (RuntimeException e) {
            ok = false;
            name += " (" + e + ")";
        }
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
        if (!ok) {
            FAILURES.add(name);
        }
    }
}
