package example;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.JwtSigner;
import ai.keycard.oauth.SigningKey;
import ai.keycard.oauth.TokenTypes;
import ai.keycard.oauth.testing.StubZone;
import ai.keycard.oauth.testing.StubZone.RecordedRequest;
import ai.keycard.oauth.testing.StubZone.StubResponse;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * Hermetic end-to-end proof of the delegation contract with agent B on a2a-java. A stub zone
 * performs a real RFC 8693 exchange: it checks agent A's client authentication, keeps the user as
 * {@code sub}, re-scopes {@code aud} to the target, and records the caller in {@code act}. No
 * network, no live zone.
 */
public final class SelfTest {

    private static final String AGENT_A_CLIENT = "agent-a";
    private static final String AGENT_A_SECRET = "agent-a-secret";

    private static final List<String> FAILURES = new ArrayList<>();
    private static final HttpClient HTTP =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    private SelfTest() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        RSAKey key = new RSAKeyGenerator(2048).keyID("kid-selftest").generate();
        try (StubZone zone = StubZone.start().serveDiscovery()) {
            zone.respond("GET", StubZone.JWKS_PATH, 200, new JWKSet(key.toPublicJWK()).toString());
            zone.respondWith("POST", StubZone.TOKEN_PATH, request -> exchange(zone, key, request));
            try (Agents agents = Agents.start(zone.issuer(), ClientSecret.of(AGENT_A_CLIENT, AGENT_A_SECRET), 0, 0)) {
                run(zone, key, agents);
            }
        }
        System.out.println(FAILURES.isEmpty() ? "selftest passed" : "selftest FAILED: " + FAILURES);
        System.exit(FAILURES.isEmpty() ? 0 : 1);
    }

    private static void run(StubZone zone, RSAKey key, Agents agents) throws Exception {
        URI a = agents.agentA();
        URI b = agents.agentB();
        String user = sign(key, zone, Map.of("sub", "usr_selftest", "aud", a.toString(), "client_id", "user-app"));

        System.out.println("agent B (a2a-java):");
        HttpResponse<String> card = get(b.resolve("/.well-known/agent-card.json"));
        check("B's card, serialized by a2a-java, names B and a JSONRPC 1.0 interface", () -> card.statusCode() == 200
                && card.body().contains("\"Agent B\"")
                && card.body().contains("JSONRPC"));
        HttpResponse<String> bare = post(b.resolve("/a2a/jsonrpc"), "{}", null);
        check("an unauthenticated call to B is 401 with resource_metadata", () -> bare.statusCode() == 401
                && bare.headers().firstValue("WWW-Authenticate").orElse("").contains("resource_metadata="));
        HttpResponse<String> wrongAudience = post(b.resolve("/a2a/jsonrpc"), "{}", user);
        check("the user's token for A is refused at B", () -> wrongAudience.statusCode() == 401);

        System.out.println("delegation A -> B:");
        HttpResponse<String> delegated = post(a.resolve("/delegate"), "hello", user);
        String reply = delegated.body();
        System.out.println("       B replied: " + reply);
        check("A delegates and returns B's reply", () -> delegated.statusCode() == 200);
        check("B verified the user as sub", () -> reply.contains("sub=usr_selftest"));
        check("B's token is scoped to B", () -> reply.contains("aud=[" + b + "]"));
        check("act names agent A", () -> reply.contains("act={sub=" + AGENT_A_CLIENT + "}"));
        check("a2a-java read a ROLE_USER message with the text", () -> reply.contains("role=ROLE_USER text=hello"));
        check("the exchange sent the user's token as the subject, for B", () -> {
            Map<String, List<String>> form = zone.requests(StubZone.TOKEN_PATH).get(0).formParams();
            return form.get("grant_type").equals(List.of(TokenTypes.TOKEN_EXCHANGE_GRANT))
                    && form.get("subject_token").equals(List.of(user))
                    && form.get("resource").equals(List.of(b.toString()));
        });
    }

    /** A real RFC 8693 exchange: same subject, re-scoped audience, caller appended to act. */
    private static StubResponse exchange(StubZone zone, RSAKey key, RecordedRequest request) {
        String expected = "Basic " + Base64.getEncoder()
                .encodeToString((AGENT_A_CLIENT + ":" + AGENT_A_SECRET).getBytes(StandardCharsets.UTF_8));
        if (!expected.equals(request.header("Authorization"))) {
            return StubResponse.json(401, "{\"error\":\"invalid_client\"}");
        }
        Map<String, List<String>> form = request.formParams();
        try {
            Map<String, Object> subject = claims(form.get("subject_token").get(0));
            Map<String, Object> act = new LinkedHashMap<>();
            act.put("sub", AGENT_A_CLIENT);
            if (subject.get("act") != null) {
                act.put("act", subject.get("act"));
            }
            Map<String, Object> issued = new LinkedHashMap<>();
            issued.put("sub", subject.get("sub"));
            issued.put("aud", form.get("resource").get(0));
            issued.put("client_id", AGENT_A_CLIENT);
            issued.put("act", act);
            return StubResponse.json(
                    200,
                    "{\"access_token\":\"" + sign(key, zone, issued)
                            + "\",\"token_type\":\"Bearer\",\"expires_in\":300,"
                            + "\"issued_token_type\":\"" + TokenTypes.ACCESS_TOKEN + "\"}");
        } catch (Exception e) {
            return StubResponse.json(400, "{\"error\":\"invalid_grant\"}");
        }
    }

    private static String sign(RSAKey key, StubZone zone, Map<String, Object> extra) throws Exception {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", zone.issuer().toString());
        claims.put("iat", now);
        claims.put("exp", now + 300);
        claims.putAll(extra);
        return JwtSigner.of(new SigningKey(key.toRSAPrivateKey(), key.getKeyID(), null)).sign(claims);
    }

    private static Map<String, Object> claims(String jwt) throws Exception {
        return JSONObjectUtils.parse(
                new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> get(URI uri) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(uri).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(URI uri, String body, String bearer) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
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
