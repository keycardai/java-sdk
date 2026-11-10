package example;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.AuthorizationServerDiscovery;
import ai.keycard.oauth.AuthorizationServerMetadata;
import ai.keycard.oauth.ClientCredentialsClient;
import ai.keycard.oauth.ClientCredentialsRequest;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.JwksKeyring;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.UserInfoClient;
import ai.keycard.oauth.WorkloadIdentity;
import com.nimbusds.jose.JWSObject;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The core oauth-client, credential and JWT Integration Tests rows against a live zone, as the
 * engine application. Prints claims and codes only, never a token or secret.
 */
public final class CoreE2e {

    private CoreE2e() {}

    public static void main(String[] args) throws Exception {
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        URI ledger = Env.uri("LEDGER_RESOURCE");
        String user = Files.readString(Path.of(Env.require("SUBJECT_TOKEN_FILE"))).strip();
        WorkloadIdentity engine = WorkloadIdentity.builder(FileTokenSource.of(Path.of(Env.require("SVID_FILE"))))
                .clientId(Env.require("ENGINE_V2_CLIENT_ID"))
                .build();
        Map<String, Object> secretDoc = com.nimbusds.jose.util.JSONObjectUtils.parse(
                Files.readString(Path.of(Env.require("ENGINE_SECRET_FILE"))));
        ClientSecret secret = ClientSecret.of((String) secretDoc.get("identifier"), (String) secretDoc.get("password"));
        ClientSecret wrongSecret = ClientSecret.of((String) secretDoc.get("identifier"), "not-the-secret");
        List<String> failures = new ArrayList<>();

        // authorization-server-discovery row 1
        AuthorizationServerMetadata metadata = AuthorizationServerDiscovery.builder().build().discover(zone);
        report(failures,
                metadata.issuer().equals(zone)
                        && metadata.tokenEndpoint() != null
                        && metadata.tokenEndpoint().getHost().equals(zone.getHost())
                        && metadata.jwksUri() != null,
                "discovery row 1: issuer " + metadata.issuer() + ", token and JWKS endpoints on the zone host");

        // jwks-caching row 1, jwt-signing-and-verification row 2
        AtomicInteger fetches = new AtomicInteger();
        KeycardHttpTransport real = KeycardHttpTransport.create();
        KeycardHttpTransport counting = request -> {
            if (request.uri().equals(metadata.jwksUri())) {
                fetches.incrementAndGet();
            }
            return real.send(request);
        };
        JwksKeyring keyring = JwksKeyring.builder().transport(counting).build();
        String kid = JWSObject.parse(user).getHeader().getKeyID();
        keyring.resolve(zone, kid);
        keyring.resolve(zone, kid);
        report(failures, fetches.get() == 1, "jwks-caching row 1: kid " + kid + " resolved twice with "
                + fetches.get() + " JWKS fetch");
        TokenVerifier verifier = TokenVerifier.builder(zone)
                .audiences(Env.require("ENGINE_RESOURCE"))
                .keyring(keyring)
                .build();
        AccessToken verified = verifier.verifyToken(user);
        verifier.verifyToken(user);
        report(failures, fetches.get() == 1, "jwt verification row 2 / jwks-caching row 2: verified sub="
                + verified.subject() + " twice from the cached key");
        expect(failures, "bearer row 2: a token for another audience is rejected", () -> TokenVerifier.builder(zone)
                .audiences(ledger.toString())
                .keyring(keyring)
                .build()
                .verifyToken(user), InvalidTokenException.class, null);

        // token-exchange rows 1 to 3, workload-identity row 1
        TokenExchangeClient exchange = TokenExchangeClient.builder(zone).credential(engine).build();
        TokenResponse issued = exchange.exchangeToken(user, ledger);
        Map<String, Object> claims = Env.claims(issued.accessToken());
        report(failures, ledger.toString().equals(claims.get("aud")) && verified.subject().equals(claims.get("sub")),
                "token-exchange row 1 / workload-identity row 1: aud=" + claims.get("aud") + " sub=" + claims.get("sub"));
        expect(failures, "token-exchange row 2: a malformed subject token", () ->
                exchange.exchangeToken("not.a.token", ledger), OAuthErrorException.class, "invalid_grant");
        expect(failures, "token-exchange row 3: an unregistered resource", () ->
                exchange.exchangeToken(user, URI.create("https://unregistered.java-sdk.test")),
                OAuthErrorException.class, "invalid_target");

        // workload-identity row 2: a platform token for the wrong audience
        WorkloadIdentity wrongAudience = WorkloadIdentity.builder(
                        FileTokenSource.of(Path.of(Env.require("WRONG_AUDIENCE_SVID_FILE"))))
                .clientId(Env.require("ENGINE_V2_CLIENT_ID"))
                .build();
        expect(failures, "workload-identity row 2: a wrong-audience platform token", () ->
                TokenExchangeClient.builder(zone).credential(wrongAudience).build().exchangeToken(user, ledger),
                OAuthErrorException.class, "invalid_client");

        // client-credentials rows 1 and 2, client-secret rows 1 and 2
        TokenResponse own = ClientCredentialsClient.builder(zone)
                .credential(secret)
                .build()
                .requestToken(ClientCredentialsRequest.builder().resource(ledger).build());
        Map<String, Object> ownClaims = Env.claims(own.accessToken());
        report(failures, ledger.toString().equals(ownClaims.get("aud")),
                "client-credentials row 1: the engine's own token, aud=" + ownClaims.get("aud") + " sub="
                        + ownClaims.get("sub"));
        expect(failures, "client-credentials row 2: an invalid client secret", () ->
                ClientCredentialsClient.builder(zone).credential(wrongSecret).build().requestToken(),
                OAuthErrorException.class, "invalid_client");
        TokenResponse bySecret =
                TokenExchangeClient.builder(zone).credential(secret).build().exchangeToken(user, ledger);
        report(failures, ledger.toString().equals(Env.claims(bySecret.accessToken()).get("aud")),
                "client-secret row 1: an exchange authenticated by the client secret");
        expect(failures, "client-secret row 2: an exchange with an invalid secret", () ->
                TokenExchangeClient.builder(zone).credential(wrongSecret).build().exchangeToken(user, ledger),
                OAuthErrorException.class, "invalid_client");

        // impersonation rows 1 and 3: the engine impersonates the user; the ledger sees the user
        TokenResponse impersonated = exchange.impersonate(verified.subject(), ledger);
        Map<String, Object> asUser = Env.claims(impersonated.accessToken());
        report(failures, verified.subject().equals(asUser.get("sub")) && !asUser.containsKey("act"),
                "impersonation row 1: sub=" + asUser.get("sub") + ", act=" + asUser.get("act"));
        AccessToken downstream = TokenVerifier.builder(zone)
                .audiences(ledger.toString())
                .keyring(keyring)
                .build()
                .verifyToken(impersonated.accessToken());
        report(failures, verified.subject().equals(downstream.subject()),
                "impersonation row 3: the ledger's verifier sees sub=" + downstream.subject());

        // impersonation row 2: a client impersonating for a resource it has no dependency on
        WorkloadIdentity gateway = WorkloadIdentity.builder(
                        FileTokenSource.of(Path.of(Env.require("GATEWAY_SVID_FILE"))))
                .clientId(Env.require("GATEWAY_V2_CLIENT_ID"))
                .build();
        expect(failures, "impersonation row 2: the gateway impersonating for the engine's resource", () ->
                TokenExchangeClient.builder(zone)
                        .credential(gateway)
                        .build()
                        .impersonate(verified.subject(), Env.uri("ENGINE_RESOURCE")),
                OAuthErrorException.class, "unauthorized_client");

        // userinfo row 2
        expect(failures, "userinfo row 2: an invalid token", () ->
                UserInfoClient.builder(zone).build().userInfo(issued.accessToken() + "x"),
                OAuthErrorException.class, "invalid_token");

        System.out.println(failures.isEmpty() ? "ALL PASSED" : "FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    @FunctionalInterface
    private interface Call {
        Object run() throws Exception;
    }

    private static void expect(List<String> failures, String name, Call call, Class<?> type, String code) {
        try {
            call.run();
            report(failures, false, name + ": succeeded");
        } catch (Exception e) {
            String got = e instanceof OAuthErrorException oauth ? oauth.error() : e.getClass().getSimpleName();
            boolean ok = type.isInstance(e) && (code == null || code.equals(got));
            report(failures, ok, name + ": " + got);
        }
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
