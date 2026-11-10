package example;

import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.IdentityTokenSource;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.WorkloadIdentity;
import ai.keycard.spiffe.SpiffeJwtSvidSource;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * BNY's engine flow against a live zone. A user's access token (minted for the engine's own
 * resource) is exchanged for a token for a downstream resource, with the engine's JWT-SVID:
 *
 * <ol>
 *   <li>as the client assertion only, through a v2 credential (client_id set);
 *   <li>as the client assertion and the actor token, the actor matched by a v1 credential.
 * </ol>
 *
 * <p>The SVID comes from SVID_FILE, or from the SPIFFE Workload API when SVID_SOURCE is
 * {@code workload-api} (socket from SPIFFE_ENDPOINT_SOCKET). Each scenario prints PASS or FAIL and
 * the issued token's identity claims, never a token.
 */
public final class LiveE2e {

    private static int failures;

    public static void main(String[] args) throws Exception {
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        URI ledger = Env.uri("LEDGER_RESOURCE");
        String engineApp = Env.require("ENGINE_APP_IDENTIFIER");
        String v2ClientId = Env.require("ENGINE_V2_CLIENT_ID");
        IdentityTokenSource svid = "workload-api".equals(System.getenv("SVID_SOURCE"))
                ? SpiffeJwtSvidSource.builder(zone.toString()).build()
                : FileTokenSource.of(Path.of(Env.require("SVID_FILE")));
        System.out.println("SVID source: " + svid);
        String subjectToken = Files.readString(Path.of(Env.require("SUBJECT_TOKEN_FILE"))).strip();
        Object user = Env.claims(subjectToken).get("sub");

        WorkloadIdentity engine = WorkloadIdentity.builder(svid).clientId(v2ClientId).build();

        scenario("assertion only, v2 credential", () -> {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(engine)
                    .build()
                    .exchangeToken(subjectToken, ledger);
            return check(issued, user, ledger, engineApp);
        });

        scenario("assertion plus actor token, actor via v1 credential", () -> {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(engine)
                    .actor(svid)
                    .build()
                    .exchangeToken(subjectToken, ledger);
            return check(issued, user, ledger, engineApp);
        });

        if (System.getenv("GATEWAY_V2_CLIENT_ID") != null) {
            twoHops(zone, ledger, engine, svid, subjectToken, user);
        }

        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /**
     * Engine to gateway to ledger. The engine's hop always names itself as actor; the gateway's hop
     * either does too (the chain nests) or doesn't (the zone replaces the chain with the caller).
     */
    private static void twoHops(
            URI zone, URI ledger, WorkloadIdentity engine, IdentityTokenSource engineSvid, String subjectToken, Object user)
            throws Exception {
        URI gatewayResource = Env.uri("GATEWAY_RESOURCE");
        String gatewayApp = Env.require("GATEWAY_APP_IDENTIFIER");
        String engineApp = Env.require("ENGINE_APP_IDENTIFIER");
        FileTokenSource gatewaySvid = FileTokenSource.of(Path.of(Env.require("GATEWAY_SVID_FILE")));
        WorkloadIdentity gateway =
                WorkloadIdentity.builder(gatewaySvid).clientId(Env.require("GATEWAY_V2_CLIENT_ID")).build();

        String hop1 = TokenExchangeClient.builder(zone)
                .credential(engine)
                .actor(engineSvid)
                .build()
                .exchangeToken(subjectToken, gatewayResource)
                .accessToken();

        scenario("two hops, both with actor tokens: act nests gateway over engine", () -> {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(gateway)
                    .actor(gatewaySvid)
                    .build()
                    .exchangeToken(hop1, ledger);
            return chain(issued, user, gatewayApp, engineApp);
        });

        scenario("two hops, second without an actor token: act is replaced by the gateway", () -> {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(gateway)
                    .build()
                    .exchangeToken(hop1, ledger);
            return chain(issued, user, gatewayApp, null);
        });
    }

    /** Checks sub, the top-level actor, and the nested actor (or its absence). */
    private static String chain(TokenResponse issued, Object user, String top, String nested) {
        Map<String, Object> claims = Env.claims(issued.accessToken());
        Object act = claims.get("act");
        String summary = "sub=" + claims.get("sub") + " act=" + act;
        if (!user.equals(claims.get("sub")) || !(act instanceof Map<?, ?> outer) || !top.equals(outer.get("sub"))) {
            return "mismatch " + summary;
        }
        Object inner = outer.get("act");
        boolean innerOk = nested == null
                ? inner == null
                : inner instanceof Map<?, ?> in && nested.equals(in.get("sub"));
        return (innerOk ? "ok " : "mismatch ") + summary;
    }

    private interface Run {
        String run();
    }

    private static void scenario(String name, Run run) {
        try {
            String result = run.run();
            System.out.println((result.startsWith("ok") ? "PASS  " : "FAIL  ") + name + ": " + result);
            if (!result.startsWith("ok")) {
                failures++;
            }
        } catch (OAuthErrorException e) {
            failures++;
            System.out.println("FAIL  " + name + ": " + e.error() + " (" + e.errorDescription() + ")");
        } catch (KeycardException e) {
            failures++;
            System.out.println("FAIL  " + name + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static String check(TokenResponse issued, Object user, URI ledger, String engineApp) {
        Map<String, Object> claims = Env.claims(issued.accessToken());
        Object act = claims.get("act");
        String summary = "sub=" + claims.get("sub") + " aud=" + claims.get("aud") + " client_id="
                + claims.get("client_id") + " keycard_app_id=" + claims.get("keycard_app_id") + " act=" + act;
        boolean subOk = user.equals(claims.get("sub"));
        Object aud = claims.get("aud");
        boolean audOk = aud != null && aud.toString().contains(ledger.toString());
        boolean actOk = act instanceof Map<?, ?> a && a.get("sub") != null;
        return (subOk && audOk && actOk ? "ok " : "mismatch ") + summary;
    }
}
