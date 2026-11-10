package example;

import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.WorkloadIdentity;
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
 * <p>Each scenario prints PASS or FAIL and the issued token's identity claims, never a token.
 */
public final class LiveE2e {

    private static int failures;

    public static void main(String[] args) throws Exception {
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        URI ledger = Env.uri("LEDGER_RESOURCE");
        String engineApp = Env.require("ENGINE_APP_IDENTIFIER");
        String v2ClientId = Env.require("ENGINE_V2_CLIENT_ID");
        FileTokenSource svid = FileTokenSource.of(Path.of(Env.require("SVID_FILE")));
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

        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
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
