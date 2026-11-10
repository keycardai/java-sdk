package example;

import ai.keycard.oauth.ClientRegistrationClient;
import ai.keycard.oauth.ClientRegistrationRequest;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.CredentialDiscovery;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.RegisteredClient;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenResponse;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Live rows for credential discovery and dynamic client registration. Prints claims and ids only,
 * never a token or secret.
 *
 * <ul>
 *   <li>credential-discovery integration row 2: the engine's credential is discovered from {@code
 *       KEYCARD_*} variables naming a projected token file, then exchanges the user's token.
 *   <li>dynamic-client-registration rows 1 and 2: register a public client, then send metadata
 *       the zone should refuse.
 * </ul>
 */
public final class OnboardingE2e {

    private OnboardingE2e() {}

    public static void main(String[] args) throws Exception {
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        List<String> failures = new ArrayList<>();

        // The same variables a pod would carry; discovery reads the map it's given.
        Map<String, String> pod = Map.of(
                "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE", Env.require("SVID_FILE"),
                "KEYCARD_CLIENT_ID", Env.require("ENGINE_V2_CLIENT_ID"));
        Credential credential = CredentialDiscovery.discover(pod);
        String user = Files.readString(Path.of(Env.require("SUBJECT_TOKEN_FILE"))).strip();
        try {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(credential)
                    .build()
                    .exchangeToken(user, Env.uri("LEDGER_RESOURCE"));
            Map<String, Object> claims = Env.claims(issued.accessToken());
            report(failures, true, "discovery row 2: " + credential.getClass().getSimpleName()
                    + " from the environment exchanged a token: aud=" + claims.get("aud") + " act=" + claims.get("act"));
        } catch (Exception e) {
            report(failures, false, "discovery row 2: " + e);
        }

        // credential-discovery row 1: the same process on a laptop, with a client secret
        Map<String, Object> secret = com.nimbusds.jose.util.JSONObjectUtils.parse(
                Files.readString(Path.of(Env.require("ENGINE_SECRET_FILE"))));
        Credential laptop = CredentialDiscovery.discover(Map.of(
                "KEYCARD_CLIENT_ID", (String) secret.get("identifier"),
                "KEYCARD_CLIENT_SECRET", (String) secret.get("password")));
        try {
            TokenResponse issued = TokenExchangeClient.builder(zone)
                    .credential(laptop)
                    .build()
                    .exchangeToken(user, Env.uri("LEDGER_RESOURCE"));
            report(failures, true, "discovery row 1: " + laptop.getClass().getSimpleName()
                    + " from the environment exchanged a token: aud=" + Env.claims(issued.accessToken()).get("aud"));
        } catch (Exception e) {
            report(failures, false, "discovery row 1: " + e);
        }

        ClientRegistrationClient registration = ClientRegistrationClient.builder(zone).build();
        try {
            RegisteredClient client = registration.register(ClientRegistrationRequest.builder()
                    .clientName("java-sdk-live-dcr")
                    .redirectUris(URI.create("http://127.0.0.1:8765/callback"))
                    .grantTypes("authorization_code", "refresh_token")
                    .responseTypes("code")
                    .tokenEndpointAuthMethod("none")
                    .build());
            report(failures, client.clientId() != null, "dcr row 1: registered a public client, client_id="
                    + client.clientId() + ", secret " + (client.clientSecret() == null ? "absent" : "present"));
        } catch (Exception e) {
            report(failures, false, "dcr row 1: " + e);
        }
        try {
            RegisteredClient accepted = registration.register(ClientRegistrationRequest.builder()
                    .clientName("java-sdk-live-dcr-invalid")
                    .tokenEndpointAuthMethod("none")
                    .additionalMetadata(Map.of("redirect_uris", List.of("not a url")))
                    .build());
            report(failures, false, "dcr row 2: invalid metadata was accepted as " + accepted.clientId());
        } catch (OAuthErrorException e) {
            report(failures, e.error().equals("invalid_client_metadata") || e.error().equals("invalid_redirect_uri"),
                    "dcr row 2: refused with " + e.error() + " (retryable=" + e.retryable() + ")");
        }

        System.out.println(failures.isEmpty() ? "ALL PASSED" : "FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
