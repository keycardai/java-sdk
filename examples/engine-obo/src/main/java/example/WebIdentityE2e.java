package example;

import ai.keycard.oauth.ClientAuthentication;
import ai.keycard.oauth.ClientAuthenticator;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.DeviceAuthorization;
import ai.keycard.oauth.DeviceAuthorizationClient;
import ai.keycard.oauth.FileKeyStorage;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenExchangeClient;
import ai.keycard.oauth.TokenExchangeContext;
import ai.keycard.oauth.TokenExchangeRequest;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.WebIdentity;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * web-identity.md Integration Tests and device-authorization.md row 7 against a live zone. The
 * engine application holds a {@code public-key} credential whose {@code jwks_uri} serves this
 * WebIdentity's public key. Prints claims only, never a token or key material.
 *
 * <p>{@code jwks <file>} creates the key (if needed) and writes the public key set; {@code run}
 * runs the rows.
 */
public final class WebIdentityE2e {

    static final String KEY_ID = "java-sdk-web-identity";

    private WebIdentityE2e() {}

    public static void main(String[] args) throws Exception {
        Path keys = Path.of(Env.require("LIVE_DIR"), "web-identity-keys");
        if (args.length == 2 && args[0].equals("jwks")) {
            WebIdentity identity = WebIdentity.builder().keyId(KEY_ID).storage(FileKeyStorage.of(keys)).build();
            Files.writeString(Path.of(args[1]), identity.publicJwks().toString());
            System.out.println("wrote the public key set for kid " + identity.keyId());
            return;
        }
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        String clientId = Env.require("WEB_IDENTITY_CLIENT_ID");
        WebIdentity identity = WebIdentity.builder()
                .keyId(KEY_ID)
                .clientId(clientId)
                .storage(FileKeyStorage.of(keys))
                .build();
        List<String> failures = new ArrayList<>();
        String user = Files.readString(Path.of(Env.require("SUBJECT_TOKEN_FILE"))).strip();
        URI ledger = Env.uri("LEDGER_RESOURCE");

        try {
            TokenResponse issued =
                    TokenExchangeClient.builder(zone).credential(identity).build().exchangeToken(user, ledger);
            Map<String, Object> claims = Env.claims(issued.accessToken());
            report(failures, true, "web identity row 1: exchanged with the registered key: aud=" + claims.get("aud")
                    + " act=" + claims.get("act"));
        } catch (Exception e) {
            report(failures, false, "web identity row 1: " + e);
        }

        WebIdentity rotated = WebIdentity.builder()
                .keyId(KEY_ID + "-rotated")
                .clientId(clientId)
                .storage(FileKeyStorage.of(keys))
                .build();
        expect(failures, "web identity row 2: an unregistered key is invalid_client", "invalid_client", () ->
                TokenExchangeClient.builder(zone).credential(rotated).build().exchangeToken(user, ledger));

        DeviceAuthorizationClient device =
                DeviceAuthorizationClient.builder(zone).credential(identity).build();
        try {
            DeviceAuthorization authorization = device.requestDeviceAuthorization(List.of(), List.of(ledger));
            report(failures, true, "device row 7: device authorization with WebIdentity succeeds: user_code="
                    + authorization.userCode());
        } catch (Exception e) {
            report(failures, false, "device row 7: " + e);
        }
        URI tokenEndpoint = URI.create(zone + "/oauth/2/token");
        DeviceAuthorizationClient wrongAudience = DeviceAuthorizationClient.builder(zone)
                .credential(new TokenEndpointAudience(identity, tokenEndpoint))
                .build();
        expect(failures, "device row 7: an assertion audienced to the token endpoint is invalid_client",
                "invalid_client", () -> wrongAudience.requestDeviceAuthorization(List.of(), List.of(ledger)));

        System.out.println(failures.isEmpty() ? "ALL PASSED" : "FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    /** Signs every assertion for the token endpoint, whatever endpoint the request goes to. */
    private record TokenEndpointAudience(WebIdentity identity, URI tokenEndpoint)
            implements Credential, ClientAuthenticator {

        @Override
        public ClientAuthentication authenticate(URI issuer, URI endpoint) {
            return identity.authenticate(issuer, tokenEndpoint);
        }

        @Override
        public TokenExchangeRequest prepareTokenExchangeRequest(TokenExchangeContext context) {
            return identity.prepareTokenExchangeRequest(context);
        }
    }

    @FunctionalInterface
    private interface Call {
        Object run() throws Exception;
    }

    private static void expect(List<String> failures, String name, String code, Call call) {
        try {
            call.run();
            report(failures, false, name + ": succeeded");
        } catch (OAuthErrorException e) {
            report(failures, e.error().equals(code), name + ": " + e.error());
        } catch (Exception e) {
            report(failures, false, name + ": " + e);
        }
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
