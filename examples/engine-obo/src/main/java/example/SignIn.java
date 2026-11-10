package example;

import ai.keycard.oauth.AuthorizationCodeClient;
import ai.keycard.oauth.TokenResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

/**
 * Signs a user in with the loopback authorization code flow (a public client) and writes the access
 * token to SUBJECT_TOKEN_FILE, readable only by the owner. Prints the claims, never the token.
 */
public final class SignIn {

    public static void main(String[] args) throws Exception {
        AuthorizationCodeClient client = AuthorizationCodeClient.builder(Env.uri("KEYCARD_ZONE_URL"))
                .clientId(Env.require("CLI_CLIENT_ID"))
                .build();
        TokenResponse token = client.authenticate(AuthorizationCodeClient.Loopback.builder()
                .port(8765)
                .resources(Env.uri("ENGINE_RESOURCE"))
                .build());

        Path file = Path.of(Env.require("SUBJECT_TOKEN_FILE"));
        Files.deleteIfExists(file);
        Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(file, token.accessToken());

        Map<String, Object> claims = Env.claims(token.accessToken());
        System.out.println("signed in: sub=" + claims.get("sub") + " sub_profile=" + claims.get("sub_profile")
                + " aud=" + claims.get("aud") + " expires_in=" + token.expiresIn());
    }
}
