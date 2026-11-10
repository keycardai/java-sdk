package example;

import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.WorkloadIdentity;
import java.net.URI;
import java.nio.file.Path;

/** Reads the example's configuration from the environment; the SDK itself reads none. */
final class Env {

    private Env() {}

    static String require(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is not set");
        }
        return value;
    }

    static URI uri(String name) {
        return URI.create(require(name));
    }

    /** Agent A's credential: a client secret, or a workload identity token file for a v2 credential. */
    static Credential credential() {
        String clientId = require("KEYCARD_CLIENT_ID");
        String secret = System.getenv("KEYCARD_CLIENT_SECRET");
        if (secret != null && !secret.isBlank()) {
            return ClientSecret.of(clientId, secret);
        }
        return WorkloadIdentity.builder(FileTokenSource.of(Path.of(require("KEYCARD_ASSERTION_FILE"))))
                .clientId(clientId)
                .build();
    }
}
