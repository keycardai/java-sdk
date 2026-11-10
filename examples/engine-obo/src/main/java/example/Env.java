package example;

import java.net.URI;
import java.util.Base64;
import java.util.Map;

/** Configuration from the environment, and a claims peek that never prints the token. */
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

    /** The token's payload, decoded without verification, for printing a summary. */
    static Map<String, Object> claims(String jwt) {
        try {
            String payload = jwt.split("\\.")[1];
            return com.nimbusds.jose.util.JSONObjectUtils.parse(
                    new String(Base64.getUrlDecoder().decode(payload), java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("not a JWT", e);
        }
    }
}
