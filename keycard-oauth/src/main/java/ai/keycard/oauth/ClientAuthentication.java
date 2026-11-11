package ai.keycard.oauth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What authenticates a client on one request: headers, form fields, or both. The caller merges
 * these into its own request; client authentication never adds a grant parameter.
 *
 * @param headers headers to set, such as {@code Authorization}
 * @param formFields form fields to add, such as {@code client_assertion}
 */
public record ClientAuthentication(Map<String, String> headers, Map<String, String> formFields) {

    /**
     * Freezes both maps, keeping insertion order.
     *
     * @param headers headers to set
     * @param formFields form fields to add
     */
    public ClientAuthentication {
        headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
        formFields = Collections.unmodifiableMap(new LinkedHashMap<>(formFields));
    }

    /**
     * Authentication carried in one header.
     *
     * @param name the header name
     * @param value the header value
     * @return the authentication
     */
    public static ClientAuthentication header(String name, String value) {
        return new ClientAuthentication(Map.of(name, value), Map.of());
    }

    /**
     * Authentication carried in form fields.
     *
     * @param formFields the fields, in the order to send them
     * @return the authentication
     */
    public static ClientAuthentication formFields(Map<String, String> formFields) {
        return new ClientAuthentication(Map.of(), formFields);
    }

    /**
     * {@code client_secret_basic}: an HTTP Basic header (RFC 7617). Per RFC 6749 section 2.3.1
     * the client id and secret are each percent-encoded before they are joined, so a client id
     * such as {@code urn:app:billing} isn't split at its first colon, and a {@code %} in either
     * isn't read as an escape. Keycard decodes them the same way.
     *
     * @param clientId the client id
     * @param clientSecret the client secret
     * @return the authentication
     */
    public static ClientAuthentication basic(String clientId, String clientSecret) {
        String userPass = percentEncode(clientId) + ":" + percentEncode(clientSecret);
        String encoded = java.util.Base64.getEncoder()
                .encodeToString(userPass.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return header("Authorization", "Basic " + encoded);
    }

    /**
     * Percent-encodes everything but RFC 3986's unreserved characters. Unlike form encoding, a
     * space becomes {@code %20}, never {@code +}: Keycard decodes {@code %XX} and leaves {@code +}
     * as it is, so a {@code +} must be sent as {@code %2B}.
     */
    static String percentEncode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (byte b : value.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '.'
                    || c == '_'
                    || c == '~') {
                out.append(c);
            } else {
                out.append('%')
                        .append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xf, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xf, 16)));
            }
        }
        return out.toString();
    }

    /**
     * Never prints header or field values, which carry secrets and assertions.
     *
     * @return the header and field names only
     */
    @Override
    public String toString() {
        return "ClientAuthentication[headers=" + headers.keySet() + ", formFields=" + formFields.keySet() + "]";
    }
}
