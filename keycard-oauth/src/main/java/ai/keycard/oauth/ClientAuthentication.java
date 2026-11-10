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
     * {@code client_secret_basic}: an HTTP Basic header (RFC 7617).
     *
     * @param clientId the client id
     * @param clientSecret the client secret
     * @return the authentication
     */
    public static ClientAuthentication basic(String clientId, String clientSecret) {
        String encoded = java.util.Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return header("Authorization", "Basic " + encoded);
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
