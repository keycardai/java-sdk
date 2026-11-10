package ai.keycard.oauth;

import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * One HTTP request to the authorization server.
 *
 * @param method the HTTP method, such as {@code GET}
 * @param uri the absolute request URL
 * @param headers request headers, in insertion order
 * @param body the request body as UTF-8, or {@code null} for none
 * @param timeout the bound on the whole exchange
 */
public record TransportRequest(
        String method,
        URI uri,
        Map<String, String> headers,
        @Nullable String body,
        Duration timeout) {

    /**
     * Validates the components and freezes the headers.
     *
     * @param method the HTTP method
     * @param uri the absolute request URL
     * @param headers request headers
     * @param body the request body, or {@code null}
     * @param timeout the bound on the whole exchange, which must be positive
     */
    public TransportRequest {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new ConfigurationException("request timeout must be positive, got " + timeout);
        }
        headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    /**
     * A GET request with no headers.
     *
     * @param uri the absolute request URL
     * @param timeout the bound on the whole exchange
     * @return the request
     */
    public static TransportRequest get(URI uri, Duration timeout) {
        return new TransportRequest("GET", uri, Map.of(), null, timeout);
    }

    /**
     * A POST request carrying a body of the given content type.
     *
     * @param uri the absolute request URL
     * @param contentType the body's media type, such as {@code application/x-www-form-urlencoded}
     * @param body the body as UTF-8
     * @param timeout the bound on the whole exchange
     * @return the request
     */
    public static TransportRequest post(URI uri, String contentType, String body, Duration timeout) {
        return new TransportRequest("POST", uri, Map.of("Content-Type", contentType), body, timeout);
    }

    /**
     * A copy of this request with one header added or replaced.
     *
     * @param name the header name
     * @param value the header value
     * @return the new request
     */
    public TransportRequest withHeader(String name, String value) {
        Map<String, String> copy = new LinkedHashMap<>(headers);
        copy.put(name, value);
        return new TransportRequest(method, uri, copy, body, timeout);
    }
}
