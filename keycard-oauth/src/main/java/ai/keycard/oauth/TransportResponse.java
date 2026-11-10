package ai.keycard.oauth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * One HTTP response, whatever its status.
 *
 * @param status the HTTP status code
 * @param headers header values keyed by lowercase name
 * @param body the response body as UTF-8, possibly empty
 */
public record TransportResponse(int status, Map<String, List<String>> headers, String body) {

    /**
     * Lowercases the header names and freezes the headers.
     *
     * @param status the HTTP status code
     * @param headers header values keyed by name, in any case
     * @param body the response body
     */
    public TransportResponse {
        Map<String, List<String>> normalized = new LinkedHashMap<>();
        headers.forEach((name, values) -> normalized.put(name.toLowerCase(Locale.ROOT), List.copyOf(values)));
        headers = Collections.unmodifiableMap(normalized);
    }

    /**
     * Whether the status is 2xx.
     *
     * @return {@code true} for 200 to 299
     */
    public boolean isSuccess() {
        return status >= 200 && status <= 299;
    }

    /**
     * The first value of a header.
     *
     * @param name the header name, in any case
     * @return the value, or {@code null} when the header is absent
     */
    public @Nullable String header(String name) {
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        return values == null || values.isEmpty() ? null : values.get(0);
    }
}
