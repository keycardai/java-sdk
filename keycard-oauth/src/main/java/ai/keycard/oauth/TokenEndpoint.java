package ai.keycard.oauth;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** Sends form POSTs to a token endpoint and parses what comes back. Shared by every grant. */
final class TokenEndpoint {

    private TokenEndpoint() {}

    /**
     * POSTs a form with client authentication merged in, and parses the token response.
     *
     * @param operation names the grant in error messages, such as {@code client credentials}
     */
    static TokenResponse post(
            KeycardHttpTransport transport,
            URI endpoint,
            Map<String, List<String>> form,
            ClientAuthentication auth,
            Duration timeout,
            String operation) {
        return post(transport, endpoint, form, auth, timeout, operation, java.util.Set.of());
    }

    /**
     * As {@link #post}, with OAuth error codes this operation treats as permanent on top of base's
     * table, such as {@code invalid_grant} on a refresh.
     */
    static TokenResponse post(
            KeycardHttpTransport transport,
            URI endpoint,
            Map<String, List<String>> form,
            ClientAuthentication auth,
            Duration timeout,
            String operation,
            java.util.Set<String> locallyPermanent) {
        TransportResponse response = send(transport, endpoint, form, auth, timeout);
        if (!response.isSuccess()) {
            throw error(response, operation + " request", locallyPermanent);
        }
        return parseToken(response.body(), operation);
    }

    /** POSTs a form with client authentication merged in, and returns the raw response. */
    static TransportResponse send(
            KeycardHttpTransport transport,
            URI endpoint,
            Map<String, List<String>> form,
            ClientAuthentication auth,
            Duration timeout) {
        Map<String, List<String>> body = new LinkedHashMap<>(form);
        auth.formFields().forEach((name, value) -> body.put(name, List.of(value)));
        TransportRequest request = TransportRequest.post(
                        endpoint, "application/x-www-form-urlencoded", encode(body), timeout)
                .withHeader("Accept", "application/json");
        for (Map.Entry<String, String> header : auth.headers().entrySet()) {
            request = request.withHeader(header.getKey(), header.getValue());
        }
        return transport.send(request);
    }

    static String encode(Map<String, List<String>> form) {
        StringBuilder out = new StringBuilder();
        form.forEach((name, values) -> {
            for (String value : values) {
                if (out.length() > 0) {
                    out.append('&');
                }
                out.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
                        .append('=')
                        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
            }
        });
        return out.toString();
    }

    /**
     * Classifies a non-2xx response: an RFC 6749 §5.2 error body becomes an {@link
     * OAuthErrorException}, anything else an {@link HttpStatusException}.
     */
    static HttpStatusException error(TransportResponse response, String what) {
        return error(response, what, java.util.Set.of());
    }

    static HttpStatusException error(TransportResponse response, String what, java.util.Set<String> locallyPermanent) {
        Map<String, Object> document = parseObjectOrNull(response.body());
        if (document != null && document.get("error") instanceof String code && !code.isEmpty()) {
            String description = stringOrNull(document.get("error_description"));
            String message = what + " failed with " + code + (description == null ? "" : ": " + description);
            return new OAuthErrorException(
                    message,
                    response.status(),
                    response.body(),
                    code,
                    description,
                    stringOrNull(document.get("error_uri")),
                    !OAuthErrorCodes.isPermanent(code) && !locallyPermanent.contains(code));
        }
        return new HttpStatusException(
                what + " returned HTTP " + response.status(), response.status(), response.body());
    }

    static TokenResponse parseToken(String body, String operation) {
        Map<String, Object> document = parseObjectOrNull(body);
        if (document == null) {
            throw invalid(operation + " response is not a JSON object");
        }
        if (!(document.get("access_token") instanceof String accessToken) || accessToken.isEmpty()) {
            throw invalid(operation + " response has no access_token");
        }
        Object tokenType = document.get("token_type");
        if (tokenType != null && !(tokenType instanceof String)) {
            throw invalid(operation + " response has a token_type that is not a string");
        }
        return new TokenResponse(
                accessToken,
                tokenType == null || ((String) tokenType).isEmpty() ? "Bearer" : (String) tokenType,
                expiresIn(document.get("expires_in"), operation),
                scopes(document.get("scope"), operation),
                optionalString(document, "issued_token_type", operation),
                optionalString(document, "refresh_token", operation),
                optionalString(document, "id_token", operation),
                document);
    }

    private static @Nullable Duration expiresIn(@Nullable Object value, String operation) {
        if (value == null) {
            return null;
        }
        try {
            long seconds = value instanceof Number number
                    ? number.longValue()
                    : value instanceof String string ? Long.parseLong(string.trim()) : -1;
            if (seconds >= 0) {
                return Duration.ofSeconds(seconds);
            }
        } catch (NumberFormatException e) {
            // falls through to the typed error
        }
        throw invalid(operation + " response has an invalid expires_in");
    }

    private static List<String> scopes(@Nullable Object value, String operation) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof String string)) {
            throw invalid(operation + " response has a scope that is not a string");
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : string.trim().split("\\s+")) {
            if (!scope.isEmpty()) {
                scopes.add(scope);
            }
        }
        return scopes;
    }

    private static @Nullable String optionalString(Map<String, Object> document, String field, String operation) {
        Object value = document.get(field);
        if (value == null || value instanceof String) {
            return (String) value;
        }
        throw invalid(operation + " response has a " + field + " that is not a string");
    }

    static @Nullable Map<String, Object> parseObjectOrNull(String body) {
        try {
            return JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            return null;
        }
    }

    private static @Nullable String stringOrNull(@Nullable Object value) {
        return value instanceof String string ? string : null;
    }

    private static OAuthProtocolException invalid(String message) {
        return new OAuthProtocolException(message, OAuthProtocolException.INVALID_RESPONSE);
    }
}
