package ai.keycard.mcp;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.jspecify.annotations.Nullable;

/** Writes RFC 6750 challenges and the 503 outage response. */
final class BearerChallenge {

    static final String PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";

    private BearerChallenge() {}

    /** {@code <origin>/.well-known/oauth-protected-resource}, scheme from X-Forwarded-Proto. */
    static String resourceMetadataUrl(HttpServletRequest request) {
        return origin(request) + PROTECTED_RESOURCE_PATH;
    }

    static String origin(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-Proto");
        String scheme =
                forwarded != null && !forwarded.isBlank() ? forwarded.split(",")[0].trim() : request.getScheme();
        String host = request.getHeader("Host");
        if (host == null || host.isBlank()) {
            int port = request.getServerPort();
            boolean defaultPort = (scheme.equals("https") && port == 443) || (scheme.equals("http") && port == 80);
            host = request.getServerName() + (defaultPort ? "" : ":" + port);
        }
        return scheme + "://" + host;
    }

    /** 401 or 403 with a challenge; {@code error} null for the missing-header case. */
    static void challenge(
            HttpServletRequest request,
            HttpServletResponse response,
            int status,
            @Nullable String error,
            @Nullable String description)
            throws IOException {
        StringBuilder value = new StringBuilder("Bearer ");
        if (error != null) {
            value.append("error=\"").append(error).append("\", ");
            if (description != null) {
                value.append("error_description=\"").append(quote(description)).append("\", ");
            }
        }
        value.append("resource_metadata=\"")
                .append(resourceMetadataUrl(request))
                .append('"');
        response.setHeader("WWW-Authenticate", value.toString());
        json(response, status, error == null ? "{\"error\":\"unauthorized\"}" : "{\"error\":\"" + error + "\"}");
    }

    static void badRequest(HttpServletResponse response, String description) throws IOException {
        json(response, 400, "{\"error\":\"invalid_request\",\"error_description\":\"" + quote(description) + "\"}");
    }

    /** 503 with no challenge: the token was never judged. */
    static void unavailable(HttpServletResponse response) throws IOException {
        json(response, 503, "{\"error\":\"temporarily_unavailable\"}");
    }

    static void json(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }

    /** Keeps a description safe inside a quoted-string: no quotes, backslashes or control characters. */
    private static String quote(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') {
                out.append('\'');
            } else if (c >= 0x20 && c != 0x7f) {
                out.append(c);
            }
        }
        return out.toString();
    }
}
