package ai.keycard.oauth;

import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A token endpoint's successful response, the shape every grant returns.
 *
 * @param accessToken the issued token
 * @param tokenType the token type, {@code Bearer} when the server omits it
 * @param expiresIn the token's lifetime, or {@code null} when the server didn't say
 * @param scope the granted scopes, parsed from the space-separated wire value; empty when omitted
 * @param issuedTokenType the issued token's type (RFC 8693), or {@code null}
 * @param refreshToken a refresh token, or {@code null}
 * @param idToken an OpenID Connect ID token, or {@code null}
 * @param raw the complete response document
 */
public record TokenResponse(
        String accessToken,
        String tokenType,
        @Nullable Duration expiresIn,
        List<String> scope,
        @Nullable String issuedTokenType,
        @Nullable String refreshToken,
        @Nullable String idToken,
        Map<String, Object> raw) {

    /**
     * Freezes the scope list and the raw document.
     *
     * @param accessToken the issued token
     * @param tokenType the token type
     * @param expiresIn the lifetime, or {@code null}
     * @param scope the granted scopes
     * @param issuedTokenType the issued token's type, or {@code null}
     * @param refreshToken the refresh token, or {@code null}
     * @param idToken the ID token, or {@code null}
     * @param raw the complete response
     */
    public TokenResponse {
        Objects.requireNonNull(accessToken, "accessToken");
        Objects.requireNonNull(tokenType, "tokenType");
        scope = List.copyOf(scope);
        raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }

    /**
     * Never prints the access, refresh or ID token.
     *
     * @return the response without its tokens
     */
    @Override
    public String toString() {
        return "TokenResponse[tokenType=" + tokenType + ", expiresIn=" + expiresIn + ", scope=" + scope
                + ", issuedTokenType=" + issuedTokenType + ", refreshToken="
                + (refreshToken == null ? "absent" : "present")
                + ", idToken=" + (idToken == null ? "absent" : "present") + "]";
    }
}
