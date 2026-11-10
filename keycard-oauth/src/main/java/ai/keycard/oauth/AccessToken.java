package ai.keycard.oauth;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A verified bearer token: the compact JWT and its verified claims.
 *
 * <p>Four accessors answer different questions about the caller, and picking the wrong one is a
 * real bug:
 *
 * <ul>
 *   <li>{@link #clientId()} is the OAuth client that authenticated, so it names the credential. It
 *       rotates and does not stably identify an application.
 *   <li>{@link #keycardAppId()} is the stable Keycard application id. Key on it to answer "which
 *       application is calling". For a user agent it equals the client id.
 *   <li>{@link #subject()} is the user on a user-present token and the application on an
 *       application token.
 *   <li>{@link #subjectProfile()} says which of the two it is, {@code user} or {@code app}.
 * </ul>
 *
 * <p>The last two are Keycard claims and are {@code null} on a non-Keycard token.
 *
 * @param token the compact JWT as presented
 * @param claims the verified claims
 */
public record AccessToken(String token, Map<String, Object> claims) {

    /**
     * Freezes the claims.
     *
     * @param token the compact JWT
     * @param claims the verified claims
     */
    public AccessToken {
        Objects.requireNonNull(token, "token");
        claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    /**
     * The token's subject: the user on a user-present token, the application otherwise.
     *
     * @return the {@code sub} claim
     */
    public String subject() {
        return (String) claims.get("sub");
    }

    /**
     * Whether a user authorized this access or an application acts for itself.
     *
     * @return {@code user}, {@code app}, or {@code null} on a non-Keycard token
     */
    public @Nullable String subjectProfile() {
        return claims.get("sub_profile") instanceof String value ? value : null;
    }

    /**
     * The stable Keycard application id.
     *
     * @return the {@code keycard_app_id} claim, or {@code null} on a non-Keycard token
     */
    public @Nullable String keycardAppId() {
        return claims.get("keycard_app_id") instanceof String value ? value : null;
    }

    /**
     * The OAuth client that authenticated: the credential, not the application.
     *
     * @return the {@code client_id} claim
     */
    public String clientId() {
        return (String) claims.get("client_id");
    }

    /**
     * The issuer that minted the token.
     *
     * @return the {@code iss} claim
     */
    public String issuer() {
        return (String) claims.get("iss");
    }

    /**
     * The audiences the token was minted for.
     *
     * @return the {@code aud} claim as a list
     */
    public List<String> audiences() {
        Object aud = claims.get("aud");
        if (aud instanceof String single) {
            return List.of(single);
        }
        List<String> values = new ArrayList<>();
        if (aud instanceof Collection<?> many) {
            for (Object value : many) {
                if (value instanceof String string) {
                    values.add(string);
                }
            }
        }
        return List.copyOf(values);
    }

    /**
     * The granted scopes.
     *
     * @return the space-separated {@code scope} claim as a list, empty when absent
     */
    public List<String> scopes() {
        Object scope = claims.get("scope");
        if (!(scope instanceof String value) || value.isBlank()) {
            return List.of();
        }
        return List.of(value.trim().split("\\s+"));
    }

    /**
     * When the token expires.
     *
     * @return the {@code exp} claim
     */
    public Instant expiresAt() {
        return Instant.ofEpochSecond(((Number) claims.get("exp")).longValue());
    }

    /**
     * Never prints the token.
     *
     * @return the identity claims without the token
     */
    @Override
    public String toString() {
        return "AccessToken[issuer=" + issuer() + ", subject=" + subject() + ", subjectProfile=" + subjectProfile()
                + ", clientId=" + clientId() + ", keycardAppId=" + keycardAppId() + "]";
    }
}
