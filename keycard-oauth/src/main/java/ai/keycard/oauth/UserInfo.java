package ai.keycard.oauth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The signed-in user's identity claims from the UserInfo endpoint (OIDC Core §5.3).
 *
 * @param sub the subject identifier, always present
 * @param claims every claim as returned, {@code sub} included
 */
public record UserInfo(String sub, Map<String, Object> claims) {

    /**
     * Freezes the claims.
     *
     * @param sub the subject
     * @param claims the claims
     */
    public UserInfo {
        Objects.requireNonNull(sub, "sub");
        claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    /**
     * One claim.
     *
     * @param name the claim name, such as {@code email}
     * @return the value, or {@code null} when absent
     */
    public @Nullable Object get(String name) {
        return claims.get(name);
    }
}
