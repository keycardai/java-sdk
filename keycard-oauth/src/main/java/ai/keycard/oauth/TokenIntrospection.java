package ai.keycard.oauth;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * A token introspection response (RFC 7662).
 *
 * <p>An inactive token is a valid result with {@code active == false} and absent optional fields.
 * An active result carries every claim of the verified token: the standard fields are typed below,
 * and all claims (including unknown claims such as {@code act}, {@code sub_profile}, {@code
 * auth_time}, or {@code keycard_app_id}) remain accessible through {@link #raw()} and {@link
 * #get(String)}.
 *
 * @param active whether the token is active, as seen by the calling client
 * @param tokenType the token type, such as {@code Bearer} for an active access token; {@code null}
 *     when absent (for example on a refresh token or an inactive response)
 * @param iss the issuer, or {@code null}
 * @param sub the subject, or {@code null}
 * @param clientId the client to which the token was issued, or {@code null}
 * @param aud the token audiences, normalized to a list; empty when absent
 * @param scope the granted scopes, parsed from the space-separated wire value; empty when absent
 * @param sid the session identifier, or {@code null}
 * @param jti the token identifier, or {@code null}
 * @param iat the issue time, or {@code null}
 * @param exp the expiry time, or {@code null}
 * @param raw the complete response document as parsed
 */
public record TokenIntrospection(
        boolean active,
        @Nullable String tokenType,
        @Nullable String iss,
        @Nullable String sub,
        @Nullable String clientId,
        List<String> aud,
        List<String> scope,
        @Nullable String sid,
        @Nullable String jti,
        @Nullable Instant iat,
        @Nullable Instant exp,
        Map<String, Object> raw) {

    /**
     * Freezes the lists and the raw response document.
     *
     * @param active whether the token is active
     * @param tokenType the token type, or {@code null}
     * @param iss the issuer, or {@code null}
     * @param sub the subject, or {@code null}
     * @param clientId the client identifier, or {@code null}
     * @param aud the token audiences
     * @param scope the granted scopes
     * @param sid the session identifier, or {@code null}
     * @param jti the token identifier, or {@code null}
     * @param iat the issue time, or {@code null}
     * @param exp the expiry time, or {@code null}
     * @param raw the complete response document
     */
    public TokenIntrospection {
        aud = List.copyOf(Objects.requireNonNull(aud, "aud"));
        scope = List.copyOf(Objects.requireNonNull(scope, "scope"));
        raw = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(raw, "raw")));
    }

    /**
     * A claim from the complete response document, including claims this type does not model.
     *
     * @param claim the claim name, such as {@code sub_profile} or {@code act}
     * @return the parsed JSON value, or {@code null} when the response omits it
     */
    public @Nullable Object get(String claim) {
        return raw.get(claim);
    }
}
