package ai.keycard.spring.boot;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.TokenVerifier;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Spring Security's {@link JwtDecoder}, backed by Keycard's {@link TokenVerifier}: issuer,
 * audience, algorithm and expiry checks, and the JWKS cache, follow Keycard's specs rather than
 * Spring's defaults.
 *
 * <p>An invalid token becomes a {@link BadJwtException} (401 {@code invalid_token}). A zone
 * failure, such as unreachable keys, becomes a {@link ZoneUnavailableException}, which the
 * starter's failure handler answers with 503 {@code temporarily_unavailable} and no challenge.
 */
public final class KeycardJwtDecoder implements JwtDecoder {

    private final TokenVerifier verifier;

    /**
     * A decoder over the verifier.
     *
     * @param verifier the verifier
     */
    public KeycardJwtDecoder(TokenVerifier verifier) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        AccessToken verified;
        try {
            verified = verifier.verifyToken(token);
        } catch (InvalidTokenException e) {
            throw new BadJwtException(e.getMessage(), e);
        } catch (KeycardException e) {
            throw new ZoneUnavailableException("the zone could not be reached to verify the token", e);
        }
        Map<String, Object> claims = new LinkedHashMap<>(verified.claims());
        convertTime(claims, "exp");
        convertTime(claims, "iat");
        convertTime(claims, "nbf");
        return new Jwt(token, (Instant) claims.get("iat"), (Instant) claims.get("exp"), header(token), claims);
    }

    private static void convertTime(Map<String, Object> claims, String name) {
        if (claims.get(name) instanceof Number seconds) {
            claims.put(name, Instant.ofEpochSecond(seconds.longValue()));
        } else if (claims.get(name) instanceof java.util.Date date) {
            claims.put(name, date.toInstant());
        }
    }

    private static Map<String, Object> header(String token) {
        try {
            String encoded = token.substring(0, token.indexOf('.'));
            return JSONObjectUtils.parse(new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new BadJwtException("the token header could not be read", e);
        }
    }

    /** The zone's keys or metadata could not be fetched; the request can be retried. */
    public static final class ZoneUnavailableException extends JwtException {

        private static final long serialVersionUID = 1L;

        ZoneUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
