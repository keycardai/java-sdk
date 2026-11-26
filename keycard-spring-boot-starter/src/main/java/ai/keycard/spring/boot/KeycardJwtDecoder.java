package ai.keycard.spring.boot;

import ai.keycard.mcp.ResourceBinding;
import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.TokenVerifier;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;
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
    private final @Nullable URI zone;
    private final ThreadLocal<Consumer<Jwt>> verifiedJwtCapture = new ThreadLocal<>();

    /**
     * A decoder over the verifier.
     *
     * @param verifier the verifier
     */
    public KeycardJwtDecoder(TokenVerifier verifier) {
        this(verifier, null);
    }

    private KeycardJwtDecoder(TokenVerifier verifier, @Nullable URI zone) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.zone = zone;
    }

    KeycardJwtDecoder forZone(URI issuer) {
        return new KeycardJwtDecoder(verifier, issuer);
    }

    void validate(ResourceBinding binding) {
        binding.validate(verifier);
    }

    boolean usesVerifier(TokenVerifier verifier) {
        return this.verifier == verifier;
    }

    @Nullable
    Consumer<Jwt> swapVerifiedJwtCapture(@Nullable Consumer<Jwt> capture) {
        Consumer<Jwt> previous = verifiedJwtCapture.get();
        if (capture == null) {
            verifiedJwtCapture.remove();
        } else {
            verifiedJwtCapture.set(capture);
        }
        return previous;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        AccessToken verified;
        try {
            verified = zone == null ? verifier.verifyToken(token) : verifier.verifyTokenForZone(token, zone);
        } catch (InvalidTokenException e) {
            // Spring puts this message in the challenge's error_description, so keep it fixed: the
            // verifier's own message names the expected issuer and audiences. The cause keeps it
            // for the application's logs.
            throw new BadJwtException("the access token is invalid or expired", e);
        } catch (KeycardException e) {
            throw new ZoneUnavailableException("the zone could not be reached to verify the token", e);
        }
        Map<String, Object> claims = new LinkedHashMap<>(verified.claims());
        convertTime(claims, "exp");
        convertTime(claims, "iat");
        convertTime(claims, "nbf");
        Jwt jwt = new Jwt(token, (Instant) claims.get("iat"), (Instant) claims.get("exp"), header(token), claims);
        Consumer<Jwt> capture = verifiedJwtCapture.get();
        if (capture != null) {
            capture.accept(jwt);
        }
        return jwt;
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
