package ai.keycard.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * A PKCE pair (RFC 7636): a random verifier kept by the client and the challenge sent with the
 * authorization request.
 *
 * @param codeVerifier the verifier, 43 to 128 unreserved characters
 * @param codeChallenge the challenge derived from the verifier
 * @param codeChallengeMethod {@code S256} or {@code plain}
 */
public record Pkce(String codeVerifier, String codeChallenge, String codeChallengeMethod) {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Validates the verifier and method.
     *
     * @param codeVerifier the verifier
     * @param codeChallenge the challenge
     * @param codeChallengeMethod the method
     */
    public Pkce {
        Objects.requireNonNull(codeVerifier, "codeVerifier");
        Objects.requireNonNull(codeChallenge, "codeChallenge");
        Objects.requireNonNull(codeChallengeMethod, "codeChallengeMethod");
        if (codeVerifier.length() < 43 || codeVerifier.length() > 128 || !codeVerifier.matches("[A-Za-z0-9._~-]+")) {
            throw new ConfigurationException("a PKCE verifier is 43 to 128 unreserved characters");
        }
        if (!codeChallengeMethod.equals("S256") && !codeChallengeMethod.equals("plain")) {
            throw new ConfigurationException("codeChallengeMethod must be S256 or plain");
        }
    }

    /**
     * A new S256 pair from 32 random bytes (a 43-character verifier).
     *
     * @return the pair
     */
    public static Pkce generate() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return s256(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /**
     * The S256 pair for a given verifier: the challenge is {@code BASE64URL(SHA-256(verifier))}.
     *
     * @param codeVerifier the verifier
     * @return the pair
     */
    public static Pkce s256(String codeVerifier) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return new Pkce(
                    codeVerifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest), "S256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    /**
     * The plain pair for a given verifier: the challenge is the verifier. Allowed by RFC 7636, not
     * recommended.
     *
     * @param codeVerifier the verifier
     * @return the pair
     */
    public static Pkce plain(String codeVerifier) {
        return new Pkce(codeVerifier, codeVerifier, "plain");
    }

    /**
     * Never prints the verifier.
     *
     * @return the challenge and method
     */
    @Override
    public String toString() {
        return "Pkce[codeChallenge=" + codeChallenge + ", codeChallengeMethod=" + codeChallengeMethod + "]";
    }
}
