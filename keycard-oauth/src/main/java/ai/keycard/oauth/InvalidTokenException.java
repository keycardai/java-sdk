package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * A JWT failed verification: malformed, a disallowed algorithm, an untrusted issuer, a missing
 * required claim, expired or not yet valid, an audience mismatch, no {@code kid}, an unknown key,
 * or a bad signature. One type for every rejection, so callers handle them alike. Never
 * retryable.
 */
public class InvalidTokenException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message why the token was rejected
     */
    public InvalidTokenException(String message) {
        super(message, null, false);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param message why the token was rejected
     * @param cause the underlying failure, or {@code null}
     */
    public InvalidTokenException(String message, @Nullable Throwable cause) {
        super(message, cause, false);
    }
}
