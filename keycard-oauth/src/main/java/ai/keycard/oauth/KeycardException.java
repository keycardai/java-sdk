package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * Root of the Keycard exception hierarchy. Every exception a Keycard module throws is a subclass,
 * so {@code catch (KeycardException e)} catches the whole family.
 *
 * <p>Each exception carries a read-only {@link #retryable()} classification: whether repeating the
 * failed operation unchanged could succeed. The value is computed from the failure when the
 * exception is constructed and never changes. The SDK never retries on its own; the
 * classification is input for the caller's retry policy.
 */
public class KeycardException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Whether repeating the failed operation unchanged could succeed. */
    private final boolean retryable;

    /**
     * Creates a non-retryable exception.
     *
     * @param message what went wrong
     */
    public KeycardException(String message) {
        this(message, null, false);
    }

    /**
     * Creates a non-retryable exception with a cause.
     *
     * @param message what went wrong
     * @param cause the underlying failure, or {@code null}
     */
    public KeycardException(String message, @Nullable Throwable cause) {
        this(message, cause, false);
    }

    /**
     * Creates an exception with an explicit classification. Subclasses compute {@code retryable}
     * from the failure they describe.
     *
     * @param message what went wrong
     * @param cause the underlying failure, or {@code null}
     * @param retryable whether repeating the operation unchanged could succeed
     */
    protected KeycardException(String message, @Nullable Throwable cause, boolean retryable) {
        super(message, cause);
        this.retryable = retryable;
    }

    /**
     * Whether repeating the failed operation unchanged could succeed.
     *
     * @return {@code true} for transient failures such as network errors, HTTP 429 and 5xx, and
     *     OAuth error codes outside {@link OAuthErrorCodes#PERMANENT}
     */
    public final boolean retryable() {
        return retryable;
    }
}
