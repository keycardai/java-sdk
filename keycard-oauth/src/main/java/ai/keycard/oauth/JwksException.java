package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * Resolving a verification key from an issuer's JWKS failed. The subclass says which step:
 * {@link Discovery}, {@link UriValidation}, {@link Fetch} or {@link KeyNotFound}.
 *
 * <p>A bearer-token middleware answers {@link KeyNotFound} with 401 (the zone answered and the key
 * is not there) and the other three with 503 (the token was never judged).
 */
public abstract class JwksException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what failed
     * @param cause the underlying failure, or {@code null}
     * @param retryable whether resolving again unchanged could succeed
     */
    protected JwksException(String message, @Nullable Throwable cause, boolean retryable) {
        super(message, cause, retryable);
    }

    /**
     * Discovery failed or the metadata has no {@code jwks_uri}. Retryable when the discovery
     * failure was.
     */
    public static final class Discovery extends JwksException {

        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message what failed
         * @param cause the discovery failure
         */
        public Discovery(String message, KeycardException cause) {
            super(message, cause, cause.retryable());
        }
    }

    /** The discovered {@code jwks_uri} doesn't share the issuer's origin. Never retryable. */
    public static final class UriValidation extends JwksException {

        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message what was wrong with the URI
         */
        public UriValidation(String message) {
            super(message, null, false);
        }
    }

    /**
     * The JWKS endpoint couldn't be reached, answered non-2xx, or returned a document that isn't a
     * key set. Retryable for network failures, HTTP 429 and 5xx.
     */
    public static final class Fetch extends JwksException {

        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message what failed
         * @param cause the transport, HTTP or parse failure
         * @param retryable whether fetching again could succeed
         */
        public Fetch(String message, @Nullable Throwable cause, boolean retryable) {
            super(message, cause, retryable);
        }
    }

    /**
     * The key set holds no key with the token's {@code kid}, either just fetched or fetched within
     * the refetch cooldown. Not retryable.
     */
    public static final class KeyNotFound extends JwksException {

        private static final long serialVersionUID = 1L;

        /**
         * Creates the exception.
         *
         * @param message which key is missing
         */
        public KeyNotFound(String message) {
            super(message, null, false);
        }
    }
}
