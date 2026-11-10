package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * Invalid configuration: an empty or malformed issuer, a missing credential, an out-of-range
 * option. Thrown at construction time where possible, and always before any request is sent.
 * Never retryable.
 */
public class ConfigurationException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what is misconfigured
     */
    public ConfigurationException(String message) {
        super(message, null, false);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param message what is misconfigured
     * @param cause the underlying failure, or {@code null}
     */
    public ConfigurationException(String message, @Nullable Throwable cause) {
        super(message, cause, false);
    }
}
