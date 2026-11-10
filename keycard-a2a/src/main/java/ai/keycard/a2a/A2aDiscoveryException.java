package ai.keycard.a2a;

import ai.keycard.oauth.KeycardException;
import org.jspecify.annotations.Nullable;

/**
 * An agent card couldn't be fetched, wasn't JSON, or had no {@code name}. Retryable when the cause
 * was a network failure, a 5xx or a 429.
 */
public final class A2aDiscoveryException extends KeycardException {

    private static final long serialVersionUID = 1L;

    A2aDiscoveryException(String message, @Nullable Throwable cause, boolean retryable) {
        super(message, cause, retryable);
    }
}
