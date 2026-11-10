package ai.keycard.oauth;

import java.time.Duration;
import java.util.Objects;

/**
 * Device polling stopped on a network error, a 5xx or a 429. The flow can continue: call {@link
 * DeviceAuthorizationClient#pollUntilDone(DeviceAuthorization, Duration)} again with the same
 * authorization and {@link #interval()} until it expires.
 *
 * <p>{@link #getCause()} is the original failure: the {@link NetworkException}, the {@link
 * HttpStatusException}, or the {@link OAuthErrorException} when a 5xx or 429 carried an OAuth
 * error body. Always {@linkplain #retryable() retryable}.
 */
public final class DevicePollException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** The wait before the next poll. */
    private final Duration interval;

    DevicePollException(String message, Duration interval, KeycardException cause) {
        super(message, Objects.requireNonNull(cause, "cause"), true);
        this.interval = Objects.requireNonNull(interval, "interval");
    }

    /**
     * The wait before the next poll: the loop's interval including every {@code slow_down}
     * increase, doubled after a network error (RFC 8628 §3.5).
     *
     * @return the interval to resume with
     */
    public Duration interval() {
        return interval;
    }
}
