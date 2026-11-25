package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * Thrown when a decoded authorization-server HTTP response body exceeds {@link
 * KeycardHttpTransport#MAX_RESPONSE_BODY_BYTES} while streaming.
 *
 * <p>Retryability is classified from the HTTP status code: {@code 2xx}, {@code 429}, and {@code
 * 5xx} are retryable; other non-2xx statuses (such as {@code 400}) are not.
 */
public final class ResponseBodyTooLargeException extends OAuthProtocolException {

    private static final long serialVersionUID = 1L;

    /** The HTTP status code of the oversized response. */
    private final int status;

    /** The decoded byte limit that was exceeded. */
    private final int limit;

    /** The Retry-After response header, if present. */
    private final @Nullable String retryAfter;

    /**
     * Creates the exception with the default {@link KeycardHttpTransport#MAX_RESPONSE_BODY_BYTES}
     * limit.
     *
     * @param status the HTTP status code of the oversized response
     */
    public ResponseBodyTooLargeException(int status) {
        this(status, KeycardHttpTransport.MAX_RESPONSE_BODY_BYTES);
    }

    /**
     * Creates the exception with an explicit byte limit.
     *
     * @param status the HTTP status code of the oversized response
     * @param limit the decoded byte limit that was exceeded
     */
    public ResponseBodyTooLargeException(int status, int limit) {
        this(status, limit, null);
    }

    ResponseBodyTooLargeException(int status, int limit, @Nullable String retryAfter) {
        super(
                "response body exceeded the " + limit + "-byte decoded size limit (HTTP " + status + ")",
                INVALID_RESPONSE,
                null,
                isRetryableStatus(status));
        this.status = status;
        this.limit = limit;
        this.retryAfter = retryAfter;
    }

    @Nullable
    String retryAfter() {
        return retryAfter;
    }

    /**
     * The HTTP status code of the oversized response.
     *
     * @return the HTTP status code
     */
    public int status() {
        return status;
    }

    /**
     * The decoded byte limit that was exceeded.
     *
     * @return the byte limit
     */
    public int limit() {
        return limit;
    }

    private static boolean isRetryableStatus(int status) {
        return (status >= 200 && status < 300) || status == 429 || status >= 500;
    }
}
