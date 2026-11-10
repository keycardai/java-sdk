package ai.keycard.oauth;

/**
 * A non-2xx response that is not an OAuth error response. Retryable for HTTP 429 and any 5xx,
 * not for any other status.
 */
public class HttpStatusException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** The HTTP status code. */
    private final int status;
    /** The response body, possibly empty. */
    private final String body;

    /**
     * Creates the exception, classifying it from the status.
     *
     * @param message what failed
     * @param status the HTTP status code
     * @param body the response body, possibly empty
     */
    public HttpStatusException(String message, int status, String body) {
        this(message, status, body, isRetryableStatus(status));
    }

    /**
     * Creates the exception with an explicit classification, for subclasses that classify by
     * something other than the status.
     *
     * @param message what failed
     * @param status the HTTP status code
     * @param body the response body, possibly empty
     * @param retryable whether repeating the operation unchanged could succeed
     */
    protected HttpStatusException(String message, int status, String body, boolean retryable) {
        super(message, null, retryable);
        this.status = status;
        this.body = body;
    }

    /**
     * The HTTP status code.
     *
     * @return the status
     */
    public int status() {
        return status;
    }

    /**
     * The response body.
     *
     * @return the body, possibly empty
     */
    public String body() {
        return body;
    }

    /**
     * Whether a non-OAuth HTTP failure with this status is retryable.
     *
     * @param status an HTTP status code
     * @return {@code true} for 429 and 5xx
     */
    public static boolean isRetryableStatus(int status) {
        return status == 429 || status >= 500;
    }
}
