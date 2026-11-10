package ai.keycard.oauth;

/**
 * A transport failure: DNS, TLS, connection refused, a timeout, or the calling thread being
 * interrupted. The JDK's own exception ({@link java.net.http.HttpTimeoutException}, {@link
 * java.net.ConnectException}, {@link InterruptedException}, ...) is the {@linkplain #getCause()
 * cause}. Always retryable: a failure no retry can fix reaches the caller as an HTTP or OAuth
 * error instead.
 */
public class NetworkException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what failed, naming the host but never credentials
     * @param cause the transport's exception
     */
    public NetworkException(String message, Throwable cause) {
        super(message, cause, true);
    }
}
