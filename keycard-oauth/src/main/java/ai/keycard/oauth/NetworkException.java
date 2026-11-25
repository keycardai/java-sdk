package ai.keycard.oauth;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;

/**
 * A transport failure: DNS, TLS, connection refused, a timeout, or the calling thread being
 * interrupted. The JDK's own exception ({@link java.net.http.HttpTimeoutException}, {@link
 * java.net.ConnectException}, {@link InterruptedException}, ...) is the {@linkplain #getCause()
 * cause}. Certificate validation failures are not retryable.
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
        super(message, cause, retryable(cause));
    }

    private static boolean retryable(Throwable cause) {
        for (Throwable current = cause; current != null; current = current.getCause()) {
            if (current instanceof CertificateException || current instanceof CertPathValidatorException) {
                return false;
            }
        }
        return true;
    }
}
