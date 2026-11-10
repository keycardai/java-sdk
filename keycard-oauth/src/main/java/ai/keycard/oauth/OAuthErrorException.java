package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * An OAuth error response from the authorization server (RFC 6749 §5.2). Retryable unless the
 * {@link #error()} code is in {@link OAuthErrorCodes#PERMANENT}.
 */
public class OAuthErrorException extends HttpStatusException {

    private static final long serialVersionUID = 1L;

    /** The OAuth {@code error} code. */
    private final String error;
    /** The OAuth {@code error_description}, or {@code null}. */
    private final @Nullable String errorDescription;
    /** The OAuth {@code error_uri}, or {@code null}. */
    private final @Nullable String errorUri;

    /**
     * Creates the exception, classifying it from the error code.
     *
     * @param message what failed
     * @param status the HTTP status code
     * @param body the response body
     * @param error the OAuth {@code error} code, such as {@code invalid_grant}
     * @param errorDescription the {@code error_description}, or {@code null}
     * @param errorUri the {@code error_uri}, or {@code null}
     */
    public OAuthErrorException(
            String message,
            int status,
            String body,
            String error,
            @Nullable String errorDescription,
            @Nullable String errorUri) {
        super(message, status, body, !OAuthErrorCodes.isPermanent(error));
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
    }

    /** Creates the exception with a classification an operation overrides locally. */
    OAuthErrorException(
            String message,
            int status,
            String body,
            String error,
            @Nullable String errorDescription,
            @Nullable String errorUri,
            boolean retryable) {
        super(message, status, body, retryable);
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
    }

    /**
     * The OAuth {@code error} code.
     *
     * @return the code, such as {@code invalid_grant}
     */
    public String error() {
        return error;
    }

    /**
     * The OAuth {@code error_description}.
     *
     * @return the description, or {@code null} when the server sent none
     */
    public @Nullable String errorDescription() {
        return errorDescription;
    }

    /**
     * The OAuth {@code error_uri}.
     *
     * @return the URI, or {@code null} when the server sent none
     */
    public @Nullable String errorUri() {
        return errorUri;
    }
}
