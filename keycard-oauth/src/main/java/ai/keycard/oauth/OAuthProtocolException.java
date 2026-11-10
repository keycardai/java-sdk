package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * The server answered, but its response breaks the protocol: discovery metadata with a missing
 * or mismatched issuer, a document that isn't a JSON object, a token response without an access
 * token. {@link #code()} discriminates the case.
 *
 * <p>Only {@link #INVALID_RESPONSE} is retryable, because base.md classifies a malformed token
 * response by that code like any other OAuth error. Metadata failures ({@link #ISSUER_MISMATCH},
 * {@link #INVALID_METADATA}) are deterministic and not retryable.
 */
public class OAuthProtocolException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** The discovered metadata's {@code issuer} differs from the requested issuer (RFC 8414 §3.3). */
    public static final String ISSUER_MISMATCH = "issuer_mismatch";

    /** A discovery document that is not a JSON object, lacks {@code issuer}, or mistypes a field. */
    public static final String INVALID_METADATA = "invalid_metadata";

    /** A malformed response from an OAuth endpoint, such as a token response with no token. */
    public static final String INVALID_RESPONSE = "invalid_response";

    /** The discriminator code. */
    private final String code;

    /**
     * Creates the exception.
     *
     * @param message what was wrong with the response
     * @param code the discriminator, such as {@link #ISSUER_MISMATCH}
     */
    public OAuthProtocolException(String message, String code) {
        this(message, code, null);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param message what was wrong with the response
     * @param code the discriminator, such as {@link #INVALID_METADATA}
     * @param cause the parse failure, or {@code null}
     */
    public OAuthProtocolException(String message, String code, @Nullable Throwable cause) {
        super(message, cause, INVALID_RESPONSE.equals(code));
        this.code = code;
    }

    /**
     * The discriminator code.
     *
     * @return the code
     */
    public String code() {
        return code;
    }
}
