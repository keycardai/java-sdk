package ai.keycard.oauth;

import java.util.Set;

/**
 * OAuth error codes the SDK classifies, and the exported set of permanent codes.
 *
 * <p>{@link #PERMANENT} is part of the public contract. A consumer that receives only a
 * serialized error code, after a process or workflow boundary strips the typed exception,
 * classifies by membership in this set and gets the same answer as {@link
 * OAuthErrorException#retryable()}.
 */
public final class OAuthErrorCodes {

    /** Zone policy denied the request. */
    public static final String ACCESS_DENIED = "access_denied";

    /** The device code expired or was already used. */
    public static final String EXPIRED_TOKEN = "expired_token";

    /** The caller lacks the delegated authorization the operation requires. */
    public static final String INSUFFICIENT_AUTHORIZATION = "insufficient_authorization";

    /** Client authentication failed. */
    public static final String INVALID_CLIENT = "invalid_client";

    /** The denials no retry can change. Every other OAuth error code is retryable. */
    public static final Set<String> PERMANENT =
            Set.of(ACCESS_DENIED, EXPIRED_TOKEN, INSUFFICIENT_AUTHORIZATION, INVALID_CLIENT);

    private OAuthErrorCodes() {}

    /**
     * Whether an OAuth error code is permanent.
     *
     * @param code an OAuth {@code error} code
     * @return {@code true} when the code is in {@link #PERMANENT}
     */
    public static boolean isPermanent(String code) {
        return PERMANENT.contains(code);
    }
}
