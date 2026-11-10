package ai.keycard.mcp;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.AccessToken;
import jakarta.servlet.ServletRequest;
import java.util.Optional;

/**
 * Reads what the Keycard filters put on a request.
 *
 * <pre>{@code
 * AccessToken caller = KeycardRequest.accessToken(request).orElseThrow();
 * AccessContext access = KeycardRequest.accessContext(request).orElseThrow();
 * }</pre>
 */
public final class KeycardRequest {

    /** Request attribute holding the verified {@link AccessToken}. */
    public static final String ACCESS_TOKEN_ATTRIBUTE = "ai.keycard.authInfo";

    /** Request attribute holding the grant's {@link AccessContext}. */
    public static final String ACCESS_CONTEXT_ATTRIBUTE = "ai.keycard.accessContext";

    private KeycardRequest() {}

    /**
     * The verified caller, set by {@link RequireBearerAuthFilter}.
     *
     * @param request the request
     * @return the token, empty when the request didn't pass the bearer filter
     */
    public static Optional<AccessToken> accessToken(ServletRequest request) {
        return request.getAttribute(ACCESS_TOKEN_ATTRIBUTE) instanceof AccessToken token
                ? Optional.of(token)
                : Optional.empty();
    }

    /**
     * The tokens a grant obtained for this request.
     *
     * @param request the request
     * @return the context, empty when no grant ran
     */
    public static Optional<AccessContext> accessContext(ServletRequest request) {
        return request.getAttribute(ACCESS_CONTEXT_ATTRIBUTE) instanceof AccessContext context
                ? Optional.of(context)
                : Optional.empty();
    }
}
