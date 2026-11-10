package ai.keycard.mcp;

import ai.keycard.oauth.AccessToken;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

/**
 * Gates a route on scopes (route-level-auth-gating.md). Runs after {@link
 * RequireBearerAuthFilter} and reads its verified token; it never verifies a token itself.
 * Stacked gates require the union of their scopes.
 *
 * <ul>
 *   <li>no verified token on the request: 401 with a {@code resource_metadata} challenge
 *   <li>a required scope missing: 403 with {@code error="insufficient_scope"}
 * </ul>
 */
public final class RequireScopesFilter implements Filter {

    private final Set<String> requiredScopes;

    private RequireScopesFilter(Set<String> requiredScopes) {
        this.requiredScopes = requiredScopes;
    }

    /**
     * A gate requiring every listed scope; no scopes gates on authentication alone.
     *
     * @param scopes the required scopes
     * @return the filter
     */
    public static RequireScopesFilter of(String... scopes) {
        return new RequireScopesFilter(Set.of(scopes));
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        Optional<AccessToken> token = KeycardRequest.accessToken(request);
        if (token.isEmpty()) {
            BearerChallenge.challenge(request, response, 401, null, null);
            return;
        }
        for (String scope : requiredScopes) {
            if (!token.get().scopes().contains(scope)) {
                BearerChallenge.challenge(
                        request, response, 403, "insufficient_scope", "the token lacks the scope " + scope);
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
