package ai.keycard.mcp;

import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.ConfigurationException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/**
 * Exchanges the verified caller's token for one token per declared resource before the handler
 * runs, and stores the results as an {@link AccessContext} request attribute (grant-decorator.md).
 * Built by {@link AuthProvider#grant(String...)}.
 *
 * <pre>{@code
 * Filter grant = provider.grant("https://calendar.example", "https://mail.example")
 *         .withRequestScopes(Map.of("https://mail.example", "mail.read"));
 *
 * // in the handler
 * AccessContext access = KeycardRequest.accessContext(request).orElseThrow();
 * String token = access.access("https://calendar.example").accessToken();
 * }</pre>
 *
 * <p>A request without a verified token is answered 401 with an RFC 6750 challenge and never
 * reaches the handler. A failed exchange never stops the request: it is recorded against its
 * resource for the handler to check. Stacked grants add their resources to the same context.
 * Immutable; the {@code with} methods return a new filter.
 */
public final class GrantFilter implements Filter {

    /** Picks the user a grant impersonates for one request. */
    @FunctionalInterface
    public interface UserIdentifierResolver {

        /**
         * The user to impersonate.
         *
         * @param request the request being served
         * @return the user identifier, or {@code null} for an ordinary delegated exchange
         */
        @Nullable
        String resolve(HttpServletRequest request);
    }

    private final AuthProvider provider;
    private final List<String> resources;
    private final @Nullable UserIdentifierResolver userIdentifier;
    private final Function<String, @Nullable String> scopes;

    GrantFilter(
            AuthProvider provider,
            List<String> resources,
            @Nullable UserIdentifierResolver userIdentifier,
            Function<String, @Nullable String> scopes) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.resources = AuthProvider.checkResources(resources);
        this.userIdentifier = userIdentifier;
        this.scopes = scopes;
    }

    /**
     * A filter that impersonates a user per request: each exchange becomes a substitute-user
     * exchange for the user the resolver returns (impersonation.md).
     *
     * @param resolver picks the user from the request
     * @return a new filter
     */
    public GrantFilter withUserIdentifier(UserIdentifierResolver resolver) {
        return new GrantFilter(provider, resources, Objects.requireNonNull(resolver, "resolver"), scopes);
    }

    /**
     * A filter that requests the same scopes for every resource.
     *
     * @param scopes the scopes, sent space-separated
     * @return a new filter
     */
    public GrantFilter withRequestScopes(String... scopes) {
        String joined = String.join(" ", scopes);
        return new GrantFilter(provider, resources, userIdentifier, resource -> joined.isEmpty() ? null : joined);
    }

    /**
     * A filter that requests scopes per resource; a resource missing from the map gets the server's
     * defaults.
     *
     * @param scopes space-separated scopes by resource
     * @return a new filter
     * @throws ConfigurationException when the map names a resource this grant doesn't declare
     */
    public GrantFilter withRequestScopes(Map<String, String> scopes) {
        Map<String, String> copy = new LinkedHashMap<>(scopes);
        for (String resource : copy.keySet()) {
            if (!resources.contains(resource)) {
                throw new ConfigurationException(
                        "request scopes name " + resource + ", which this grant doesn't declare");
            }
        }
        Map<String, String> frozen = Map.copyOf(copy);
        return new GrantFilter(provider, resources, userIdentifier, frozen::get);
    }

    /**
     * The resources this grant exchanges for.
     *
     * @return their identifiers
     */
    public List<String> resources() {
        return resources;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        AccessToken caller = KeycardRequest.accessToken(request).orElse(null);
        if (caller == null) {
            BearerChallenge.challenge(request, response, 401, null, null);
            return;
        }

        AccessContext context = KeycardRequest.accessContext(request).orElseGet(AccessContext::new);
        // On a forward or include the context already holds this grant's results; exchange only
        // what's new rather than spend a second exchange per resource.
        List<String> pending = new ArrayList<>(resources);
        pending.removeAll(context.successfulResources());
        pending.removeAll(context.failedResources());
        if (!pending.isEmpty()) {
            String user = userIdentifier == null ? null : userIdentifier.resolve(request);
            provider.exchange(context, caller.issuer(), caller.token(), pending, user, scopes);
        }
        request.setAttribute(KeycardRequest.ACCESS_CONTEXT_ATTRIBUTE, context);
        chain.doFilter(request, response);
    }

    /**
     * Names the resources, never a token.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "GrantFilter[resources=" + resources + ", impersonating=" + (userIdentifier != null) + "]";
    }
}
