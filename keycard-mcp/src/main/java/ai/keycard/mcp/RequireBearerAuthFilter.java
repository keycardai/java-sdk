package ai.keycard.mcp;

import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.ConfigurationException;
import ai.keycard.oauth.InvalidTokenException;
import ai.keycard.oauth.JwksException;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.TokenVerifier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Requires a valid Keycard bearer token (bearer-token-verification-middleware.md).
 *
 * <pre>{@code
 * Filter auth = RequireBearerAuthFilter.builder(
 *                 TokenVerifier.builder(URI.create("https://acme.keycard.cloud"))
 *                         .audiences("https://mcp.example.com/mcp")
 *                         .build())
 *         .build();
 * }</pre>
 *
 * <p>Failures are HTTP responses, never exceptions into the application:
 *
 * <ul>
 *   <li>no {@code Authorization} header: 401 with {@code Bearer resource_metadata="..."}
 *   <li>a header that isn't two parts: 400
 *   <li>a scheme other than {@code Bearer}, or a token that fails verification: 401 with {@code
 *       error="invalid_token"}
 *   <li>a required scope missing: 403 with {@code error="insufficient_scope"}
 *   <li>the zone's keys or metadata can't be fetched: 503 {@code {"error":"temporarily_unavailable"}}
 *       with no challenge, since the token was never judged
 * </ul>
 *
 * <p>On success the {@link AccessToken} is stored under {@link
 * KeycardRequest#ACCESS_TOKEN_ATTRIBUTE} and the chain continues.
 */
public final class RequireBearerAuthFilter implements Filter {

    /** Resolves a request's zone issuer for a multi-zone server. */
    @FunctionalInterface
    public interface ZoneResolver {

        /**
         * The zone this request belongs to.
         *
         * @param request the request
         * @return the zone's issuer, or {@code null} when it can't be determined (the request is
         *     then rejected)
         */
        @Nullable
        URI resolve(HttpServletRequest request);
    }

    private final TokenVerifier verifier;
    private final Set<String> requiredScopes;
    private final @Nullable ZoneResolver zoneResolver;

    private RequireBearerAuthFilter(Builder builder) {
        this.verifier = builder.verifier;
        this.requiredScopes = Set.copyOf(builder.requiredScopes);
        this.zoneResolver = builder.zoneResolver;
    }

    /**
     * A builder for a filter verifying with {@code verifier}.
     *
     * @param verifier the token verifier, built with this server's audience
     * @return a new builder
     */
    public static Builder builder(TokenVerifier verifier) {
        return new Builder(verifier);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // A forward or include of a request this filter already verified: the token stands, and
        // only this instance's scopes are left to check. Request attributes are server-side, so a
        // client can't set this one.
        AccessToken verified = KeycardRequest.accessToken(request).orElse(null);
        if (verified != null) {
            if (hasRequiredScopes(request, response, verified)) {
                chain.doFilter(request, response);
            }
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            BearerChallenge.challenge(request, response, 401, null, null);
            return;
        }
        String[] parts = header.trim().split("\\s+");
        if (parts.length != 2) {
            BearerChallenge.badRequest(response, "the Authorization header must be 'Bearer <token>'");
            return;
        }
        if (!parts[0].toLowerCase(Locale.ROOT).equals("bearer")) {
            BearerChallenge.challenge(request, response, 401, "invalid_token", "unsupported authorization scheme");
            return;
        }

        AccessToken token;
        try {
            token = verify(request, parts[1]);
        } catch (InvalidTokenException e) {
            // A fixed description: the verifier's message names the expected issuer and audiences,
            // which a caller probing with forged tokens has no business learning.
            BearerChallenge.challenge(
                    request, response, 401, "invalid_token", "the access token is invalid or expired");
            return;
        } catch (JwksException e) {
            BearerChallenge.unavailable(response);
            return;
        } catch (KeycardException e) {
            // Discovery or transport failures that surface outside the keyring.
            BearerChallenge.unavailable(response);
            return;
        }

        if (!hasRequiredScopes(request, response, token)) {
            return;
        }
        request.setAttribute(KeycardRequest.ACCESS_TOKEN_ATTRIBUTE, token);
        chain.doFilter(request, response);
    }

    /** Answers 403 {@code insufficient_scope} and returns false when a required scope is missing. */
    private boolean hasRequiredScopes(HttpServletRequest request, HttpServletResponse response, AccessToken token)
            throws IOException {
        List<String> granted = token.scopes();
        for (String scope : requiredScopes) {
            if (!granted.contains(scope)) {
                BearerChallenge.challenge(
                        request, response, 403, "insufficient_scope", "the token lacks the scope " + scope);
                return false;
            }
        }
        return true;
    }

    private AccessToken verify(HttpServletRequest request, String token) {
        if (zoneResolver == null) {
            return verifier.verifyToken(token);
        }
        URI zone = zoneResolver.resolve(request);
        if (zone == null) {
            throw new InvalidTokenException("the request's zone could not be determined");
        }
        return verifier.verifyTokenForZone(token, zone);
    }

    /** Configures a {@link RequireBearerAuthFilter}. */
    public static final class Builder {

        private final TokenVerifier verifier;
        private Set<String> requiredScopes = Set.of();
        private @Nullable ZoneResolver zoneResolver;

        private Builder(TokenVerifier verifier) {
            this.verifier = Objects.requireNonNull(verifier, "verifier");
        }

        /**
         * Scopes every request's token must hold, all of them.
         *
         * @param scopes the required scopes
         * @return this builder
         */
        public Builder requiredScopes(String... scopes) {
            this.requiredScopes = Set.of(scopes);
            return this;
        }

        /**
         * Pins each request to one zone for a multi-zone server; a request whose zone can't be
         * determined, or isn't trusted by the verifier, is rejected.
         *
         * @param zoneResolver resolves the zone issuer from the request
         * @return this builder
         */
        public Builder zoneResolver(ZoneResolver zoneResolver) {
            this.zoneResolver = Objects.requireNonNull(zoneResolver, "zoneResolver");
            return this;
        }

        /**
         * Builds the filter.
         *
         * @return the filter
         * @throws ConfigurationException when the verifier trusts more than one zone and no zone
         *     resolver is set: each request must be verified against its own zone, never any
         *     trusted one
         */
        public RequireBearerAuthFilter build() {
            if (zoneResolver == null && verifier.issuers().size() > 1) {
                throw new ConfigurationException(
                        "the verifier trusts " + verifier.issuers().size()
                                + " zones; set a zoneResolver so each request is verified against its own zone");
            }
            return new RequireBearerAuthFilter(this);
        }
    }
}
