package ai.keycard.spring.boot;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

/**
 * Spring's bearer token resolver, except that an {@code Authorization: Bearer} header that isn't
 * exactly a scheme and one token is a 400 {@code invalid_request} (RFC 6750 §3.1) rather than a
 * 401, matching keycard-mcp and the FRAMEWORK-INTEGRATIONS bearer contract.
 */
final class StrictBearerTokenResolver implements BearerTokenResolver {

    private final DefaultBearerTokenResolver delegate = new DefaultBearerTokenResolver();

    @Override
    public @Nullable String resolve(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null) {
            String[] parts = header.trim().split("\\s+");
            if (parts[0].toLowerCase(Locale.ROOT).equals("bearer") && parts.length != 2) {
                throw new OAuth2AuthenticationException(
                        BearerTokenErrors.invalidRequest("the Authorization header must be 'Bearer <token>'"));
            }
        }
        return delegate.resolve(request);
    }
}
