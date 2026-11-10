package ai.keycard.spring.boot;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.mcp.KeycardRequest;
import ai.keycard.oauth.AccessContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Runs the exchanges a handler's {@link KeycardGrant}s declare, before the handler, and stores the
 * {@link AccessContext} under {@link KeycardRequest#ACCESS_CONTEXT_ATTRIBUTE}, where the argument
 * resolver and {@link KeycardRequest#accessContext} find it.
 */
public final class KeycardGrantInterceptor implements HandlerInterceptor {

    private final AuthProvider provider;
    private final AuthenticationEntryPoint challenge;

    /**
     * An interceptor exchanging through the provider.
     *
     * @param provider the provider holding the zone and application credential
     * @param challenge answers a request with no verified token
     */
    public KeycardGrantInterceptor(AuthProvider provider, AuthenticationEntryPoint challenge) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.challenge = Objects.requireNonNull(challenge, "challenge");
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        List<KeycardGrant> grants = new ArrayList<>();
        KeycardGrant onType = AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), KeycardGrant.class);
        KeycardGrant onMethod = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(), KeycardGrant.class);
        if (onType != null) {
            grants.add(onType);
        }
        if (onMethod != null) {
            grants.add(onMethod);
        }
        if (grants.isEmpty()) {
            return true;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            challenge.commence(
                    request, response, new InsufficientAuthenticationException("a verified bearer token is required"));
            return false;
        }
        AccessContext context = KeycardRequest.accessContext(request).orElseGet(AccessContext::new);
        String issuer = String.valueOf(jwt.getClaims().get("iss"));
        for (KeycardGrant grant : grants) {
            String scope = grant.scopes().length == 0 ? null : String.join(" ", grant.scopes());
            provider.exchangeInto(context, issuer, jwt.getTokenValue(), List.of(grant.resources()), resource -> scope);
        }
        request.setAttribute(KeycardRequest.ACCESS_CONTEXT_ATTRIBUTE, context);
        return true;
    }
}
