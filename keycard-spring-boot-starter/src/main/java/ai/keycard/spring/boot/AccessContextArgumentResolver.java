package ai.keycard.spring.boot;

import ai.keycard.mcp.KeycardRequest;
import ai.keycard.oauth.AccessContext;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolves an {@link AccessContext} handler parameter from the context {@link KeycardGrant}
 * filled. A handler that takes one without a grant fails loudly rather than receiving an empty
 * context.
 */
public final class AccessContextArgumentResolver implements HandlerMethodArgumentResolver {

    /** A resolver. */
    public AccessContextArgumentResolver() {}

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return AccessContext.class.equals(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(
            MethodParameter parameter,
            @Nullable ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest,
            @Nullable WebDataBinderFactory binderFactory) {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        if (request == null) {
            throw new IllegalStateException("AccessContext parameters need a servlet request");
        }
        return KeycardRequest.accessContext(request)
                .orElseThrow(() -> new IllegalStateException(
                        "handler " + parameter.getExecutable() + " takes an AccessContext but has no @KeycardGrant"));
    }
}
