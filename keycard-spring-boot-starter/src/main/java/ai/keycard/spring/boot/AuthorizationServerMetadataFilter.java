package ai.keycard.spring.boot;

import ai.keycard.mcp.AuthorizationServerMetadataServlet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Serves {@code /.well-known/oauth-authorization-server} as an unmodified proxy of the zone's RFC
 * 8414 metadata, ahead of authorization so it stays public whatever rules the application sets.
 * Wraps keycard-mcp's servlet.
 */
final class AuthorizationServerMetadataFilter extends OncePerRequestFilter {

    private final AuthorizationServerMetadataServlet servlet;
    private final boolean explicitBinding;
    private static final String PATH = "/.well-known/oauth-authorization-server";

    AuthorizationServerMetadataFilter(AuthorizationServerMetadataServlet servlet, boolean explicitBinding) {
        this.servlet = Objects.requireNonNull(servlet, "servlet");
        this.explicitBinding = explicitBinding;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !path.equals(PATH) && !(explicitBinding && path.startsWith(PATH + "/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        servlet.service(request, response);
    }
}
