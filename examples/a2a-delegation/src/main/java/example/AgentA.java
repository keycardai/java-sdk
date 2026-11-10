package example;

import ai.keycard.a2a.A2aProtocol;
import ai.keycard.a2a.DelegationClient;
import ai.keycard.a2a.DelegationResult;
import ai.keycard.mcp.KeycardRequest;
import ai.keycard.mcp.RequireBearerAuthFilter;
import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.TokenVerifier;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;

/**
 * The calling agent. {@code POST /delegate} with a user's bearer token and a text body: A verifies
 * the token, then delegates to B with keycard-a2a (discover B's card, exchange the user's token
 * for one scoped to B, send the message) and returns B's reply text.
 */
final class AgentA {

    private AgentA() {}

    static void mount(ServletContextHandler context, TokenVerifier verifier, DelegationClient delegation, URI agentB) {
        FilterHolder bearer = new FilterHolder(RequireBearerAuthFilter.builder(verifier).build());
        context.addFilter(bearer, "/delegate", EnumSet.of(DispatcherType.REQUEST));
        context.addServlet(new ServletHolder(new Delegate(delegation, agentB)), "/delegate");
    }

    /** {@code POST /delegate}. */
    static final class Delegate extends HttpServlet {

        private static final long serialVersionUID = 1L;

        /** The delegation client, shared across requests. */
        private final transient DelegationClient delegation;

        /** Agent B's base URL. */
        private final URI agentB;

        Delegate(DelegationClient delegation, URI agentB) {
            this.delegation = delegation;
            this.agentB = agentB;
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            AccessToken user = KeycardRequest.accessToken(request).orElseThrow();
            String text = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            response.setContentType("text/plain");
            try {
                DelegationResult result = delegation.invoke(agentB, user.token(), A2aProtocol.textMessage(text));
                response.getWriter().write(result.text().orElse("(no text)"));
            } catch (KeycardException e) {
                response.setStatus(502);
                response.getWriter().write(e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }
    }
}
