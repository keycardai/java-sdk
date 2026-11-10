package ai.keycard.mcp;

import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.KeycardHttpTransport;
import ai.keycard.oauth.TransportRequest;
import ai.keycard.oauth.TransportResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Proxies the zone's RFC 8414 authorization-server metadata, for clients that look for it on the
 * resource server. Map it at {@code /.well-known/oauth-authorization-server}.
 *
 * <p>The upstream document is returned unmodified, {@code authorization_endpoint} included: MCP
 * clients send the RFC 8707 {@code resource} themselves. An upstream failure is {@code 502 Bad
 * Gateway}.
 */
public final class AuthorizationServerMetadataServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /** The upstream metadata URL. */
    private final URI upstream;

    /** The bound on the upstream fetch. */
    private final Duration timeout;

    /** Sends the upstream request; not serialized with the servlet. */
    private final transient KeycardHttpTransport transport;

    private AuthorizationServerMetadataServlet(URI issuer, KeycardHttpTransport transport, Duration timeout) {
        String base = issuer.toString();
        String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        String origin = base.substring(
                0,
                base.length()
                        - (issuer.getRawPath() == null ? 0 : issuer.getRawPath().length()));
        this.upstream = URI.create(origin + "/.well-known/oauth-authorization-server" + path);
        this.transport = transport;
        this.timeout = timeout;
    }

    /**
     * A proxy for {@code issuer}'s metadata with a 10 second upstream timeout.
     *
     * @param issuer the Keycard zone
     * @return the servlet
     */
    public static AuthorizationServerMetadataServlet of(URI issuer) {
        return of(issuer, KeycardHttpTransport.create(), KeycardHttpTransport.DEFAULT_TIMEOUT);
    }

    /**
     * A proxy with a chosen transport and upstream timeout.
     *
     * @param issuer the Keycard zone
     * @param transport sends the upstream request
     * @param timeout the bound on the upstream fetch
     * @return the servlet
     */
    public static AuthorizationServerMetadataServlet of(URI issuer, KeycardHttpTransport transport, Duration timeout) {
        return new AuthorizationServerMetadataServlet(
                Objects.requireNonNull(issuer, "issuer"),
                Objects.requireNonNull(transport, "transport"),
                Objects.requireNonNull(timeout, "timeout"));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cors.allow(response);
        TransportResponse upstreamResponse;
        try {
            upstreamResponse =
                    transport.send(TransportRequest.get(upstream, timeout).withHeader("Accept", "application/json"));
        } catch (KeycardException e) {
            BearerChallenge.json(response, 502, "{\"error\":\"bad_gateway\"}");
            return;
        }
        if (!upstreamResponse.isSuccess()) {
            BearerChallenge.json(response, 502, "{\"error\":\"bad_gateway\"}");
            return;
        }
        BearerChallenge.json(response, 200, upstreamResponse.body());
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        Cors.preflight(response);
    }
}
