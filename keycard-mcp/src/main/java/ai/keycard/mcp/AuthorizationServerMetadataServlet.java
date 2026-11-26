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
import org.jspecify.annotations.Nullable;

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
    private static final String PATH = "/.well-known/oauth-authorization-server";

    /** The upstream issuer, or the base issuer in zone-scoped mode. */
    private final URI issuer;

    /** The configured zones for a zone-scoped proxy. */
    private final @Nullable ResourceBinding binding;

    /** The bound on the upstream fetch. */
    private final Duration timeout;

    /** Sends the upstream request; not serialized with the servlet. */
    private final transient KeycardHttpTransport transport;

    private AuthorizationServerMetadataServlet(URI issuer, KeycardHttpTransport transport, Duration timeout) {
        this(issuer, null, transport, timeout);
    }

    private AuthorizationServerMetadataServlet(
            URI issuer, @Nullable ResourceBinding binding, KeycardHttpTransport transport, Duration timeout) {
        this.issuer = issuer;
        this.binding = binding;
        this.transport = transport;
        this.timeout = timeout;
    }

    private static URI upstream(URI issuer) {
        String base = issuer.toString();
        String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        String origin = base.substring(
                0,
                base.length()
                        - (issuer.getRawPath() == null ? 0 : issuer.getRawPath().length()));
        return URI.create(origin + PATH + path);
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

    static AuthorizationServerMetadataServlet of(
            URI issuer, ResourceBinding binding, KeycardHttpTransport transport, Duration timeout) {
        return new AuthorizationServerMetadataServlet(issuer, binding, transport, timeout);
    }

    private @Nullable URI selectedIssuer(HttpServletRequest request) {
        if (binding == null) {
            return issuer;
        }
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (!binding.requiresZone() && !binding.sharedDiscovery()) {
            return path.equals(PATH) ? issuer : null;
        }
        if (!path.startsWith(PATH + "/")) {
            return null;
        }
        String zoneId = path.substring(PATH.length() + 1).split("/", 2)[0];
        return binding.issuer(zoneId).orElse(null);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        URI selected = selectedIssuer(request);
        if (selected == null) {
            response.sendError(404);
            return;
        }
        Cors.allow(response);
        TransportResponse upstreamResponse;
        try {
            upstreamResponse = transport.send(
                    TransportRequest.get(upstream(selected), timeout).withHeader("Accept", "application/json"));
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
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (selectedIssuer(request) != null) {
            Cors.preflight(response);
        } else {
            response.sendError(404);
        }
    }
}
