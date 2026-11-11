package example;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.mcp.AuthorizationServerMetadataServlet;
import ai.keycard.mcp.GrantFilter;
import ai.keycard.mcp.ProtectedResourceMetadataServlet;
import ai.keycard.mcp.RequireBearerAuthFilter;
import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.ClientSecret;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.TokenResponse;
import ai.keycard.oauth.WorkloadIdentity;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.ServerCapabilities;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.ServerConnector;

/**
 * An MCP server on the official MCP Java SDK's Streamable HTTP servlet transport, protected by
 * keycard-mcp. Two tools: {@code whoami} reports the verified caller, and {@code downstream}
 * reports what the grant obtained for each downstream resource.
 *
 * <p>Configuration comes from the environment and is passed to the SDK explicitly; the SDK reads
 * no environment variables itself.
 */
public final class Server implements AutoCloseable {

    static final String SERVER_NAME = "mcp-server-servlet";
    static final String MCP_PATH = "/mcp";

    /** What the server needs; built from the environment by {@link #fromEnvironment()}. */
    record Config(
            URI zoneUrl,
            String host,
            int port,
            String resourceId,
            Credential credential,
            List<String> downstreamResources,
            List<String> requiredScopes) {}

    private final org.eclipse.jetty.server.Server jetty;
    private final McpSyncServer mcp;

    private Server(org.eclipse.jetty.server.Server jetty, McpSyncServer mcp) {
        this.jetty = jetty;
        this.mcp = mcp;
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
        Config config = fromEnvironment();
        Server server = start(config);
        System.out.println(SERVER_NAME + " listening on " + server.url(MCP_PATH));
        server.jetty.join();
    }

    /** Builds and starts the server. */
    static Server start(Config config) throws Exception {
        AuthProvider provider = AuthProvider.builder(config.zoneUrl())
                .credential(config.credential())
                .audiences(config.resourceId())
                .build();

        HttpServletStreamableServerTransportProvider transport = HttpServletStreamableServerTransportProvider.builder()
                .mcpEndpoint(MCP_PATH)
                .contextExtractor(KeycardTransportContext::extract)
                .build();
        McpSyncServer mcp = McpServer.sync(transport)
                .serverInfo(SERVER_NAME, "0.1.0")
                .capabilities(ServerCapabilities.builder().tools(false).build())
                .toolCall(tool("whoami", "Report the verified caller"), (exchange, request) -> whoami(exchange))
                .toolCall(
                        tool("downstream", "Report what the grant obtained for each downstream resource"),
                        (exchange, request) -> downstream(exchange, config.downstreamResources()))
                .build();

        ServletContextHandler context = new ServletContextHandler();
        context.addServlet(new ServletHolder(new Health()), "/healthz");
        context.addServlet(
                new ServletHolder(ProtectedResourceMetadataServlet.builder(config.zoneUrl())
                        .resourceName(SERVER_NAME)
                        .scopesSupported(config.requiredScopes().toArray(String[]::new))
                        .build()),
                "/.well-known/oauth-protected-resource/*");
        context.addServlet(
                new ServletHolder(AuthorizationServerMetadataServlet.of(config.zoneUrl())),
                "/.well-known/oauth-authorization-server");

        // Bearer verification first, then the grant, then the MCP transport. Every holder in the
        // chain is async-supported because the transport answers on an async context.
        RequireBearerAuthFilter bearer = RequireBearerAuthFilter.builder(provider.tokenVerifier())
                .requiredScopes(config.requiredScopes().toArray(String[]::new))
                .build();
        GrantFilter grant = provider.grant(config.downstreamResources().toArray(String[]::new));
        addFilter(context, bearer);
        addFilter(context, grant);
        ServletHolder mcpHolder = new ServletHolder(transport);
        mcpHolder.setAsyncSupported(true);
        context.addServlet(mcpHolder, MCP_PATH);

        org.eclipse.jetty.server.Server jetty =
                new org.eclipse.jetty.server.Server(new InetSocketAddress(config.host(), config.port()));
        jetty.setHandler(context);
        jetty.start();
        return new Server(jetty, mcp);
    }

    /** The server's URL for a path. */
    URI url(String path) {
        ServerConnector connector = (ServerConnector) jetty.getConnectors()[0];
        return URI.create("http://" + connector.getHost() + ":" + connector.getLocalPort() + path);
    }

    @Override
    public void close() throws Exception {
        mcp.closeGracefully();
        jetty.stop();
    }

    static Config fromEnvironment() {
        URI zone = URI.create(require("KEYCARD_ZONE_URL"));
        String clientId = require("KEYCARD_CLIENT_ID");
        String secret = System.getenv("KEYCARD_CLIENT_SECRET");
        String assertionFile = System.getenv("KEYCARD_ASSERTION_FILE");
        Credential credential;
        if (secret != null && !secret.isBlank()) {
            credential = ClientSecret.of(clientId, secret);
        } else if (assertionFile != null && !assertionFile.isBlank()) {
            credential = WorkloadIdentity.builder(FileTokenSource.of(Path.of(assertionFile)))
                    .clientId(clientId)
                    .build();
        } else {
            throw new IllegalStateException("set KEYCARD_CLIENT_SECRET, or KEYCARD_ASSERTION_FILE for a workload identity");
        }
        String scopes = System.getenv().getOrDefault("KEYCARD_REQUIRED_SCOPES", "");
        return new Config(
                zone,
                System.getenv().getOrDefault("HOST", "127.0.0.1"),
                Integer.parseInt(System.getenv().getOrDefault("PORT", "8765")),
                require("KEYCARD_RESOURCE_ID"),
                credential,
                List.of(require("DOWNSTREAM_RESOURCES").trim().split("\\s+")),
                scopes.isBlank() ? List.of() : List.of(scopes.trim().split("\\s+")));
    }

    private static CallToolResult whoami(McpSyncServerExchange exchange) {
        AccessToken caller = KeycardTransportContext.accessToken(exchange.transportContext())
                .orElseThrow(() -> new IllegalStateException("no verified caller; is the bearer filter mapped?"));
        return text("sub=" + caller.subject() + " client_id=" + caller.clientId());
    }

    /**
     * One line per resource: the issued token's claims, or why the exchange failed. A failed
     * resource doesn't fail the others; the call is an error only when every resource failed.
     */
    private static CallToolResult downstream(McpSyncServerExchange exchange, List<String> resources) {
        AccessContext access = KeycardTransportContext.accessContext(exchange.transportContext())
                .orElseThrow(() -> new IllegalStateException("no AccessContext; is the grant filter mapped?"));
        StringBuilder report = new StringBuilder();
        for (String resource : resources) {
            report.append(resource).append(": ");
            if (access.hasResourceError(resource) || access.hasError()) {
                KeycardException failure =
                        access.resourceError(resource).or(access::error).orElseThrow();
                String code = failure instanceof OAuthErrorException oauth
                        ? oauth.error()
                        : failure.getClass().getSimpleName();
                report.append("failed (").append(code).append(")");
            } else {
                // Report the issued token's claims, never the token itself.
                TokenResponse token = access.access(resource);
                report.append(claims(token.accessToken()));
            }
            report.append("\n");
        }
        boolean allFailed = access.successfulResources().isEmpty();
        return CallToolResult.builder()
                .addTextContent(report.toString().strip())
                .isError(allFailed)
                .build();
    }

    private static String claims(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return "opaque";
        }
        try {
            Map<String, Object> claims = com.nimbusds.jose.util.JSONObjectUtils.parse(
                    new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            return "sub=" + claims.get("sub") + " aud=" + claims.get("aud") + " act=" + claims.get("act");
        } catch (Exception e) {
            return "opaque";
        }
    }

    private static Tool tool(String name, String description) {
        return Tool.builder(name, Map.of("type", "object", "properties", Map.of()))
                .description(description)
                .build();
    }

    private static CallToolResult text(String text) {
        return CallToolResult.builder().addTextContent(text).isError(false).build();
    }

    private static void addFilter(ServletContextHandler context, Filter filter) {
        FilterHolder holder = new FilterHolder(filter);
        holder.setAsyncSupported(true);
        // The servlet's own path plus everything under it, for forwards and includes as well.
        context.addFilter(
                holder,
                MCP_PATH + "/*",
                EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.INCLUDE));
    }

    private static String require(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is not set");
        }
        return value;
    }

    /** {@code GET /healthz}. */
    static final class Health extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"ok\"}");
        }
    }
}
