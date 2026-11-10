package example;

import ai.keycard.mcp.AuthProvider;
import ai.keycard.oauth.AccessContext;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.KeycardException;
import ai.keycard.oauth.OAuthErrorException;
import ai.keycard.oauth.WorkloadIdentity;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson3.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.springframework.ai.mcp.server.webmvc.transport.WebMvcStreamableServerTransportProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import tools.jackson.databind.json.JsonMapper;

/**
 * A Spring AI 2.0 MCP server (WebMVC, Streamable HTTP) protected by keycard-spring-boot-starter.
 *
 * <p>The starter puts Spring Security's resource server in front of {@code /mcp} with Keycard's
 * verifier, challenges and metadata. Two beans connect it to the MCP tools: the transport's
 * context extractor copies the verified {@link Jwt} into the MCP transport context, and the
 * {@code downstream} tool exchanges that token through the starter's {@link AuthProvider} for the
 * resources it calls.
 */
@SpringBootApplication
public class Application {

    static final String JWT = "keycard.jwt";

    /** Created by Spring. */
    public Application() {}

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /** Spring AI's transport, with an extractor carrying the verified caller to tool handlers. */
    @Bean
    WebMvcStreamableServerTransportProvider webMvcStreamableServerTransportProvider(
            @Qualifier("mcpServerJsonMapper") JsonMapper jsonMapper) {
        return WebMvcStreamableServerTransportProvider.builder()
                .jsonMapper(new JacksonMcpJsonMapper(jsonMapper))
                .mcpEndpoint("/mcp")
                .contextExtractor(request -> request.principal()
                        .filter(JwtAuthenticationToken.class::isInstance)
                        .map(principal -> McpTransportContext.create(
                                Map.of(JWT, ((JwtAuthenticationToken) principal).getToken())))
                        .orElse(McpTransportContext.EMPTY))
                .build();
    }

    /** With {@code keycard.assertion-file}, the app authenticates as a v2 workload credential. */
    @Bean
    @ConditionalOnProperty("keycard.assertion-file")
    Credential workloadIdentity(
            @Value("${keycard.client-id}") String clientId, @Value("${keycard.assertion-file}") String file) {
        return WorkloadIdentity.builder(FileTokenSource.of(Path.of(file)))
                .clientId(clientId)
                .build();
    }

    @Bean
    List<SyncToolSpecification> keycardTools(
            AuthProvider keycard, @Value("${downstream.resources}") List<String> downstream) {
        return List.of(
                SyncToolSpecification.builder()
                        .tool(tool("whoami", "Report the verified caller"))
                        .callHandler((exchange, request) -> {
                            Jwt jwt = caller(exchange);
                            return text("sub=" + jwt.getSubject() + " client_id=" + jwt.getClaimAsString("client_id"),
                                    false);
                        })
                        .build(),
                SyncToolSpecification.builder()
                        .tool(tool("downstream", "Report what an exchange obtains for each downstream resource"))
                        .callHandler((exchange, request) -> downstream(keycard, caller(exchange), downstream))
                        .build());
    }

    private static Jwt caller(McpSyncServerExchange exchange) {
        if (exchange.transportContext().get(JWT) instanceof Jwt jwt) {
            return jwt;
        }
        throw new IllegalStateException("no verified caller in the transport context");
    }

    /** One line per resource: the issued token's claims, or why the exchange failed. Never a token. */
    private static CallToolResult downstream(AuthProvider keycard, Jwt caller, List<String> resources) {
        AccessContext access = keycard.exchangeTokens(caller.getTokenValue(), resources.toArray(String[]::new));
        StringBuilder report = new StringBuilder();
        for (String resource : resources) {
            report.append(resource).append(": ");
            KeycardException failure = access.resourceError(resource).or(access::error).orElse(null);
            if (failure != null) {
                String code = failure instanceof OAuthErrorException oauth
                        ? oauth.error()
                        : failure.getClass().getSimpleName();
                report.append("failed (").append(code).append(")");
            } else {
                report.append(claims(access.access(resource).accessToken()));
            }
            report.append("\n");
        }
        return text(report.toString().strip(), access.successfulResources().isEmpty());
    }

    private static String claims(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return "opaque";
        }
        try {
            Map<String, Object> claims = JSONObjectUtils.parse(
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

    private static CallToolResult text(String text, boolean error) {
        return CallToolResult.builder().addTextContent(text).isError(error).build();
    }
}
