package example;

import ai.keycard.mcp.KeycardRequest;
import ai.keycard.mcp.RequireBearerAuthFilter;
import ai.keycard.oauth.AccessToken;
import ai.keycard.oauth.TokenVerifier;
import com.google.protobuf.util.JsonFormat;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import org.a2aproject.sdk.grpc.utils.JSONRPCUtils;
import org.a2aproject.sdk.grpc.utils.ProtoJsonUtils;
import org.a2aproject.sdk.grpc.utils.ProtoUtils;
import org.a2aproject.sdk.jsonrpc.common.wrappers.A2ARequest;
import org.a2aproject.sdk.jsonrpc.common.wrappers.SendMessageRequest;
import org.a2aproject.sdk.spec.AgentCapabilities;
import org.a2aproject.sdk.spec.AgentCard;
import org.a2aproject.sdk.spec.AgentInterface;
import org.a2aproject.sdk.spec.AgentSkill;
import org.a2aproject.sdk.spec.Message;
import org.a2aproject.sdk.spec.MethodNotFoundError;
import org.a2aproject.sdk.spec.Part;
import org.a2aproject.sdk.spec.TextPart;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;

/**
 * The downstream agent, speaking A2A through the official a2a-java SDK. It publishes its card and
 * a JSON-RPC endpoint behind Keycard bearer verification, audience-bound to its own URL, and
 * answers {@code SendMessage} with what it verified: the token's {@code sub}, {@code aud} and
 * {@code act}. Those come from B's own check against the zone's keys, not from anything the
 * caller says.
 */
final class AgentB {

    static final String NAME = "Agent B";

    private AgentB() {}

    /** Mounts B on a context served at {@code baseUrl}, trusting tokens from {@code verifier}. */
    static void mount(ServletContextHandler context, URI baseUrl, TokenVerifier verifier) {
        context.addServlet(new ServletHolder(new Card(baseUrl)), "/.well-known/agent-card.json");
        FilterHolder bearer = new FilterHolder(RequireBearerAuthFilter.builder(verifier).build());
        context.addFilter(bearer, "/a2a/jsonrpc", EnumSet.of(DispatcherType.REQUEST));
        context.addServlet(new ServletHolder(new JsonRpc()), "/a2a/jsonrpc");
    }

    static AgentCard card(URI baseUrl) {
        String base = baseUrl.toString().replaceAll("/$", "");
        return AgentCard.builder()
                .name(NAME)
                .description("Reports the identity it verified on each delegated call")
                .version("0.1.0")
                .capabilities(AgentCapabilities.builder().streaming(false).build())
                .defaultInputModes(List.of("text"))
                .defaultOutputModes(List.of("text"))
                .skills(List.of(AgentSkill.builder()
                        .id("whoami")
                        .name("Who am I")
                        .description("Echoes the verified subject and actor chain")
                        .tags(List.of("identity"))
                        .build()))
                .supportedInterfaces(List.of(new AgentInterface("JSONRPC", base + "/a2a/jsonrpc", null, "1.0")))
                .build();
    }

    /** {@code GET /.well-known/agent-card.json}, serialized by a2a-java. */
    static final class Card extends HttpServlet {

        private static final long serialVersionUID = 1L;

        /** The card's JSON. */
        private final String json;

        Card(URI baseUrl) {
            try {
                this.json = ProtoJsonUtils.toJson(JsonFormat.printer(), ProtoUtils.ToProto.agentCard(card(baseUrl)));
            } catch (Exception e) {
                throw new IllegalStateException("could not serialize the agent card", e);
            }
        }

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.setContentType("application/json");
            response.getWriter().write(json);
        }
    }

    /** {@code POST /a2a/jsonrpc}: a2a-java parses the request and serializes the reply. */
    static final class JsonRpc extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String body = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            response.setContentType("application/json");
            A2ARequest<?> parsed;
            try {
                parsed = JSONRPCUtils.parseRequestBody(body, null);
            } catch (Exception e) {
                response.getWriter().write(JSONRPCUtils.toJsonRPCErrorResponse(
                        null, new MethodNotFoundError(null, "unparseable request: " + e.getMessage(), null)));
                return;
            }
            if (!(parsed instanceof SendMessageRequest send) || !"1.0".equals(request.getHeader("A2A-Version"))) {
                response.getWriter().write(JSONRPCUtils.toJsonRPCErrorResponse(
                        parsed.getId(), new MethodNotFoundError(null, "only SendMessage under A2A 1.0", null)));
                return;
            }
            Message incoming = send.getParams().message();
            AccessToken caller = KeycardRequest.accessToken(request).orElseThrow();
            String reply = "verified sub=" + caller.subject() + " aud=" + caller.audiences() + " act="
                    + caller.claims().get("act") + " role=" + incoming.role() + " text=" + firstText(incoming);
            Message answer = Message.builder()
                    .role(Message.Role.ROLE_AGENT)
                    .parts(new TextPart(reply, null))
                    .messageId(UUID.randomUUID().toString())
                    .build();
            response.getWriter()
                    .write(JSONRPCUtils.toJsonRPCResultResponse(
                            send.getId(), ProtoUtils.ToProto.taskOrMessage(answer)));
        }

        private static String firstText(Message message) {
            for (Part<?> part : message.parts()) {
                if (part instanceof TextPart text) {
                    return text.text();
                }
            }
            return "";
        }
    }
}
