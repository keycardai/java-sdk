package example;

import ai.keycard.a2a.DelegationClient;
import ai.keycard.oauth.FileTokenSource;
import ai.keycard.oauth.TokenVerifier;
import ai.keycard.oauth.WorkloadIdentity;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;

/**
 * a2a-delegation.md Integration Tests against a live zone. Agent A runs as the engine application
 * and agent B as the gateway, both authenticating with v2 workload credentials (JWT-SVIDs); agent
 * C only reports what it verified. A signed-in user's token calls A, which delegates to B, which
 * delegates to C. Prints claims only, never a token.
 *
 * <p>B and C listen on the ports their registered resources name ({@code http://127.0.0.1:9601}
 * and {@code :9603}), since the exchange's resource is the target's base URL.
 */
public final class LiveE2e {

    private LiveE2e() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        URI zone = Env.uri("KEYCARD_ZONE_URL");
        String user = Files.readString(Path.of(Env.require("SUBJECT_TOKEN_FILE"))).strip();
        URI a = URI.create("http://127.0.0.1:9602");
        URI b = URI.create("http://127.0.0.1:9601");
        URI c = URI.create("http://127.0.0.1:9603");
        WorkloadIdentity engine = WorkloadIdentity.builder(FileTokenSource.of(Path.of(Env.require("SVID_FILE"))))
                .clientId(Env.require("ENGINE_V2_CLIENT_ID"))
                .build();
        WorkloadIdentity gateway = WorkloadIdentity.builder(
                        FileTokenSource.of(Path.of(Env.require("GATEWAY_SVID_FILE"))))
                .clientId(Env.require("GATEWAY_V2_CLIENT_ID"))
                .build();

        ServletContextHandler cContext = new ServletContextHandler();
        AgentB.mount(cContext, "Agent C", c, verifier(zone, c.toString()), null);
        ServletContextHandler bContext = new ServletContextHandler();
        AgentB.mount(
                bContext,
                AgentB.NAME,
                b,
                verifier(zone, b.toString()),
                new AgentB.Forward(DelegationClient.builder(zone).credential(gateway).build(), c));
        ServletContextHandler aContext = new ServletContextHandler();
        // The user's token was minted for the engine's resource, so A accepts that audience.
        AgentA.mount(
                aContext,
                verifier(zone, Env.require("ENGINE_RESOURCE")),
                DelegationClient.builder(zone).credential(engine).build(),
                b);

        List<String> failures = new ArrayList<>();
        Server cServer = Agents.server(c, cContext);
        Server bServer = Agents.server(b, bContext);
        Server aServer = Agents.server(a, aContext);
        try {
            HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(
                            HttpRequest.newBuilder(a.resolve("/delegate"))
                                    .header("Authorization", "Bearer " + user)
                                    .POST(HttpRequest.BodyPublishers.ofString("hello from the live run"))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
            String[] hops = response.body().split(" \\| ");
            System.out.println("  A -> " + response.statusCode());
            for (String hop : hops) {
                System.out.println("       " + hop);
            }
            String hopB = hops[0];
            String hopC = hops.length > 1 ? hops[1] : "";
            report(failures, response.statusCode() == 200 && hopB.startsWith("Agent B verified sub=")
                            && hopB.contains("aud=[" + b + "]")
                            && hopB.contains("act={sub=urn:app:java-sdk-engine"),
                    "row 1: B sees the user as sub, its own URL as aud, and agent A (engine) in act");
            String userSub = hopB.replaceAll(".*verified sub=(\\S+).*", "$1");
            report(failures, hopC.startsWith("Agent C verified sub=" + userSub)
                            && hopC.contains("aud=[" + c + "]")
                            && hopC.matches(".*act=\\{sub=urn:app:java-sdk-gateway.*act=\\{sub=urn:app:java-sdk-engine.*"),
                    "row 2: C still sees the user as sub; act names B (gateway) over A (engine)");
        } finally {
            aServer.stop();
            bServer.stop();
            cServer.stop();
        }
        System.out.println(failures.isEmpty() ? "ALL PASSED" : "FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    private static TokenVerifier verifier(URI zone, String audience) {
        return TokenVerifier.builder(zone).audiences(audience).build();
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
