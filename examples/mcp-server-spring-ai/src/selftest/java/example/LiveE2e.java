package example;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * The grant Integration Tests against a live zone through Spring AI and the starter. The app runs
 * as a registered application (here a v2 workload credential), a real user token calls it over
 * MCP, and the {@code downstream} tool exchanges that token for a real resource and for one that
 * isn't registered. Prints claims only, never a token. Settings come from the environment through
 * Spring's relaxed binding ({@code KEYCARD_ZONE_URL}, {@code KEYCARD_AUDIENCES}, ...).
 */
public final class LiveE2e {

    private LiveE2e() {}

    public static void main(String[] args) throws Exception {
        String user = Files.readString(Path.of(System.getenv("SUBJECT_TOKEN_FILE"))).strip();
        List<String> resources = List.of(System.getenv("DOWNSTREAM_RESOURCES").trim().split("[\\s,]+"));
        List<String> failures = new ArrayList<>();
        try (ConfigurableApplicationContext app = SpringApplication.run(
                Application.class, "--server.port=0", "--downstream.resources=" + String.join(",", resources))) {
            URI base = URI.create("http://127.0.0.1:" + app.getEnvironment().getProperty("local.server.port"));
            System.out.println("live checks against " + app.getEnvironment().getProperty("keycard.zone-url") + ":");
            McpSyncClient client = McpClient.sync(HttpClientStreamableHttpTransport.builder(base.toString())
                            .endpoint("/mcp")
                            .requestBuilder(HttpRequest.newBuilder().header("Authorization", "Bearer " + user))
                            .build())
                    .requestTimeout(Duration.ofSeconds(30))
                    .build();
            try {
                client.initialize();
                String whoami = SelfTest.text(SelfTest.call(client, "whoami"));
                System.out.println("       whoami: " + whoami);
                report(failures, whoami.startsWith("sub="), "whoami sees the signed-in user");
                CallToolResult downstream = SelfTest.call(client, "downstream");
                String report = SelfTest.text(downstream);
                System.out.println("       downstream:\n         " + report.replace("\n", "\n         "));
                report(failures,
                        report.contains(resources.get(0) + ": sub=") && report.contains("aud=" + resources.get(0)),
                        "integration row 1: the exchange yields a token for " + resources.get(0));
                if (resources.size() > 1) {
                    report(failures,
                            report.contains(resources.get(1) + ": failed (") && !Boolean.TRUE.equals(downstream.isError()),
                            "integration row 2: " + resources.get(1) + " records an error while the first succeeds");
                }
            } finally {
                client.closeGracefully();
            }
        }
        System.out.println(failures.isEmpty() ? "live-e2e passed" : "live-e2e FAILED: " + failures);
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    private static void report(List<String> failures, boolean ok, String line) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + line);
        if (!ok) {
            failures.add(line);
        }
    }
}
