package example;

import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The grant-decorator Integration Tests against a live zone: this server runs as a registered
 * application, a real user token calls it through the MCP client, and the grant exchanges that
 * token for a real downstream resource. Prints claims only, never a token.
 *
 * <p>Reads the server's settings from the same environment as {@link Server}, plus {@code
 * SUBJECT_TOKEN_FILE}: a user access token whose audience is {@code KEYCARD_RESOURCE_ID}.
 */
public final class LiveE2e {

    private LiveE2e() {}

    public static void main(String[] args) throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        String user = Files.readString(Path.of(System.getenv("SUBJECT_TOKEN_FILE"))).strip();
        Server.Config config = Server.fromEnvironment();
        int code;
        try (Server server = Server.start(config)) {
            Driver driver = new Driver(server.url("/"));
            System.out.println("live checks against " + config.zoneUrl() + ":");
            driver.check(
                    "bare POST /mcp is 401",
                    () -> driver.postMcp("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", null)
                                    .statusCode()
                            == 401);
            McpSyncClient client = driver.client(user);
            try {
                String whoami = Driver.text(Driver.call(client, "whoami"));
                System.out.println("       whoami: " + whoami);
                driver.check("whoami sees the signed-in user", () -> whoami.startsWith("sub="));
                CallToolResult downstream = Driver.call(client, "downstream");
                String report = Driver.text(downstream);
                System.out.println("       downstream:\n         " + report.replace("\n", "\n         "));
                List<String> resources = config.downstreamResources();
                driver.check(
                        "integration row 1: the grant yields a token for " + resources.get(0),
                        () -> report.contains(resources.get(0) + ": sub=")
                                && report.contains("aud=" + resources.get(0)));
                if (resources.size() > 1) {
                    driver.check(
                            "integration row 2: " + resources.get(1) + " records an error while the first succeeds",
                            () -> report.contains(resources.get(1) + ": failed (") && !Boolean.TRUE.equals(downstream.isError()));
                }
            } finally {
                client.closeGracefully();
            }
            code = driver.finish("live-e2e");
        }
        System.exit(code);
    }
}
