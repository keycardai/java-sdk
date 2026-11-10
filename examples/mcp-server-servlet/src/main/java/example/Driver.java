package example;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/** Drives the server the way a client would: plain HTTP for the contract, the MCP SDK client for tools. */
final class Driver {

    private final URI base;
    private final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private final List<String> failures = new ArrayList<>();

    Driver(URI base) {
        this.base = base;
    }

    /** Records a check; a thrown exception counts as a failure with its message. */
    void check(String name, BooleanSupplier condition) {
        boolean ok;
        String detail = "";
        try {
            ok = condition.getAsBoolean();
        } catch (RuntimeException e) {
            ok = false;
            detail = " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")";
        }
        System.out.println((ok ? "  ok   " : "  FAIL ") + name + detail);
        if (!ok) {
            failures.add(name);
        }
    }

    /** Prints the outcome and returns the exit code. */
    int finish(String label) {
        if (failures.isEmpty()) {
            System.out.println(label + " passed");
            return 0;
        }
        System.out.println(label + " FAILED: " + String.join(", ", failures));
        return 1;
    }

    HttpResponse<String> get(String path) {
        return send(HttpRequest.newBuilder(base.resolve(path)).GET().build());
    }

    HttpResponse<String> postMcp(String body, String bearer) {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve(Server.MCP_PATH))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return send(request.build());
    }

    /** An MCP session authenticated with {@code bearer}. */
    McpSyncClient client(String bearer) {
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(base.toString())
                .endpoint(Server.MCP_PATH)
                .requestBuilder(HttpRequest.newBuilder().header("Authorization", "Bearer " + bearer))
                .build();
        McpSyncClient client =
                McpClient.sync(transport).requestTimeout(Duration.ofSeconds(20)).build();
        client.initialize();
        return client;
    }

    static List<String> toolNames(McpSyncClient client) {
        return client.listTools().tools().stream().map(Tool::name).toList();
    }

    static CallToolResult call(McpSyncClient client, String tool) {
        return client.callTool(CallToolRequest.builder(tool).arguments(Map.of()).build());
    }

    static String text(CallToolResult result) {
        return result.content().stream()
                .filter(TextContent.class::isInstance)
                .map(c -> ((TextContent) c).text())
                .findFirst()
                .orElse("");
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
