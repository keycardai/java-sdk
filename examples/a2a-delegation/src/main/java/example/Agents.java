package example;

import ai.keycard.a2a.DelegationClient;
import ai.keycard.oauth.Credential;
import ai.keycard.oauth.TokenVerifier;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/** Runs agent A and agent B in one process, each on its own port, against one zone. */
public final class Agents implements AutoCloseable {

    private final Server a;
    private final Server b;

    private Agents(Server a, Server b) {
        this.a = a;
        this.b = b;
    }

    /**
     * Starts both agents. B is audience-bound to its own URL, A to its own.
     *
     * @param zone the zone's issuer
     * @param agentACredential agent A's application credential
     * @param portA A's port, or 0
     * @param portB B's port, or 0
     * @return the running agents
     * @throws Exception when Jetty can't start
     */
    public static Agents start(URI zone, Credential agentACredential, int portA, int portB) throws Exception {
        URI bUrl = URI.create("http://127.0.0.1:" + (portB == 0 ? freePort() : portB));
        URI aUrl = URI.create("http://127.0.0.1:" + (portA == 0 ? freePort() : portA));

        ServletContextHandler bContext = new ServletContextHandler();
        AgentB.mount(bContext, AgentB.NAME, bUrl, TokenVerifier.builder(zone).audiences(bUrl.toString()).build(), null);
        Server b = server(bUrl, bContext);

        ServletContextHandler aContext = new ServletContextHandler();
        DelegationClient delegation =
                DelegationClient.builder(zone).credential(agentACredential).build();
        AgentA.mount(aContext, TokenVerifier.builder(zone).audiences(aUrl.toString()).build(), delegation, bUrl);
        Server a = server(aUrl, aContext);
        return new Agents(a, b);
    }

    static Server server(URI url, ServletContextHandler context) throws Exception {
        Server server = new Server(new InetSocketAddress("127.0.0.1", url.getPort()));
        server.setHandler(context);
        server.start();
        return server;
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    /**
     * Agent A's base URL.
     *
     * @return the URL, without a trailing slash
     */
    public URI agentA() {
        return url(a);
    }

    /**
     * Agent B's base URL.
     *
     * @return the URL, without a trailing slash
     */
    public URI agentB() {
        return url(b);
    }

    @Override
    public void close() throws Exception {
        a.stop();
        b.stop();
    }

    static URI url(Server server) {
        return URI.create("http://127.0.0.1:" + ((ServerConnector) server.getConnectors()[0]).getLocalPort());
    }

    /**
     * Runs both agents from the environment until killed.
     *
     * @param args unused
     * @throws Exception when Jetty can't start
     */
    public static void main(String[] args) throws Exception {
        try (Agents agents = start(
                Env.uri("KEYCARD_ZONE_URL"),
                Env.credential(),
                Integer.parseInt(System.getenv().getOrDefault("AGENT_A_PORT", "9602")),
                Integer.parseInt(System.getenv().getOrDefault("AGENT_B_PORT", "9601")))) {
            System.out.println("agent A on " + agents.agentA() + ", agent B on " + agents.agentB());
            Thread.currentThread().join();
        }
    }
}
