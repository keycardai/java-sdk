package ai.keycard.oauth;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * The HTTP transport every Keycard operation sends its requests through. Inject one to route
 * requests through a corporate proxy, a custom truststore or mTLS, or a test double.
 *
 * <p>An implementation sends exactly one request per call: no retries, no redirects followed on
 * the caller's behalf. It honors {@link TransportRequest#timeout()} as a bound on the whole
 * exchange and reports a transport failure as a {@link NetworkException}. A non-2xx response is
 * not a failure here; it comes back as a {@link TransportResponse} for the operation to classify.
 */
@FunctionalInterface
public interface KeycardHttpTransport {

    /** The default bound on each request to the authorization server: 10 seconds. */
    Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    /**
     * Sends one request.
     *
     * @param request the request
     * @return the response, whatever its status
     * @throws NetworkException on DNS, TLS, connect or timeout failures, or when the calling
     *     thread is interrupted (the interrupt flag stays set)
     */
    TransportResponse send(TransportRequest request);

    /**
     * The default transport: a JDK {@link HttpClient} that follows no redirects and connects
     * within {@link #DEFAULT_TIMEOUT}.
     *
     * @return a new transport
     */
    static KeycardHttpTransport create() {
        return new JdkHttpTransport(HttpClient.newBuilder()
                .connectTimeout(DEFAULT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    /**
     * A transport over a caller-configured JDK {@link HttpClient}. The client's own settings
     * (proxy, SSL context, redirect policy) apply; each request is still bounded by its {@link
     * TransportRequest#timeout()}.
     *
     * @param client the client to send with
     * @return a new transport
     */
    static KeycardHttpTransport of(HttpClient client) {
        return new JdkHttpTransport(client);
    }
}
