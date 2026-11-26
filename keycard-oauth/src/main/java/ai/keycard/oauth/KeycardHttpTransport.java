package ai.keycard.oauth;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.function.Consumer;

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

    /** The maximum number of decoded bytes read from any authorization-server HTTP response: 1 MiB. */
    int MAX_RESPONSE_BODY_BYTES = 1_048_576;

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
     * Sends one request without enforcing {@link #MAX_RESPONSE_BODY_BYTES}. Used for non-OAuth
     * application payloads (such as A2A agent invocation replies) that share a transport with
     * authorization-server calls.
     *
     * @param request the request
     * @return the response, whatever its status
     * @throws NetworkException on DNS, TLS, connect or timeout failures, or when the calling
     *     thread is interrupted (the interrupt flag stays set)
     */
    default TransportResponse sendUnbounded(TransportRequest request) {
        return send(request);
    }

    /**
     * Sends one request with a decoded byte limit on the SDK's JDK transport.
     * Other implementations can apply their own transport policy.
     *
     * @param request the request
     * @param maxResponseBodyBytes the positive decoded byte limit
     * @return the response, whatever its status
     * @throws ResponseBodyTooLargeException if the SDK transport exceeds the limit
     */
    default TransportResponse sendWithLimit(TransportRequest request, int maxResponseBodyBytes) {
        return sendUnbounded(request);
    }

    /**
     * Sends one request, inspecting response status and headers before reading the body on the
     * SDK's JDK transport. Other transports may provide an already buffered response.
     *
     * @param request the request
     * @param maxResponseBodyBytes the positive decoded byte limit
     * @param inspectResponse the response inspector, which may throw to reject the response
     * @return the response, whatever its status
     */
    default TransportResponse sendWithLimit(
            TransportRequest request, int maxResponseBodyBytes, Consumer<TransportResponse> inspectResponse) {
        TransportResponse response = sendWithLimit(request, maxResponseBodyBytes);
        inspectResponse.accept(response);
        return response;
    }

    /**
     * Checks that redirects are disabled when the client's policy is visible to the SDK.
     * Custom transports are responsible for disabling redirects.
     *
     * @throws ConfigurationException if the client follows redirects
     */
    default void requireRedirectsDisabled() {}

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
