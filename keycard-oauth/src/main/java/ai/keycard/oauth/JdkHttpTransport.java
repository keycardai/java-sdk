package ai.keycard.oauth;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * {@link KeycardHttpTransport} over the JDK's {@link HttpClient}.
 *
 * <p>{@link HttpRequest.Builder#timeout} stops counting once response headers arrive, so a server
 * that stalls mid-body would hold the caller past it. The exchange is therefore sent
 * asynchronously and awaited for the request's timeout as a whole, then cancelled if it hasn't
 * finished.
 */
final class JdkHttpTransport implements KeycardHttpTransport {

    private final HttpClient client;

    JdkHttpTransport(HttpClient client) {
        this.client = Objects.requireNonNull(client, "client");
    }

    @Override
    public TransportResponse send(TransportRequest request) {
        HttpRequest httpRequest = toHttpRequest(request);
        String host = request.uri().getHost();
        CompletableFuture<HttpResponse<String>> exchange =
                client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        try {
            HttpResponse<String> response = exchange.get(request.timeout().toNanos(), TimeUnit.NANOSECONDS);
            return new TransportResponse(
                    response.statusCode(), response.headers().map(), response.body());
        } catch (TimeoutException e) {
            exchange.cancel(true);
            throw new NetworkException(
                    "request to " + host + " timed out after " + request.timeout(),
                    new HttpTimeoutException("request timed out after " + request.timeout()));
        } catch (InterruptedException e) {
            exchange.cancel(true);
            Thread.currentThread().interrupt();
            throw new NetworkException("request to " + host + " was interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw new NetworkException(
                        "request to " + host + " failed: " + cause.getClass().getSimpleName(), cause);
            }
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new NetworkException("request to " + host + " failed", e);
        }
    }

    private static HttpRequest toHttpRequest(TransportRequest request) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri()).timeout(request.timeout());
            request.headers().forEach(builder::header);
            String body = request.body();
            builder.method(
                    request.method(),
                    body == null
                            ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            return builder.build();
        } catch (IllegalArgumentException e) {
            // The JDK's message quotes the offending header value, which may be a token; name only
            // which header was refused, and leave the original out of the chain.
            throw new ConfigurationException("invalid request to " + request.uri()
                    + ": a header name or value is not allowed (for example, it holds a line break)");
        }
    }
}
