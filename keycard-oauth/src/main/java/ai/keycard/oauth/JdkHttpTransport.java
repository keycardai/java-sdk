package ai.keycard.oauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * {@link KeycardHttpTransport} over the JDK's {@link HttpClient}.
 *
 * <p>{@link HttpRequest.Builder#timeout} stops counting once response headers arrive, so a server
 * that stalls mid-body would hold the caller past it. The exchange is therefore sent
 * asynchronously and awaited for the request's timeout as a whole, then cancelled if it hasn't
 * finished. Response bodies are streamed and capped at {@link
 * KeycardHttpTransport#MAX_RESPONSE_BODY_BYTES} decoded bytes before buffering or parsing.
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
        CompletableFuture<TransportResponse> exchange = client.sendAsync(
                        httpRequest, HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(JdkHttpTransport::readBoundedResponse);
        try {
            return exchange.get(request.timeout().toNanos(), TimeUnit.NANOSECONDS);
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
            if (cause instanceof UncheckedIOException uio) {
                IOException io = uio.getCause();
                throw new NetworkException(
                        "request to " + host + " failed: " + io.getClass().getSimpleName(), io);
            }
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

    private static TransportResponse readBoundedResponse(HttpResponse<InputStream> response) {
        int status = response.statusCode();
        String encoding = response.headers()
                .firstValue("content-encoding")
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .orElse("");
        try (InputStream raw = response.body();
                InputStream decoded = wrapEncoding(raw, encoding)) {
            byte[] bytes = readBoundedBytes(decoded, status, KeycardHttpTransport.MAX_RESPONSE_BODY_BYTES);
            return new TransportResponse(status, response.headers().map(), new String(bytes, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static InputStream wrapEncoding(InputStream raw, String encoding) throws IOException {
        return switch (encoding) {
            case "gzip", "x-gzip" -> new GZIPInputStream(raw);
            case "deflate" -> new InflaterInputStream(raw);
            default -> raw;
        };
    }

    private static byte[] readBoundedBytes(InputStream in, int status, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) != -1) {
            total += n;
            if (total > limit) {
                throw new ResponseBodyTooLargeException(status, limit);
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
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
