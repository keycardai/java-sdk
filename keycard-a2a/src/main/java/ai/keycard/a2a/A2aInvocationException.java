package ai.keycard.a2a;

import ai.keycard.oauth.KeycardException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * The target agent's JSON-RPC call failed: a network error, an HTTP error status, a body that
 * isn't JSON-RPC, or a JSON-RPC error response. Retryable for network failures, 5xx and 429; a
 * JSON-RPC error is not.
 */
public final class A2aInvocationException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** The HTTP status, or 0 when no response arrived. */
    private final int status;

    /** The JSON-RPC error object, when the agent answered with one. */
    private final @Nullable LinkedHashMap<String, Object> rpcError;

    A2aInvocationException(
            String message,
            @Nullable Throwable cause,
            boolean retryable,
            int status,
            @Nullable Map<String, Object> rpcError) {
        super(message, cause, retryable);
        this.status = status;
        this.rpcError = rpcError == null ? null : new LinkedHashMap<>(rpcError);
    }

    /**
     * The HTTP status of the response.
     *
     * @return the status, or 0 when no response arrived
     */
    public int status() {
        return status;
    }

    /**
     * The JSON-RPC error object ({@code code}, {@code message}, optional {@code data}).
     *
     * @return the error, empty unless the agent answered with a JSON-RPC error
     */
    public Optional<Map<String, Object>> rpcError() {
        return Optional.ofNullable(rpcError).map(Collections::unmodifiableMap);
    }
}
