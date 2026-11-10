package ai.keycard.oauth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * The tokens a grant obtained for one request, one per resource, with each failure recorded
 * rather than thrown (access-context.md).
 *
 * <p>The grant layer builds and fills it before the handler runs; the handler reads it. {@link
 * #access(String)} returns a token or throws; every other reader never throws, so a handler can
 * look at {@link #status()} and decide to proceed, degrade or fail.
 *
 * <pre>{@code
 * AccessContext access = KeycardRequest.accessContext(request);
 * if (access.hasResourceError("https://ledger.example")) {
 *     return degraded();
 * }
 * String token = access.access("https://ledger.example").accessToken();
 * }</pre>
 *
 * <p>Safe to read from the handler thread while nothing else writes; the mutators are
 * synchronized for grant layers that fill it from several threads.
 */
public final class AccessContext {

    /** A context's overall outcome. */
    public enum Status {
        /** Every exchange succeeded. */
        SUCCESS,
        /** At least one resource failed; others may have tokens. */
        PARTIAL_ERROR,
        /** A context-wide error is set. */
        ERROR
    }

    /**
     * Every recorded error.
     *
     * @param resources per-resource errors
     * @param error the context-wide error, if any
     */
    public record Errors(Map<String, KeycardException> resources, Optional<KeycardException> error) {

        /**
         * Freezes the map.
         *
         * @param resources per-resource errors
         * @param error the context-wide error
         */
        public Errors {
            resources = Map.copyOf(resources);
            Objects.requireNonNull(error, "error");
        }
    }

    private final Map<String, TokenResponse> tokens = new LinkedHashMap<>();
    private final Map<String, KeycardException> resourceErrors = new LinkedHashMap<>();
    private @Nullable KeycardException error;

    /** An empty context. */
    public AccessContext() {}

    /**
     * A context seeded with successful exchanges.
     *
     * @param tokens tokens by resource
     */
    public AccessContext(Map<String, TokenResponse> tokens) {
        setBulkTokens(tokens);
    }

    /**
     * The token for a resource.
     *
     * @param resource the resource identifier
     * @return the exchanged token
     * @throws ResourceAccessException when a context-wide error is set, the resource failed, or it
     *     was never granted
     */
    public synchronized TokenResponse access(String resource) {
        if (error != null) {
            throw new ResourceAccessException(
                    "token access failed for " + resource + ": a context-wide error is set",
                    resource,
                    ResourceAccessException.ErrorType.GLOBAL_ERROR,
                    List.of(),
                    error);
        }
        KeycardException failure = resourceErrors.get(resource);
        if (failure != null) {
            throw new ResourceAccessException(
                    "the exchange for " + resource + " failed",
                    resource,
                    ResourceAccessException.ErrorType.RESOURCE_ERROR,
                    List.of(),
                    failure);
        }
        TokenResponse token = tokens.get(resource);
        if (token == null) {
            throw new ResourceAccessException(
                    "no token for " + resource + "; it was not granted",
                    resource,
                    ResourceAccessException.ErrorType.MISSING_TOKEN,
                    new ArrayList<>(tokens.keySet()),
                    null);
        }
        return token;
    }

    /**
     * The recorded error for one resource.
     *
     * @param resource the resource identifier
     * @return the error, empty when the resource succeeded or wasn't granted
     */
    public synchronized Optional<KeycardException> resourceError(String resource) {
        return Optional.ofNullable(resourceErrors.get(resource));
    }

    /**
     * The context-wide error.
     *
     * @return the error, empty when none is set
     */
    public synchronized Optional<KeycardException> error() {
        return Optional.ofNullable(error);
    }

    /**
     * Every recorded error.
     *
     * @return a snapshot of the per-resource errors and the context-wide error
     */
    public synchronized Errors errors() {
        return new Errors(resourceErrors, Optional.ofNullable(error));
    }

    /**
     * Whether one resource failed.
     *
     * @param resource the resource identifier
     * @return {@code true} when it has a recorded error
     */
    public synchronized boolean hasResourceError(String resource) {
        return resourceErrors.containsKey(resource);
    }

    /**
     * Whether a context-wide error is set.
     *
     * @return {@code true} when one is set; per-resource errors don't count
     */
    public synchronized boolean hasError() {
        return error != null;
    }

    /**
     * Whether anything failed.
     *
     * @return {@code true} when a context-wide error or any per-resource error is set
     */
    public synchronized boolean hasErrors() {
        return error != null || !resourceErrors.isEmpty();
    }

    /**
     * The overall outcome.
     *
     * @return {@link Status#ERROR} with a context-wide error, {@link Status#PARTIAL_ERROR} with any
     *     per-resource error, {@link Status#SUCCESS} otherwise
     */
    public synchronized Status status() {
        if (error != null) {
            return Status.ERROR;
        }
        return resourceErrors.isEmpty() ? Status.SUCCESS : Status.PARTIAL_ERROR;
    }

    /**
     * The resources that have tokens.
     *
     * @return their identifiers, in the order they were recorded
     */
    public synchronized List<String> successfulResources() {
        return List.copyOf(tokens.keySet());
    }

    /**
     * The resources that failed.
     *
     * @return their identifiers, in the order they were recorded
     */
    public synchronized List<String> failedResources() {
        return List.copyOf(resourceErrors.keySet());
    }

    /**
     * Records a token, clearing any error recorded for the resource.
     *
     * @param resource the resource identifier
     * @param token the exchanged token
     */
    public synchronized void setToken(String resource, TokenResponse token) {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(token, "token");
        resourceErrors.remove(resource);
        tokens.put(resource, token);
    }

    /**
     * Records several tokens.
     *
     * @param tokens tokens by resource
     */
    public synchronized void setBulkTokens(Map<String, TokenResponse> tokens) {
        tokens.forEach(this::setToken);
    }

    /**
     * Records a resource's failure, clearing any token recorded for it.
     *
     * @param resource the resource identifier
     * @param failure the upstream error
     */
    public synchronized void setResourceError(String resource, KeycardException failure) {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(failure, "failure");
        tokens.remove(resource);
        resourceErrors.put(resource, failure);
    }

    /**
     * Records a context-wide error.
     *
     * @param failure the error
     */
    public synchronized void setError(KeycardException failure) {
        this.error = Objects.requireNonNull(failure, "failure");
    }

    /**
     * Names the resources and the status, never a token.
     *
     * @return a description without tokens
     */
    @Override
    public synchronized String toString() {
        return "AccessContext[status=" + status() + ", successful=" + tokens.keySet() + ", failed="
                + resourceErrors.keySet() + "]";
    }
}
