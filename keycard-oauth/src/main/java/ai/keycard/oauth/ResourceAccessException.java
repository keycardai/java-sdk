package ai.keycard.oauth;

import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * {@link AccessContext#access(String)} could not hand out a token. {@link #errorType()} says why.
 * Never retryable on its own; inspect {@link #errorDetails()} for the upstream failure.
 */
public class ResourceAccessException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** Why a token could not be handed out. */
    public enum ErrorType {
        /** A context-wide error is set. */
        GLOBAL_ERROR,
        /** The resource's exchange failed. */
        RESOURCE_ERROR,
        /** The resource was never granted. */
        MISSING_TOKEN
    }

    /** The resource that was asked for. */
    private final String resource;

    /** Why the token could not be handed out. */
    private final ErrorType errorType;

    /** The granted resources, for a {@link ErrorType#MISSING_TOKEN} error. */
    private final String[] availableResources;

    /** The recorded upstream error. */
    private final @Nullable KeycardException errorDetails;

    /**
     * Creates the exception.
     *
     * @param message what happened
     * @param resource the resource asked for
     * @param errorType why
     * @param availableResources the granted resources
     * @param errorDetails the recorded upstream error, or {@code null}
     */
    public ResourceAccessException(
            String message,
            String resource,
            ErrorType errorType,
            List<String> availableResources,
            @Nullable KeycardException errorDetails) {
        super(message, errorDetails, false);
        this.resource = resource;
        this.errorType = errorType;
        this.availableResources = availableResources.toArray(String[]::new);
        this.errorDetails = errorDetails;
    }

    /**
     * The resource that was asked for.
     *
     * @return the resource
     */
    public String resource() {
        return resource;
    }

    /**
     * Why the token could not be handed out.
     *
     * @return the error type
     */
    public ErrorType errorType() {
        return errorType;
    }

    /**
     * The resources that were granted, populated for {@link ErrorType#MISSING_TOKEN}.
     *
     * @return the granted resources
     */
    public List<String> availableResources() {
        return List.of(availableResources);
    }

    /**
     * The recorded upstream error, for the global and resource cases.
     *
     * @return the error, or {@code null}
     */
    public @Nullable KeycardException errorDetails() {
        return errorDetails;
    }
}
