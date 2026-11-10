package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * A workload-identity token source failed at request time: the token file is unreadable or
 * empty, the metadata endpoint is unreachable or answered non-200, or a custom source threw.
 *
 * <p>Retryable when the underlying cause is a retryable {@link KeycardException}, such as a
 * {@link NetworkException} reaching a metadata server; otherwise not.
 */
public class WorkloadIdentityRuntimeException extends KeycardException {

    private static final long serialVersionUID = 1L;

    /** Identifier of {@link FileTokenSource}. */
    public static final String SOURCE_FILE = "file";

    /** Identifier of {@link GcpMetadataTokenSource}. */
    public static final String SOURCE_GCP_METADATA = "gcp-metadata";

    /** Identifier for a caller-supplied source, such as a lambda. */
    public static final String SOURCE_CUSTOM = "custom";

    /** The failing source's identifier. */
    private final String source;

    /**
     * Creates the exception.
     *
     * @param message what failed
     * @param source the source identifier, such as {@link #SOURCE_FILE}
     * @param cause the underlying failure, or {@code null}
     */
    public WorkloadIdentityRuntimeException(String message, String source, @Nullable Throwable cause) {
        super(message, cause, cause instanceof KeycardException keycard && keycard.retryable());
        this.source = source;
    }

    /**
     * Creates the exception with an explicit classification, for a source that knows whether its
     * failure is transient, such as an unreachable local agent.
     *
     * @param message what failed
     * @param source the source identifier
     * @param cause the underlying failure, or {@code null}
     * @param retryable whether fetching again unchanged could succeed
     */
    public WorkloadIdentityRuntimeException(
            String message, String source, @Nullable Throwable cause, boolean retryable) {
        super(message, cause, retryable);
        this.source = source;
    }

    /**
     * The failing source's identifier.
     *
     * @return {@code file}, {@code gcp-metadata}, {@code custom}, or another source's identifier
     */
    public String source() {
        return source;
    }
}
