package ai.keycard.oauth;

import org.jspecify.annotations.Nullable;

/**
 * A workload-identity token source is misconfigured at construction: no token file path could be
 * resolved, the file is missing or empty, or a required audience is absent. Never retryable.
 */
public class WorkloadIdentityConfigurationException extends ConfigurationException {

    private static final long serialVersionUID = 1L;

    /** The failing source's identifier. */
    private final String source;

    /**
     * Creates the exception.
     *
     * @param message what is misconfigured
     * @param source the source identifier, such as {@value WorkloadIdentityRuntimeException#SOURCE_FILE}
     * @param cause the underlying failure, or {@code null}
     */
    public WorkloadIdentityConfigurationException(String message, String source, @Nullable Throwable cause) {
        super(message, cause);
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
