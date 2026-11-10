package ai.keycard.oauth;

import java.util.List;
import java.util.Objects;

/**
 * The environment describes no single usable credential (credential-discovery.md). A
 * configuration error: retrying without changing the environment can't succeed.
 */
public final class CredentialDiscoveryException extends ConfigurationException {

    private static final long serialVersionUID = 1L;

    /** Why discovery failed. */
    public enum Reason {
        /** No supported credential is configured. */
        ABSENT,
        /** More than one credential type is configured and no selector is set. */
        AMBIGUOUS,
        /** A client secret is set without a client id, and no selector is set. */
        INCOMPLETE,
        /** The selector names an unknown credential type. */
        UNKNOWN_TYPE,
        /** The selector names a type whose inputs aren't all present. */
        NOT_SATISFIABLE
    }

    /** Why discovery failed. */
    private final Reason reason;

    /** The credential types the environment could have built. */
    private final String[] resolvable;

    CredentialDiscoveryException(String message, Reason reason, List<String> resolvable) {
        super(message);
        this.reason = Objects.requireNonNull(reason, "reason");
        this.resolvable = resolvable.toArray(String[]::new);
    }

    /**
     * Why discovery failed.
     *
     * @return the reason
     */
    public Reason reason() {
        return reason;
    }

    /**
     * The credential type names the environment could have built, such as {@code client_secret}
     * and {@code workload_identity} for an ambiguous environment.
     *
     * @return the type names, in canonical order
     */
    public List<String> resolvable() {
        return List.of(resolvable);
    }
}
