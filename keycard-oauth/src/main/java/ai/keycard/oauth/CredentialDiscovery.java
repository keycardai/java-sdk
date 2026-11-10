package ai.keycard.oauth;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Builds the credential a workload authenticates with from the canonical {@code KEYCARD_*}
 * variables (credential-discovery.md). The one place the SDK reads Keycard configuration from the
 * environment, and only when called; the caller passes the environment:
 *
 * <pre>{@code
 * Credential credential = CredentialDiscovery.discover(System.getenv());
 * }</pre>
 *
 * <p>The same environment moves a workload from a laptop ({@code KEYCARD_CLIENT_ID} and {@code
 * KEYCARD_CLIENT_SECRET}) to a cluster (a projected token file) with no code change. When the
 * environment describes no credential, several without {@code
 * KEYCARD_APPLICATION_CREDENTIAL_TYPE}, an incomplete one or an unknown type, it fails with a
 * {@link CredentialDiscoveryException} instead of guessing.
 */
public final class CredentialDiscovery {

    /** The registered client id. */
    public static final String CLIENT_ID = "KEYCARD_CLIENT_ID";

    /** The registered client secret. */
    public static final String CLIENT_SECRET = "KEYCARD_CLIENT_SECRET";

    /** The directory holding a {@link WebIdentity}'s keys. */
    public static final String WEB_IDENTITY_KEY_STORAGE_DIR = "KEYCARD_WEB_IDENTITY_KEY_STORAGE_DIR";

    /** Chooses the credential type when the environment configures more than one. */
    public static final String CREDENTIAL_TYPE = "KEYCARD_APPLICATION_CREDENTIAL_TYPE";

    /** A {@link ClientSecret} over the client id and secret. */
    public static final String CLIENT_SECRET_TYPE = "client_secret";

    /** A {@link WorkloadIdentity} over a {@link FileTokenSource}. */
    public static final String WORKLOAD_IDENTITY_TYPE = "workload_identity";

    /** A {@link WebIdentity} over the key storage directory. */
    public static final String WEB_IDENTITY_TYPE = "web_identity";

    /** Accepted for {@link #WORKLOAD_IDENTITY_TYPE}; deprecated. */
    public static final String LEGACY_WORKLOAD_IDENTITY_TYPE = "eks_workload_identity";

    private static final List<String> TYPES = List.of(CLIENT_SECRET_TYPE, WORKLOAD_IDENTITY_TYPE, WEB_IDENTITY_TYPE);

    private CredentialDiscovery() {}

    /**
     * Discovers the credential the environment describes.
     *
     * @param environment the environment, such as {@code System.getenv()}
     * @return the credential
     * @throws CredentialDiscoveryException when the environment describes no single usable
     *     credential
     * @throws WorkloadIdentityConfigurationException when the discovered token file is missing or
     *     empty
     */
    public static Credential discover(Map<String, String> environment) {
        return discover(environment, null);
    }

    /**
     * Discovers the credential the environment describes, naming a discovered {@link WebIdentity}
     * after the server.
     *
     * @param environment the environment, such as {@code System.getenv()}
     * @param webIdentityServerName the server name a discovered {@link WebIdentity} derives its
     *     key id from, or {@code null} for its default naming
     * @return the credential
     * @throws CredentialDiscoveryException when the environment describes no single usable
     *     credential
     * @throws WorkloadIdentityConfigurationException when the discovered token file is missing or
     *     empty
     */
    public static Credential discover(Map<String, String> environment, @Nullable String webIdentityServerName) {
        Objects.requireNonNull(environment, "environment");
        String clientId = value(environment, CLIENT_ID);
        String clientSecret = value(environment, CLIENT_SECRET);
        String tokenFileVariable = tokenFileVariable(environment);
        String storageDir = value(environment, WEB_IDENTITY_KEY_STORAGE_DIR);
        String selector = value(environment, CREDENTIAL_TYPE);

        List<String> resolvable = new ArrayList<>();
        if (clientId != null && clientSecret != null) {
            resolvable.add(CLIENT_SECRET_TYPE);
        }
        if (tokenFileVariable != null) {
            resolvable.add(WORKLOAD_IDENTITY_TYPE);
        }
        if (storageDir != null) {
            resolvable.add(WEB_IDENTITY_TYPE);
        }

        if (selector != null) {
            String type = LEGACY_WORKLOAD_IDENTITY_TYPE.equals(selector) ? WORKLOAD_IDENTITY_TYPE : selector;
            if (!TYPES.contains(type)) {
                throw new CredentialDiscoveryException(
                        CREDENTIAL_TYPE + "=" + selector + " is not a credential type; use one of "
                                + String.join(", ", TYPES),
                        CredentialDiscoveryException.Reason.UNKNOWN_TYPE,
                        resolvable);
            }
            if (type.equals(WEB_IDENTITY_TYPE)) {
                return webIdentity(storageDir, webIdentityServerName);
            }
            if (!resolvable.contains(type)) {
                String needs = type.equals(CLIENT_SECRET_TYPE)
                        ? CLIENT_ID + " and " + CLIENT_SECRET
                        : "one of " + String.join(", ", FileTokenSource.DISCOVERY_VARIABLES);
                throw new CredentialDiscoveryException(
                        CREDENTIAL_TYPE + "=" + type + " needs " + needs,
                        CredentialDiscoveryException.Reason.NOT_SATISFIABLE,
                        resolvable);
            }
            return build(type, clientId, clientSecret, environment, storageDir, webIdentityServerName);
        }

        if (clientSecret != null && clientId == null) {
            throw new CredentialDiscoveryException(
                    CLIENT_SECRET + " is set without " + CLIENT_ID,
                    CredentialDiscoveryException.Reason.INCOMPLETE,
                    resolvable);
        }
        if (resolvable.isEmpty()) {
            throw new CredentialDiscoveryException(
                    "no Keycard application credential is configured; set " + CLIENT_ID + " and " + CLIENT_SECRET
                            + ", a token file variable, or " + WEB_IDENTITY_KEY_STORAGE_DIR,
                    CredentialDiscoveryException.Reason.ABSENT,
                    resolvable);
        }
        if (resolvable.size() > 1) {
            throw new CredentialDiscoveryException(
                    "the environment configures " + String.join(" and ", resolvable) + "; set " + CREDENTIAL_TYPE
                            + " to choose one",
                    CredentialDiscoveryException.Reason.AMBIGUOUS,
                    resolvable);
        }
        return build(resolvable.get(0), clientId, clientSecret, environment, storageDir, webIdentityServerName);
    }

    private static Credential build(
            String type,
            @Nullable String clientId,
            @Nullable String clientSecret,
            Map<String, String> environment,
            @Nullable String storageDir,
            @Nullable String serverName) {
        switch (type) {
            case CLIENT_SECRET_TYPE:
                return ClientSecret.of(Objects.requireNonNull(clientId), Objects.requireNonNull(clientSecret));
            case WORKLOAD_IDENTITY_TYPE:
                WorkloadIdentity.Builder workload = WorkloadIdentity.builder(
                        FileTokenSource.builder().environment(environment).build());
                if (clientId != null) {
                    workload.clientId(clientId);
                }
                return workload.build();
            default:
                return webIdentity(storageDir, serverName);
        }
    }

    private static WebIdentity webIdentity(@Nullable String storageDir, @Nullable String serverName) {
        WebIdentity.Builder builder = WebIdentity.builder();
        if (storageDir != null) {
            builder.storageDir(Path.of(storageDir));
        }
        if (serverName != null && !serverName.isEmpty()) {
            builder.serverName(serverName);
        }
        return builder.build();
    }

    private static @Nullable String tokenFileVariable(Map<String, String> environment) {
        for (String variable : FileTokenSource.DISCOVERY_VARIABLES) {
            if (value(environment, variable) != null) {
                return variable;
            }
        }
        return null;
    }

    private static @Nullable String value(Map<String, String> environment, String name) {
        String value = environment.get(name);
        return value == null || value.isEmpty() ? null : value;
    }
}
