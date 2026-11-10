package ai.keycard.oauth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Reads a platform-projected OIDC token from a file, fresh on every call. Covers EKS pod
 * identity, AKS workload identity, any Kubernetes projected service-account token, a
 * spiffe-helper JWT-SVID file, and CI providers that write the token to a file.
 *
 * <p>Without an explicit path, the path comes from the first set environment variable among
 * {@link #DISCOVERY_VARIABLES}, after {@link Builder#envVarName(String)} when given. This
 * discovery is the only environment access in the SDK outside {@code CredentialDiscovery}.
 *
 * <pre>{@code
 * FileTokenSource source = FileTokenSource.builder().build();                     // discover
 * FileTokenSource source = FileTokenSource.of(Path.of("/var/run/secrets/token")); // explicit
 * }</pre>
 */
public final class FileTokenSource implements IdentityTokenSource {

    /** Discovery order: the EKS pod-identity variables, then the AKS federated-token variable. */
    public static final List<String> DISCOVERY_VARIABLES = List.of(
            "KEYCARD_EKS_WORKLOAD_IDENTITY_TOKEN_FILE",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AZURE_FEDERATED_TOKEN_FILE");

    private final Path path;

    private FileTokenSource(Path path) {
        this.path = path;
    }

    /**
     * A source reading an explicit path, validated now.
     *
     * @param path the token file
     * @return the source
     * @throws WorkloadIdentityConfigurationException when the file is missing, unreadable or empty
     */
    public static FileTokenSource of(Path path) {
        return builder().tokenFilePath(path).build();
    }

    /**
     * A builder; with no path set, {@link Builder#build()} discovers one from the environment.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The file this source reads.
     *
     * @return the resolved path
     */
    public Path path() {
        return path;
    }

    /**
     * Re-reads the file and returns its contents with surrounding whitespace trimmed.
     *
     * @return the token
     * @throws WorkloadIdentityRuntimeException when the file is unreadable or empty
     */
    @Override
    public String identityToken() {
        String token;
        try {
            token = Files.readString(path, StandardCharsets.UTF_8).strip();
        } catch (IOException e) {
            throw new WorkloadIdentityRuntimeException(
                    "reading token file " + path + " failed", WorkloadIdentityRuntimeException.SOURCE_FILE, e);
        }
        if (token.isEmpty()) {
            throw new WorkloadIdentityRuntimeException(
                    "token file is empty: " + path, WorkloadIdentityRuntimeException.SOURCE_FILE, null);
        }
        return token;
    }

    @Override
    public String toString() {
        return "FileTokenSource[" + path + "]";
    }

    /** Configures a {@link FileTokenSource}. */
    public static final class Builder {

        private @Nullable Path tokenFilePath;
        private @Nullable String envVarName;
        private Map<String, String> environment = System.getenv();

        private Builder() {}

        /**
         * The token file, skipping environment discovery.
         *
         * @param tokenFilePath the path
         * @return this builder
         */
        public Builder tokenFilePath(Path tokenFilePath) {
            this.tokenFilePath = Objects.requireNonNull(tokenFilePath, "tokenFilePath");
            return this;
        }

        /**
         * An extra environment variable to consult first during discovery.
         *
         * @param envVarName the variable name
         * @return this builder
         */
        public Builder envVarName(String envVarName) {
            this.envVarName = Objects.requireNonNull(envVarName, "envVarName");
            return this;
        }

        /**
         * The environment discovery reads. Defaults to {@link System#getenv()}; tests pass a map.
         *
         * @param environment variable values by name
         * @return this builder
         */
        public Builder environment(Map<String, String> environment) {
            this.environment = Objects.requireNonNull(environment, "environment");
            return this;
        }

        /**
         * Resolves the path and checks that the file exists and is non-empty.
         *
         * @return the source
         * @throws WorkloadIdentityConfigurationException when no path resolves, or the file is
         *     missing, unreadable or empty
         */
        public FileTokenSource build() {
            Path path = tokenFilePath != null ? tokenFilePath : discover();
            String contents;
            try {
                contents = Files.readString(path, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new WorkloadIdentityConfigurationException(
                        "cannot read token file " + path, WorkloadIdentityRuntimeException.SOURCE_FILE, e);
            }
            if (contents.isBlank()) {
                throw new WorkloadIdentityConfigurationException(
                        "token file is empty: " + path, WorkloadIdentityRuntimeException.SOURCE_FILE, null);
            }
            return new FileTokenSource(path);
        }

        private Path discover() {
            List<String> variables = new ArrayList<>();
            if (envVarName != null) {
                variables.add(envVarName);
            }
            variables.addAll(DISCOVERY_VARIABLES);
            for (String variable : variables) {
                String value = environment.get(variable);
                if (value != null && !value.isEmpty()) {
                    return Path.of(value);
                }
            }
            throw new WorkloadIdentityConfigurationException(
                    "could not find a token file path in the environment; checked " + String.join(", ", variables),
                    WorkloadIdentityRuntimeException.SOURCE_FILE,
                    null);
        }
    }
}
